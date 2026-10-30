//! openchange-mapihttpd: MAPI/HTTP service listening on 127.0.0.1 behind a TLS reverse proxy.

mod auth;
mod autodiscover;
mod emsmdb;
// Request handling uses the backend from Task 5; until then only the tests use it.
#[cfg_attr(not(test), allow(dead_code))]
mod backend;
mod dovecot;
#[cfg(any(feature = "c-backend", test))]
#[cfg_attr(not(test), allow(dead_code))]
mod ffi;
mod request;
// Until Connect/Execute (Task 5), only the tests use every item.
#[cfg_attr(not(test), allow(dead_code))]
mod session;

use auth::Authenticator;
use backend::Backend;
use bytes::Bytes;
use dovecot::DovecotAuthenticator;
use http::{Request, Response};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use request::{
    check_headers, format_reply, handle_body, reply, MapiReply, MapiRequest, Server, MAX_BODY,
};
use session::SessionTable;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

const CHALLENGE: &str = "Basic realm=\"openchange\"";
/// Connections that have not sent complete request headers by then are closed.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const USAGE: &str = "usage: openchange-mapihttpd --port PORT --dovecot-socket PATH \
     --external-host HOST [--org NAME] [--ou NAME] [--dovecot-service NAME] \
     [--session-idle-seconds SECONDS] [--notification-wait-seconds SECONDS] [--smb-conf PATH]";

/// Builds the HTTP response; the only place reply headers and bodies are laid out.
fn to_response(rep: &MapiReply, elapsed: Duration, start: SystemTime) -> Response<Full<Bytes>> {
    let mut b = Response::builder()
        .status(rep.http_status)
        .header("X-ServerApplication", request::SERVER_APPLICATION);
    let echoed = [
        ("X-RequestType", &rep.request_type),
        ("X-RequestId", &rep.request_id),
        ("X-ClientInfo", &rep.client_info),
        ("Set-Cookie", &rep.set_cookie),
    ];
    for (name, value) in echoed {
        if let Some(v) = value {
            b = b.header(name, v.as_str());
        }
    }
    let body = match rep.http_status {
        200 if rep.xml => {
            b = b.header("Content-Type", "text/xml; charset=utf-8");
            rep.body.clone()
        }
        200 => {
            let ctype = if rep.response_code == 0 {
                "application/mapi-http"
            } else {
                "text/html"
            };
            b = b
                .header("Content-Type", ctype)
                .header("X-ResponseCode", rep.response_code)
                .header("X-PendingPeriod", 15_000);
            if rep.expiration_ms != 0 {
                b = b.header("X-ExpirationInfo", rep.expiration_ms);
            }
            let ms = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX);
            format_reply(rep, ms, &httpdate::fmt_http_date(start))
        }
        401 => {
            b = b.header("WWW-Authenticate", CHALLENGE);
            Vec::new()
        }
        405 => {
            b = b.header("Allow", "POST");
            Vec::new()
        }
        _ => Vec::new(),
    };
    b.body(Full::new(Bytes::from(body))).unwrap_or_else(|_| {
        let mut r = Response::new(Full::default());
        *r.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
        r
    })
}

/// `trust_real_ip`: the peer is the local reverse proxy, so its X-Real-IP is believed.
async fn serve<A: Authenticator, B: Backend>(
    srv: Arc<Server<A, B>>,
    trust_real_ip: bool,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let (start, t0) = (SystemTime::now(), Instant::now());
    let (parts, body) = req.into_parts();
    let h = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
    // Clients may split cookies over several Cookie fields (MS-OXCMAPIHTTP 4.2).
    let cookies = parts
        .headers
        .get_all("Cookie")
        .iter()
        .filter_map(|v| v.to_str().ok());
    let cookies = cookies.collect::<Vec<_>>().join("; ");
    let base = MapiRequest {
        method: parts.method.as_str(),
        path: parts.uri.path(),
        request_type: h("X-RequestType"),
        request_id: h("X-RequestId"),
        client_info: h("X-ClientInfo"),
        content_type: h("Content-Type"),
        authorization: h("Authorization"),
        cookie: (!cookies.is_empty()).then_some(cookies.as_str()),
        real_ip: h("X-Real-IP")
            .filter(|_| trust_real_ip)
            .and_then(|v| v.parse().ok()),
        body: &[],
    };
    let declared = h("Content-Length").and_then(|v| v.parse::<u64>().ok());
    if autodiscover::is_path(base.path) {
        let cap = h("X-MapiHttpCapability");
        let rep = serve_autodiscover(&srv, base, declared, body, cap).await?;
        return Ok(to_response(&rep, t0.elapsed(), start));
    }
    let rep = match check_headers(&srv, &base, declared).await {
        Err(rep) => rep,
        Ok(admitted) => match Limited::new(body, MAX_BODY).collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                let req = MapiRequest {
                    body: &bytes,
                    ..base
                };
                handle_body(&srv, &req, admitted).await
            }
            Err(e) if e.is::<LengthLimitError>() => reply(&base, 200, 9),
            Err(e) => return Err(e),
        },
    };
    Ok(to_response(&rep, t0.elapsed(), start))
}

async fn serve_autodiscover<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    base: MapiRequest<'_>,
    declared: Option<u64>,
    body: Incoming,
    mapihttp_capability: Option<&str>,
) -> Result<MapiReply, Box<dyn std::error::Error + Send + Sync>> {
    let user = match autodiscover::check_headers(srv, &base, declared).await {
        Ok(user) => user,
        Err(rep) => return Ok(rep),
    };
    Ok(
        match Limited::new(body, autodiscover::MAX_BODY).collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                let req = MapiRequest {
                    body: &bytes,
                    ..base
                };
                autodiscover::handle_body(srv, &req, &user, mapihttp_capability)
            }
            Err(e) if e.is::<LengthLimitError>() => autodiscover::error(srv, &base, 600),
            Err(e) => return Err(e),
        },
    )
}

async fn serve_conn<A, B, IO>(srv: Arc<Server<A, B>>, io: IO, trust_real_ip: bool)
where
    A: Authenticator + 'static,
    B: Backend + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| serve(srv.clone(), trust_real_ip, req));
    // Connection errors are the client's business (resets, bad framing); nothing to log.
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(io), svc)
        .await;
}

#[derive(Debug, PartialEq)]
struct Args {
    port: u16,
    dovecot_socket: PathBuf,
    dovecot_service: String,
    session_idle_seconds: u64,
    notification_wait_seconds: u64,
    smb_conf: Option<PathBuf>,
    external_host: String,
    org: String,
    ou: String,
}

/// A positive number of seconds.
fn seconds(what: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .ok()
        .filter(|&n| n > 0)
        .ok_or(format!("bad {what}: {value}"))
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut port, mut socket, mut service, mut idle) = (None, None, "openchange".to_owned(), 1800);
    let (mut wait, mut smb_conf) = (300, None);
    let mut host = None;
    let mut org = "First Organization".to_owned();
    let mut ou = "Exchange Administrative Group (FYDIBOHF23SPDLT)".to_owned();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--port" => port = Some(value.parse().map_err(|_| format!("bad port: {value}"))?),
            "--dovecot-socket" => socket = Some(PathBuf::from(value)),
            // Sent unescaped in the AUTH line.
            "--dovecot-service" if value.is_empty() || value.contains(char::is_control) => {
                return Err(format!("bad service name: {value:?}"))
            }
            "--dovecot-service" => service = value,
            "--session-idle-seconds" => {
                idle = value
                    .parse()
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or(format!("bad session idle seconds: {value}"))?
            }
            "--notification-wait-seconds" => wait = seconds("notification wait seconds", &value)?,
            "--smb-conf" => smb_conf = Some(PathBuf::from(value)),
            // Becomes the authority of the advertised URLs.
            "--external-host"
                if value.is_empty()
                    || !value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c)) =>
            {
                return Err(format!("bad external host: {value:?}"))
            }
            "--external-host" => host = Some(value),
            "--org" => org = value,
            "--ou" => ou = value,
            _ => return Err(format!("unknown option: {flag}")),
        }
    }
    Ok(Args {
        port: port.ok_or("--port is required")?,
        dovecot_socket: socket.ok_or("--dovecot-socket is required")?,
        dovecot_service: service,
        session_idle_seconds: idle,
        notification_wait_seconds: wait,
        smb_conf,
        external_host: host.ok_or("--external-host is required")?,
        org,
        ou,
    })
}

/// liboc_emsmdb, initialised from `--smb-conf` before the runtime starts.
#[cfg(feature = "c-backend")]
fn start_backend(smb_conf: Option<PathBuf>) -> Result<backend::c::CBackend, String> {
    use std::os::unix::ffi::OsStringExt;
    let path = smb_conf.ok_or("--smb-conf is required")?;
    let conf = std::ffi::CString::new(path.into_os_string().into_vec())
        .map_err(|_| "--smb-conf contains a NUL byte".to_owned())?;
    backend::c::CBackend::start(conf).map_err(|s| format!("oc_emsmdb_init failed: {s:#010x}"))
}

/// Without the C library every Connect fails closed.
#[cfg(not(feature = "c-backend"))]
fn start_backend(smb_conf: Option<PathBuf>) -> Result<backend::NoBackend, String> {
    if smb_conf.is_some() {
        eprintln!("openchange-mapihttpd: built without c-backend; --smb-conf ignored");
    }
    Ok(backend::NoBackend)
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("openchange-mapihttpd: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let port = args.port;
    let backend = match start_backend(args.smb_conf) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("openchange-mapihttpd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("openchange-mapihttpd: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async {
        let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("openchange-mapihttpd: bind 127.0.0.1:{port}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let srv = Arc::new(Server {
            auth: DovecotAuthenticator {
                socket: args.dovecot_socket,
                service: args.dovecot_service,
            },
            sessions: SessionTable::new(Duration::from_secs(args.session_idle_seconds)),
            backend,
            notification_wait: Duration::from_secs(args.notification_wait_seconds),
            autodiscover: autodiscover::Settings {
                external_host: args.external_host,
                org: args.org,
                ou: args.ou,
            },
        });
        let sweeper = srv.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tick.tick().await;
                emsmdb::sweep(&sweeper, Instant::now()).await;
            }
        });
        loop {
            match listener.accept().await {
                Ok((sock, peer)) => {
                    let proxy = peer.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST);
                    tokio::spawn(serve_conn(srv.clone(), sock, proxy));
                }
                Err(e) => {
                    eprintln!("openchange-mapihttpd: accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use request::handle;
    use request::tests::{call, connect, execute, ping, run, server, BASIC, CLIENT_INFO};
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn header(r: &Response<Full<Bytes>>, name: &str) -> Option<String> {
        r.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    }

    fn respond(rep: &MapiReply) -> Response<Full<Bytes>> {
        to_response(rep, Duration::from_millis(1), SystemTime::now())
    }

    #[test]
    fn test_anonymous() {
        let rep = call(MapiRequest {
            authorization: None,
            ..ping("/mapi/emsmdb/")
        });
        let r = respond(&rep);
        assert_eq!(r.status(), 401);
        assert_eq!(header(&r, "WWW-Authenticate").as_deref(), Some(CHALLENGE));
    }

    #[test]
    fn test_bearer_challenged() {
        let srv = server();
        let rep = run(handle(
            &srv,
            MapiRequest {
                authorization: Some("Bearer eyJ0eXAi"),
                ..ping("/mapi/emsmdb/")
            },
        ));
        let r = respond(&rep);
        assert_eq!(r.status(), 401);
        assert_eq!(header(&r, "WWW-Authenticate").as_deref(), Some(CHALLENGE));
        assert_eq!(srv.auth.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_response_headers() {
        let r = respond(&call(ping("/mapi/nspi/")));
        assert_eq!(header(&r, "X-ClientInfo").as_deref(), Some(CLIENT_INFO));
        assert_eq!(
            header(&r, "X-ServerApplication").as_deref(),
            Some(request::SERVER_APPLICATION)
        );
        assert_eq!(header(&r, "X-ResponseCode").as_deref(), Some("0"));
        assert_eq!(header(&r, "X-PendingPeriod").as_deref(), Some("15000"));
        assert_eq!(
            header(&r, "Content-Type").as_deref(),
            Some("application/mapi-http")
        );
    }

    #[test]
    fn test_parse_args() {
        let args = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string()));
        assert_eq!(
            args(&[
                "--port",
                "8080",
                "--dovecot-socket",
                "/run/dovecot/auth-client",
                "--external-host",
                "mail.example.invalid",
            ]),
            Ok(Args {
                port: 8080,
                dovecot_socket: "/run/dovecot/auth-client".into(),
                dovecot_service: "openchange".into(),
                session_idle_seconds: 1800,
                notification_wait_seconds: 300,
                smb_conf: None,
                external_host: "mail.example.invalid".into(),
                org: "First Organization".into(),
                ou: "Exchange Administrative Group (FYDIBOHF23SPDLT)".into(),
            })
        );
        let full = args(&[
            "--dovecot-service",
            "mapi",
            "--dovecot-socket",
            "/s",
            "--port",
            "1",
            "--external-host",
            "h",
            "--org",
            "Example",
            "--ou",
            "Mail",
        ])
        .unwrap();
        assert_eq!(full.dovecot_service, "mapi");
        assert_eq!((full.org.as_str(), full.ou.as_str()), ("Example", "Mail"));
        assert_eq!(
            args(&["--port", "8080", "--external-host", "h"]),
            Err("--dovecot-socket is required".into())
        );
        assert_eq!(
            args(&["--port", "8080", "--dovecot-socket", "/s"]),
            Err("--external-host is required".into())
        );
        for host in ["", "a/b", "a b", "a?b"] {
            let a = args(&[
                "--port",
                "1",
                "--dovecot-socket",
                "/s",
                "--external-host",
                host,
            ]);
            assert!(a.is_err(), "{host:?}");
        }
        let base = [
            "--port",
            "1",
            "--dovecot-socket",
            "/s",
            "--external-host",
            "mail.example.invalid",
        ];
        let with = |extra: &[&str]| args(&[&base[..], extra].concat());
        let a = with(&[
            "--notification-wait-seconds",
            "5",
            "--smb-conf",
            "/etc/samba/smb.conf",
        ]);
        let a = a.unwrap();
        assert_eq!(a.notification_wait_seconds, 5);
        assert_eq!(a.smb_conf, Some(PathBuf::from("/etc/samba/smb.conf")));
        assert!(with(&["--notification-wait-seconds", "0"]).is_err());
        assert!(args(&["--port"]).is_err());
        assert!(args(&["--port", "8080", "x"]).is_err());
        assert!(args(&[
            "--dovecot-socket",
            "/s",
            "--port",
            "1",
            "--dovecot-service",
            "a\tb",
            "--external-host",
            "h"
        ])
        .is_err());
        assert!(args(&[]).is_err());
        let idle = args(&[
            "--session-idle-seconds",
            "60",
            "--port",
            "8080",
            "--dovecot-socket",
            "/s",
            "--external-host",
            "h",
        ]);
        assert_eq!(idle.unwrap().session_idle_seconds, 60);
        assert!(args(&[
            "--port",
            "8080",
            "--dovecot-socket",
            "/s",
            "--external-host",
            "h",
            "--session-idle-seconds",
            "0"
        ])
        .is_err());
    }

    /// Sends request headers only (the declared body is never written) and returns the
    /// response head and the authenticator call count; fails if the server waits for the
    /// body instead of answering.
    fn head_only(headers: &str) -> (String, usize) {
        run(async {
            let (mut client, conn) = tokio::io::duplex(64 * 1024);
            let srv = Arc::new(server());
            tokio::spawn(serve_conn(srv.clone(), conn, false));
            client.write_all(headers.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            while !out.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
                    .await
                    .expect("server waited for the body")
                    .unwrap();
                assert!(n > 0, "connection closed without a response");
                out.extend_from_slice(&buf[..n]);
            }
            let calls = srv.auth.calls.load(Ordering::SeqCst);
            (String::from_utf8(out).unwrap(), calls)
        })
    }

    #[test]
    fn test_bearer_large_body_not_read() {
        let (out, calls) = head_only(
            "POST /mapi/emsmdb/ HTTP/1.1\r\nHost: mail.example.invalid\r\n\
             Authorization: Bearer eyJ0eXAi\r\nContent-Type: application/mapi-http\r\n\
             X-RequestType: PING\r\nX-RequestId: {A}:1\r\nContent-Length: 16777217\r\n\r\n",
        );
        assert!(out.starts_with("HTTP/1.1 401 "), "{out}");
        assert_eq!(calls, 0);
        assert!(
            out.contains("www-authenticate: Basic realm=\"openchange\""),
            "{out}"
        );
    }

    #[test]
    fn test_wrong_basic_body_not_read() {
        // user:nope; 1 MiB declared (within the limit) and never sent.
        let (out, calls) = head_only(
            "POST /mapi/emsmdb/ HTTP/1.1\r\nHost: mail.example.invalid\r\n\
             Authorization: Basic dXNlcjpub3Bl\r\nContent-Type: application/mapi-http\r\n\
             X-RequestType: PING\r\nX-RequestId: {A}:1\r\nContent-Length: 1048576\r\n\r\n",
        );
        assert!(out.starts_with("HTTP/1.1 401 "), "{out}");
        assert_eq!(calls, 1);
    }

    #[test]
    fn test_declared_too_large_not_read() {
        let (out, _) = head_only(&format!(
            "POST /mapi/emsmdb/ HTTP/1.1\r\nHost: mail.example.invalid\r\n\
             Authorization: {BASIC}\r\nContent-Type: application/mapi-http\r\n\
             X-RequestType: PING\r\nX-RequestId: {{A}}:1\r\nContent-Length: 16777217\r\n\r\n"
        ));
        assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
        assert!(out.contains("x-responsecode: 9\r\n"), "{out}");
    }

    #[test]
    fn test_session_reply_headers() {
        let srv = server();
        let sc = connect(&srv, Instant::now());
        let rep = run(handle(&srv, execute(Some(sc.split(';').next().unwrap()))));
        let r = respond(&rep);
        assert_eq!(header(&r, "Set-Cookie"), Some(sc));
        assert_eq!(header(&r, "X-ExpirationInfo").as_deref(), Some("1800000"));
    }

    #[test]
    fn test_glue_split_cookie_fields() {
        let srv = Arc::new(server());
        let sc = connect(&srv, Instant::now());
        let raw = format!(
            "POST /mapi/emsmdb/ HTTP/1.1\r\nHost: mail.example.invalid\r\nConnection: close\r\n\
             Content-Length: 0\r\nContent-Type: application/mapi-http\r\n\
             X-RequestType: Execute\r\nX-RequestId: {{A}}:1\r\nAuthorization: {BASIC}\r\n\
             Cookie: sid=1\r\nCookie: {}\r\n\r\n",
            sc.split(';').next().unwrap()
        );
        let out = run(async {
            let (mut client, conn) = tokio::io::duplex(64 * 1024);
            tokio::spawn(serve_conn(srv.clone(), conn, false));
            client.write_all(raw.as_bytes()).await.unwrap();
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            out
        });
        assert!(!out.contains("x-responsecode: 13\r\n"), "{out}");
        assert!(out.contains(&format!("set-cookie: {sc}\r\n")), "{out}");
    }

    #[test]
    fn test_glue_outlook_headers() {
        // Headers of the Connect entry in testsuite/modernization/mapihttp/headers.json, sent as PING.
        let raw = format!(
            "POST /mapi/emsmdb/ HTTP/1.1\r\n\
             Host: mail.example.invalid\r\n\
             Connection: close\r\n\
             Content-Length: 0\r\n\
             Cache-Control: no-cache\r\n\
             Pragma: no-cache\r\n\
             Content-Type: application/mapi-http\r\n\
             Accept: application/mapi-http\r\n\
             User-Agent: Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.19127; Pro)\r\n\
             X-MS-CookieUri-Requested: t\r\n\
             X-FeatureVersion: 1\r\n\
             Accept-Auth: badger,Wlid1.1,Bearer,Basic,NTLM,Digest,Kerberos,Negotiate,Nego2\r\n\
             Client-Request-Id: {{DE5FF42C-89BB-47E5-8664-44B796DD2A7B}}\r\n\
             X-User-Identity: spike@example.invalid\r\n\
             X-MS-Negotiate: Server\r\n\
             X-Accept: application/json\r\n\
             X-ClientApplication: Outlook/16.0.19127.20800\r\n\
             X-ClientInfo: {CLIENT_INFO}\r\n\
             X-RequestId: {{DE412C9D-4AA7-444C-9405-977C4D90FA85}}:2\r\n\
             X-RequestType: PING\r\n\
             Authorization: {BASIC}\r\n\
             \r\n"
        );
        let out = run(async {
            let (mut client, conn) = tokio::io::duplex(64 * 1024);
            let srv = Arc::new(server());
            tokio::spawn(serve_conn(srv, conn, false));
            client.write_all(raw.as_bytes()).await.unwrap();
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            out
        });
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
        let lower = out.to_ascii_lowercase();
        assert!(lower.contains("\r\nx-responsecode: 0\r\n"), "{out}");
        assert!(lower.contains("\r\nx-requesttype: ping\r\n"), "{out}");
        assert!(out.contains("\r\n\r\nPROCESSING\r\nDONE\r\nX-ResponseCode: 0\r\n"));
    }

    #[test]
    fn test_real_ip_only_from_proxy() {
        for (trusted, want) in [(false, None), (true, "192.0.2.7".parse().ok())] {
            let rip = run(async {
                let (mut client, conn) = tokio::io::duplex(64 * 1024);
                let srv = Arc::new(server());
                tokio::spawn(serve_conn(srv.clone(), conn, trusted));
                let raw = format!(
                    "POST /mapi/emsmdb/ HTTP/1.1\r\nHost: mail.example.invalid\r\n\
                     Connection: close\r\nAuthorization: {BASIC}\r\n\
                     Content-Type: application/mapi-http\r\nX-RequestType: PING\r\n\
                     X-RequestId: {{A}}:1\r\nX-Real-IP: 192.0.2.7\r\nContent-Length: 0\r\n\r\n"
                );
                client.write_all(raw.as_bytes()).await.unwrap();
                let mut out = String::new();
                client.read_to_string(&mut out).await.unwrap();
                assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
                let rip = *srv.auth.rip.lock().unwrap();
                rip
            });
            assert_eq!(rip, want);
        }
    }

    #[test]
    fn test_glue_autodiscover() {
        let body = include_str!("../../testsuite/modernization/mapihttp/autodiscover-request.xml");
        let raw = format!(
            "POST /AutoDiscover/AutoDiscover.xml HTTP/1.1\r\nHost: mail.example.invalid\r\n\
             Connection: close\r\nContent-Type: text/xml\r\nX-MapiHttpCapability: 1\r\n\
             X-AnchorMailbox: bob@example.invalid\r\n\
             Authorization: Basic YWxpY2VAZXhhbXBsZS5pbnZhbGlkOnBhc3M=\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let out = run(async {
            let (mut client, conn) = tokio::io::duplex(64 * 1024);
            tokio::spawn(serve_conn(Arc::new(server()), conn, false));
            client.write_all(raw.as_bytes()).await.unwrap();
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            out
        });
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
        assert!(
            out.contains("content-type: text/xml; charset=utf-8\r\n"),
            "{out}"
        );
        assert!(!out.contains("x-responsecode"), "{out}");
        let response =
            include_str!("../../testsuite/modernization/mapihttp/autodiscover-response.xml");
        assert!(out.ends_with(&format!("\r\n\r\n{response}")), "{out}");
    }

    #[test]
    fn test_glue_autodiscover_body_not_read() {
        // Bearer and wrong Basic are answered before the declared body arrives.
        for (auth, calls) in [("Bearer eyJ0eXAi", 0), ("Basic dXNlcjpub3Bl", 1)] {
            let (out, n) = head_only(&format!(
                "POST /autodiscover/autodiscover.xml HTTP/1.1\r\nHost: mail.example.invalid\r\n\
                 Authorization: {auth}\r\nContent-Type: text/xml\r\nContent-Length: 1000\r\n\r\n"
            ));
            assert!(out.starts_with("HTTP/1.1 401 "), "{out}");
            assert!(
                out.contains("www-authenticate: Basic realm=\"openchange\""),
                "{out}"
            );
            assert_eq!(n, calls);
        }
        let (out, _) = head_only(&format!(
            "GET /autodiscover/autodiscover.xml HTTP/1.1\r\nHost: mail.example.invalid\r\n\
             Authorization: {BASIC}\r\n\r\n"
        ));
        assert!(out.starts_with("HTTP/1.1 405 "), "{out}");
        assert!(out.contains("allow: POST\r\n"), "{out}");
    }
}

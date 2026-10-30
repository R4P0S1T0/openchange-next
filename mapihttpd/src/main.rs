//! openchange-mapihttpd: MAPI/HTTP service listening on 127.0.0.1 behind a TLS reverse proxy.

// Until the Dovecot authenticator (Task 3), only the tests use every item.
#[cfg_attr(not(test), allow(dead_code))]
mod auth;
mod request;

use auth::{parse_authorization, AuthResult, Authenticator, BasicCredentials, Password};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use request::{format_reply, handle, reply, MapiReply, MapiRequest, Server, MAX_BODY};
use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

const CHALLENGE: &str = "Basic realm=\"openchange\"";
/// Connections that have not sent complete request headers by then are closed.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const USAGE: &str = "usage: openchange-mapihttpd --port PORT";

/// Placeholder until the Dovecot authenticator lands: nobody gets in.
struct RejectAll;

impl Authenticator for RejectAll {
    async fn authenticate(&self, _: &str, _: &Password, _: Option<IpAddr>) -> AuthResult {
        AuthResult::BadCredentials
    }
}

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
        200 => {
            let ctype = if rep.response_code == 0 {
                "application/mapi-http"
            } else {
                "text/html"
            };
            b = b
                .header("Content-Type", ctype)
                .header("X-ResponseCode", rep.response_code);
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
        _ => Vec::new(),
    };
    b.body(Full::new(Bytes::from(body))).unwrap_or_else(|_| {
        let mut r = Response::new(Full::default());
        *r.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
        r
    })
}

async fn serve<A: Authenticator>(
    srv: Arc<Server<A>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let (start, t0) = (SystemTime::now(), Instant::now());
    let (parts, body) = req.into_parts();
    let h = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
    let base = MapiRequest {
        method: parts.method.as_str(),
        path: parts.uri.path(),
        request_type: h("X-RequestType"),
        request_id: h("X-RequestId"),
        client_info: h("X-ClientInfo"),
        content_type: h("Content-Type"),
        authorization: h("Authorization"),
        cookie: h("Cookie"),
        real_ip: h("X-Real-IP").and_then(|v| v.parse().ok()),
        body: &[],
    };
    // Decide from headers alone what must not cost a body read: no Basic credentials or
    // an oversized declared body. Chunked bodies are still capped by Limited below.
    if !matches!(
        parse_authorization(base.authorization),
        BasicCredentials::Basic { .. }
    ) {
        return Ok(to_response(&reply(&base, 401, 0), t0.elapsed(), start));
    }
    let declared = h("Content-Length").and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_BODY as u64) {
        return Ok(to_response(&reply(&base, 200, 9), t0.elapsed(), start));
    }
    let rep = match Limited::new(body, MAX_BODY).collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            handle(
                &srv,
                MapiRequest {
                    body: &bytes,
                    ..base
                },
            )
            .await
        }
        Err(e) if e.is::<LengthLimitError>() => reply(&base, 200, 9),
        Err(e) => return Err(e),
    };
    Ok(to_response(&rep, t0.elapsed(), start))
}

async fn serve_conn<A, IO>(srv: Arc<Server<A>>, io: IO)
where
    A: Authenticator + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| serve(srv.clone(), req));
    // Connection errors are the client's business (resets, bad framing); nothing to log.
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(io), svc)
        .await;
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Option<u16> {
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--port"), Some(port), None) => port.parse().ok(),
        _ => None,
    }
}

fn main() -> ExitCode {
    let Some(port) = parse_args(std::env::args().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
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
        let srv = Arc::new(Server { auth: RejectAll });
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    tokio::spawn(serve_conn(srv.clone(), sock));
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
    use request::tests::{call, ping, run, FakeAuth, BASIC, CLIENT_INFO};
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
        let srv = Server {
            auth: FakeAuth::default(),
        };
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
        assert_eq!(
            header(&r, "Content-Type").as_deref(),
            Some("application/mapi-http")
        );
    }

    #[test]
    fn test_parse_args() {
        let args = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string()));
        assert_eq!(args(&["--port", "8080"]), Some(8080));
        assert_eq!(args(&["--port"]), None);
        assert_eq!(args(&["--port", "8080", "x"]), None);
        assert_eq!(args(&[]), None);
    }

    /// Sends request headers only (the declared body is never written) and returns the
    /// response head; fails if the server waits for the body instead of answering.
    fn head_only(headers: &str) -> String {
        run(async {
            let (mut client, server) = tokio::io::duplex(64 * 1024);
            let srv = Arc::new(Server {
                auth: FakeAuth::default(),
            });
            tokio::spawn(serve_conn(srv, server));
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
            String::from_utf8(out).unwrap()
        })
    }

    #[test]
    fn test_bearer_large_body_not_read() {
        let out = head_only(
            "POST /mapi/emsmdb/ HTTP/1.1\r\nHost: mail.example.invalid\r\n\
             Authorization: Bearer eyJ0eXAi\r\nContent-Type: application/mapi-http\r\n\
             X-RequestType: Execute\r\nX-RequestId: {A}:1\r\nContent-Length: 16777217\r\n\r\n",
        );
        assert!(out.starts_with("HTTP/1.1 401 "), "{out}");
        assert!(
            out.contains("www-authenticate: Basic realm=\"openchange\""),
            "{out}"
        );
    }

    #[test]
    fn test_declared_too_large_not_read() {
        let out = head_only(&format!(
            "POST /mapi/emsmdb/ HTTP/1.1\r\nHost: mail.example.invalid\r\n\
             Authorization: {BASIC}\r\nContent-Type: application/mapi-http\r\n\
             X-RequestType: Execute\r\nX-RequestId: {{A}}:1\r\nContent-Length: 16777217\r\n\r\n"
        ));
        assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
        assert!(out.contains("x-responsecode: 9\r\n"), "{out}");
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
            let (mut client, server) = tokio::io::duplex(64 * 1024);
            let srv = Arc::new(Server {
                auth: FakeAuth::default(),
            });
            tokio::spawn(serve_conn(srv, server));
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
}

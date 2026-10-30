//! MAPI/HTTP request validation, routing and reply layout (MS-OXCMAPIHTTP).

use crate::auth::{parse_authorization, AuthResult, Authenticator, BasicCredentials, Password};
use crate::autodiscover;
use crate::backend::Backend;
use crate::emsmdb;
use crate::session::{SessionGuard, SessionTable};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Sent as X-ServerApplication on every response (2.2.3.3.7).
pub const SERVER_APPLICATION: &str = "Exchange/15.02.1544.004";
/// Largest accepted request body; larger bodies get code 9.
pub const MAX_BODY: usize = 16 * 1024 * 1024;

pub struct Server<A: Authenticator, B: Backend> {
    pub auth: A,
    pub sessions: SessionTable,
    pub autodiscover: autodiscover::Settings,
    pub backend: B,
    /// How long NotificationWait waits for an event (3.2.2).
    pub notification_wait: Duration,
}

/// Who `check_headers` let through.
pub enum Admitted<'s> {
    /// A request bound to a live Session Context (or PING keeping one alive).
    Session(SessionGuard<'s>),
    /// Credentials the authenticator accepted: its canonical user, and the hash of the
    /// credentials as sent, which later requests on a new session must match.
    User { user: String, cred_hash: [u8; 32] },
}

pub struct MapiRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub request_type: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub client_info: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub authorization: Option<&'a str>,
    pub cookie: Option<&'a str>,
    pub real_ip: Option<IpAddr>,
    pub body: &'a [u8],
}

/// No Debug: it carries the session cookie.
pub struct MapiReply {
    pub http_status: u16,
    pub response_code: u32,
    pub request_type: Option<String>,
    pub request_id: Option<String>,
    pub client_info: Option<String>,
    pub body: Vec<u8>,
    pub set_cookie: Option<String>,
    pub expiration_ms: u32,
    /// An Autodiscover document, without MAPI/HTTP framing.
    pub xml: bool,
}

/// Header and body stages in sequence, as the glue runs them around its body read.
#[cfg(test)]
pub async fn handle<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: MapiRequest<'_>,
) -> MapiReply {
    let declared = u64::try_from(req.body.len()).ok();
    match check_headers(srv, &req, declared).await {
        Ok(admitted) => handle_body(srv, &req, admitted).await,
        Err(rep) => rep,
    }
}

/// Everything decided before the body is read, in one fixed order (codes of 2.2.3.3.3).
/// `declared_len` is the Content-Length; the glue still caps chunked bodies itself.
/// Request types bound to a Session Context come back with its guard held.
pub async fn check_headers<'s, A: Authenticator, B: Backend>(
    srv: &'s Server<A, B>,
    req: &MapiRequest<'_>,
    declared_len: Option<u64>,
) -> Result<Admitted<'s>, MapiReply> {
    if req.method != "POST" {
        return Err(reply(req, 200, 2));
    }
    let is_path = |p: &str| req.path.eq_ignore_ascii_case(p);
    if !is_path("/mapi/emsmdb/") && !is_path("/mapi/nspi/") {
        return Err(reply(req, 200, 3));
    }
    let (Some(request_type), Some(_), Some(ctype)) =
        (req.request_type, req.request_id, req.content_type)
    else {
        return Err(reply(req, 200, 7));
    };
    if !ctype.to_ascii_lowercase().contains("application/mapi-http") {
        return Err(reply(req, 200, 4));
    }
    // NSPI request types arrive with that endpoint.
    let needs_session = match request_type {
        "PING" => false,
        "Connect" if is_path("/mapi/emsmdb/") => false,
        "Execute" | "Disconnect" | "NotificationWait" if is_path("/mapi/emsmdb/") => true,
        _ => return Err(reply(req, 200, 5)),
    };
    let (user, password) = basic_credentials(req)?;
    if declared_len.is_some_and(|n| n > MAX_BODY as u64) {
        return Err(reply(req, 200, 9));
    }
    if needs_session {
        // The session's credential hash stands in for the authenticator (decision 4).
        let hash = srv.sessions.credential_hash(&user, &password);
        let session = if request_type == "NotificationWait" {
            srv.sessions
                .begin_notification(req.cookie, hash, Instant::now())
        } else {
            srv.sessions.begin(req.cookie, hash, Instant::now())
        };
        return match session {
            Ok(guard) => Ok(Admitted::Session(guard)),
            Err(code) => Err(reply(req, 200, code)),
        };
    }
    // PING with a live cookie keeps the session alive (3.1.5.3); otherwise authenticate.
    if request_type == "PING" {
        let hash = srv.sessions.credential_hash(&user, &password);
        if let Some(touched) = srv.sessions.touch(req.cookie, hash, Instant::now()) {
            return Ok(Admitted::Session(touched));
        }
    }
    let canonical = authenticate(srv, req, &user, &password).await?;
    Ok(Admitted::User {
        user: canonical,
        cred_hash: srv.sessions.credential_hash(&user, &password),
    })
}

/// Bearer and other schemes are challenged without reaching the authenticator.
#[allow(clippy::result_large_err)] // the reply check_headers returns
pub fn basic_credentials(req: &MapiRequest<'_>) -> Result<(String, Password), MapiReply> {
    match parse_authorization(req.authorization) {
        BasicCredentials::Basic { user, password } => Ok((user, password)),
        _ => Err(reply(req, 401, 0)),
    }
}

/// Checks the credentials with the authenticator; returns its canonical user name.
pub async fn authenticate<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    user: &str,
    password: &Password,
) -> Result<String, MapiReply> {
    match srv.auth.authenticate(user, password, req.real_ip).await {
        AuthResult::Ok { user } => Ok(user),
        AuthResult::BadCredentials => Err(reply(req, 401, 0)),
        AuthResult::TempFail => Err(reply(req, 503, 0)),
    }
}

/// Runs a request that passed `check_headers`, with its body read.
pub async fn handle_body<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    admitted: Admitted<'_>,
) -> MapiReply {
    // Taken before Disconnect consumes the guard: it still sends the cookie (3.2.5.4).
    let session_headers = match &admitted {
        Admitted::Session(s) => Some((s.set_cookie(), s.expiration_ms())),
        Admitted::User { .. } => None,
    };
    let mut rep = match (req.request_type, admitted) {
        (Some("PING"), _) => reply(req, 200, 0),
        (Some("Connect"), Admitted::User { user, cred_hash }) => {
            return emsmdb::connect(srv, req, user, cred_hash).await
        }
        (Some("Execute"), Admitted::Session(s)) => emsmdb::execute(srv, req, &s).await,
        (Some("Disconnect"), Admitted::Session(s)) => emsmdb::disconnect(srv, req, s).await,
        (Some("NotificationWait"), Admitted::Session(s)) => {
            emsmdb::notification_wait(srv, req, &s).await
        }
        _ => reply(req, 200, 5),
    };
    if let Some((cookie, ms)) = session_headers {
        rep.set_cookie = Some(cookie);
        rep.expiration_ms = ms;
    }
    rep
}

/// A reply echoing the request's identifying headers with an empty body.
pub fn reply(req: &MapiRequest<'_>, http_status: u16, response_code: u32) -> MapiReply {
    MapiReply {
        http_status,
        response_code,
        request_type: req.request_type.map(str::to_owned),
        request_id: req.request_id.map(str::to_owned),
        client_info: req.client_info.map(str::to_owned),
        body: Vec::new(),
        set_cookie: None,
        expiration_ms: 0,
        xml: false,
    }
}

/// The response body layout of 2.2.2.2 / 4.1: meta-tags, additional headers, body.
pub fn format_reply(rep: &MapiReply, elapsed_ms: u32, start: &str) -> Vec<u8> {
    let mut out = format!(
        "PROCESSING\r\nDONE\r\nX-ResponseCode: {}\r\nX-ElapsedTime: {elapsed_ms}\r\nX-StartTime: {start}\r\n\r\n",
        rep.response_code
    )
    .into_bytes();
    out.extend_from_slice(&rep.body);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::backend::FakeBackend;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// Accepts any user but `temp` with password `pass`, canonicalized to lower case;
    /// counts calls and records the last `rip`.
    #[derive(Default)]
    pub struct FakeAuth {
        pub calls: AtomicUsize,
        pub rip: Mutex<Option<IpAddr>>,
    }

    impl Authenticator for FakeAuth {
        async fn authenticate(&self, user: &str, pw: &Password, rip: Option<IpAddr>) -> AuthResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.rip.lock().unwrap() = rip;
            if user == "temp" {
                AuthResult::TempFail
            } else if pw.expose() == "pass" {
                AuthResult::Ok {
                    user: user.to_ascii_lowercase(),
                }
            } else {
                AuthResult::BadCredentials
            }
        }
    }

    /// `user:pass`
    pub const BASIC: &str = "Basic dXNlcjpwYXNz";
    pub const CLIENT_INFO: &str = "{0589012E-9A4E-4666-9EE1-3C5BD8DDF18B}:558760020";

    pub fn ping(path: &str) -> MapiRequest<'_> {
        MapiRequest {
            method: "POST",
            path,
            request_type: Some("PING"),
            request_id: Some("{DE412C9D-4AA7-444C-9405-977C4D90FA85}:2"),
            client_info: Some(CLIENT_INFO),
            content_type: Some("application/mapi-http"),
            authorization: Some(BASIC),
            cookie: None,
            real_ip: None,
            body: b"",
        }
    }

    pub fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    pub type TestServer = Server<FakeAuth, FakeBackend>;

    pub fn server() -> TestServer {
        Server {
            auth: FakeAuth::default(),
            sessions: SessionTable::new(Duration::from_secs(1800)),
            autodiscover: settings(),
            backend: FakeBackend::default(),
            notification_wait: Duration::from_secs(300),
        }
    }

    pub fn settings() -> autodiscover::Settings {
        autodiscover::Settings {
            external_host: "mail.example.invalid".into(),
            org: "First Organization".into(),
            ou: "Exchange Administrative Group (FYDIBOHF23SPDLT)".into(),
        }
    }

    pub fn call(req: MapiRequest<'_>) -> MapiReply {
        run(handle(&server(), req))
    }

    /// An Execute request carrying `cookie`.
    pub fn execute(cookie: Option<&str>) -> MapiRequest<'_> {
        MapiRequest {
            request_type: Some("Execute"),
            cookie,
            ..ping("/mapi/emsmdb/")
        }
    }

    /// A session for `user:pass`; returns its Set-Cookie value.
    pub fn connect(srv: &TestServer, now: Instant) -> String {
        let h = srv
            .sessions
            .credential_hash("user", &Password::from("pass"));
        srv.sessions.create(h, 1, now)
    }

    #[test]
    fn test_notification_wait_overlaps_execute() {
        let srv = server();
        let sc = connect(&srv, Instant::now());
        let ordinary = execute(Some(cookie_of(&sc)));
        let wait = MapiRequest {
            request_type: Some("NotificationWait"),
            ..execute(Some(cookie_of(&sc)))
        };
        for (first, second) in [(&ordinary, &wait), (&wait, &ordinary)] {
            let held = run(check_headers(&srv, first, Some(0))).ok().unwrap();
            let other = run(check_headers(&srv, second, Some(0))).ok();
            assert!(other.is_some(), "NotificationWait and Execute must overlap");
            assert_eq!(
                run(check_headers(&srv, &ordinary, Some(0)))
                    .err()
                    .unwrap()
                    .response_code,
                15
            );
            assert_eq!(
                run(check_headers(&srv, &wait, Some(0)))
                    .err()
                    .unwrap()
                    .response_code,
                15
            );
            // Pending requests keep the context alive even with a short idle timeout.
            assert!(srv
                .sessions
                .expire(Instant::now() + Duration::from_secs(1801))
                .is_empty());
            drop(other);
            drop(held);
        }
    }

    fn cookie_of(set_cookie: &str) -> &str {
        set_cookie.split(';').next().unwrap()
    }

    fn code(rep: &MapiReply) -> (u16, u32) {
        (rep.http_status, rep.response_code)
    }

    #[test]
    fn test_execute_without_cookie() {
        assert_eq!(code(&call(execute(None))), (200, 13));
        for t in ["Disconnect", "NotificationWait"] {
            let req = MapiRequest {
                request_type: Some(t),
                ..execute(None)
            };
            assert_eq!(code(&call(req)), (200, 13), "{t}");
        }
    }

    #[test]
    fn test_cookie_garbage() {
        assert_eq!(code(&call(execute(Some("MapiContext=zz")))), (200, 6));
    }

    #[test]
    fn test_cookie_other_user() {
        let srv = server();
        let sc = connect(&srv, Instant::now());
        let other = MapiRequest {
            authorization: Some("Basic b3RoZXI6cGFzcw=="), // other:pass
            ..execute(Some(cookie_of(&sc)))
        };
        assert_eq!(code(&run(handle(&srv, other))), (200, 10));
        // The owner's session is unaffected, and its hash spares the authenticator.
        let rep = run(handle(&srv, execute(Some(cookie_of(&sc)))));
        assert_ne!(rep.response_code, 10);
        assert_eq!(rep.set_cookie.as_deref(), Some(sc.as_str()));
        assert_eq!(rep.expiration_ms, 1_800_000);
        assert_eq!(srv.auth.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_busy_session() {
        let srv = server();
        let sc = connect(&srv, Instant::now());
        let req = execute(Some(cookie_of(&sc)));
        let held = run(check_headers(&srv, &req, Some(0))).ok().unwrap();
        assert!(matches!(held, Admitted::Session(_)));
        assert_eq!(
            code(&run(handle(&srv, execute(Some(cookie_of(&sc)))))),
            (200, 15)
        );
        drop(held);
        assert_ne!(
            run(handle(&srv, execute(Some(cookie_of(&sc))))).response_code,
            15
        );
    }

    #[test]
    fn test_bearer_with_live_cookie() {
        let srv = server();
        let then = Instant::now();
        let sc = connect(&srv, then);
        let value = &cookie_of(&sc)["MapiContext=".len()..];
        for authorization in [Some("Bearer eyJ0eXAi"), None, Some("Basic !!!")] {
            let req = MapiRequest {
                authorization,
                ..execute(Some(cookie_of(&sc)))
            };
            assert_eq!(run(handle(&srv, req)).http_status, 401);
        }
        assert_eq!(srv.sessions.last_used(value), Some(then));
        assert_eq!(srv.auth.calls.load(Ordering::SeqCst), 0);
    }

    fn ping_with<'a>(cookie: Option<&'a str>, authorization: Option<&'a str>) -> MapiRequest<'a> {
        MapiRequest {
            cookie,
            authorization,
            ..ping("/mapi/emsmdb/")
        }
    }

    #[test]
    fn test_ping_refreshes_session() {
        let srv = server();
        let then = Instant::now() - Duration::from_secs(1);
        let sc = connect(&srv, then);
        let value = &cookie_of(&sc)["MapiContext=".len()..];
        let rep = run(handle(&srv, ping_with(Some(cookie_of(&sc)), Some(BASIC))));
        assert_eq!(code(&rep), (200, 0));
        assert_eq!(rep.expiration_ms, 1_800_000);
        assert_eq!(rep.set_cookie.as_deref(), Some(sc.as_str()));
        assert!(srv.sessions.last_used(value).unwrap() > then);
        assert_eq!(srv.auth.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_ping_while_busy() {
        let srv = server();
        let then = Instant::now() - Duration::from_secs(1);
        let sc = connect(&srv, then);
        let value = &cookie_of(&sc)["MapiContext=".len()..];
        let exec = execute(Some(cookie_of(&sc)));
        let held = run(check_headers(&srv, &exec, Some(0))).ok().unwrap();
        let before = srv.sessions.last_used(value).unwrap();
        let rep = run(handle(&srv, ping_with(Some(cookie_of(&sc)), Some(BASIC))));
        assert_eq!(code(&rep), (200, 0));
        assert_eq!(rep.expiration_ms, 1_800_000);
        assert!(srv.sessions.last_used(value).unwrap() >= before);
        // The Execute still holds the session.
        assert_eq!(
            code(&run(handle(&srv, execute(Some(cookie_of(&sc)))))),
            (200, 15)
        );
        drop(held);
    }

    #[test]
    fn test_ping_other_credentials() {
        let srv = server();
        let then = Instant::now() - Duration::from_secs(1);
        let sc = connect(&srv, then);
        let value = &cookie_of(&sc)["MapiContext=".len()..];
        // user:nope
        let rep = run(handle(
            &srv,
            ping_with(Some(cookie_of(&sc)), Some("Basic dXNlcjpub3Bl")),
        ));
        assert_eq!(rep.http_status, 401);
        assert_eq!(srv.auth.calls.load(Ordering::SeqCst), 1);
        assert_eq!(srv.sessions.last_used(value), Some(then));
        assert!(rep.set_cookie.is_none());
    }

    #[test]
    fn test_ping_garbage_cookie() {
        let srv = server();
        let rep = run(handle(&srv, ping_with(Some("MapiContext=zz"), Some(BASIC))));
        assert_eq!(code(&rep), (200, 0));
        assert_eq!(rep.expiration_ms, 0);
        assert_eq!(srv.auth.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_session_types_emsmdb_only() {
        let req = MapiRequest {
            path: "/mapi/nspi/",
            ..execute(None)
        };
        assert_eq!(code(&call(req)), (200, 5));
    }

    #[test]
    fn test_get_rejected() {
        let rep = call(MapiRequest {
            method: "GET",
            ..ping("/mapi/emsmdb/")
        });
        assert_eq!((rep.http_status, rep.response_code), (200, 2));
        // Verb is checked before credentials, in handle and in the glue alike.
        let anon = call(MapiRequest {
            method: "GET",
            authorization: None,
            ..ping("/mapi/emsmdb/")
        });
        assert_eq!((anon.http_status, anon.response_code), (200, 2));
    }

    #[test]
    fn test_unknown_path() {
        assert_eq!(call(ping("/mapi/other/")).response_code, 3);
    }

    #[test]
    fn test_missing_headers() {
        let path = "/mapi/emsmdb/";
        let no_id = MapiRequest {
            request_id: None,
            ..ping(path)
        };
        assert_eq!(call(no_id).response_code, 7);
        let no_type = MapiRequest {
            request_type: None,
            ..ping(path)
        };
        assert_eq!(call(no_type).response_code, 7);
        let text = MapiRequest {
            content_type: Some("text/plain"),
            ..ping(path)
        };
        assert_eq!(call(text).response_code, 4);
    }

    #[test]
    fn test_bad_request_type() {
        let rep = call(MapiRequest {
            request_type: Some("Bind"),
            ..ping("/mapi/emsmdb/")
        });
        assert_eq!(rep.response_code, 5);
    }

    #[test]
    fn test_ping() {
        for path in ["/mapi/emsmdb/", "/mapi/nspi/"] {
            let rep = call(ping(path));
            assert_eq!((rep.http_status, rep.response_code), (200, 0), "{path}");
            assert!(rep.body.is_empty());
            assert_eq!(rep.request_type.as_deref(), Some("PING"));
        }
    }

    #[test]
    fn test_bad_password() {
        let rep = call(MapiRequest {
            authorization: Some("Basic dXNlcjpub3Bl"), // user:nope
            ..ping("/mapi/emsmdb/")
        });
        assert_eq!(rep.http_status, 401);
    }

    #[test]
    fn test_auth_tempfail() {
        let rep = call(MapiRequest {
            authorization: Some("Basic dGVtcDpwYXNz"), // temp:pass
            ..ping("/mapi/emsmdb/")
        });
        assert_eq!(rep.http_status, 503);
    }

    #[test]
    fn test_too_large() {
        let big = vec![0u8; MAX_BODY + 1];
        let rep = call(MapiRequest {
            body: &big,
            ..ping("/mapi/emsmdb/")
        });
        assert_eq!(rep.response_code, 9);
    }

    #[test]
    fn test_reply_layout() {
        let mut rep = call(ping("/mapi/emsmdb/"));
        rep.body = b"BODY".to_vec();
        let out = format_reply(&rep, 3, "Thu, 30 Oct 2026 11:30:11 GMT");
        assert!(out.starts_with(b"PROCESSING\r\nDONE\r\nX-ResponseCode: 0\r\n"));
        let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        assert_eq!(&out[split + 4..], b"BODY");
    }
}

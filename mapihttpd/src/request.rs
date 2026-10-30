//! MAPI/HTTP request validation, routing and reply layout (MS-OXCMAPIHTTP).

use crate::auth::{parse_authorization, AuthResult, Authenticator, BasicCredentials};
use std::net::IpAddr;

/// Sent as X-ServerApplication on every response (2.2.3.3.7).
pub const SERVER_APPLICATION: &str = "Exchange/15.02.1544.004";
/// Largest accepted request body; larger bodies get code 9.
pub const MAX_BODY: usize = 16 * 1024 * 1024;

pub struct Server<A: Authenticator> {
    pub auth: A,
}

pub struct MapiRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub request_type: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub client_info: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub authorization: Option<&'a str>,
    #[allow(dead_code)] // read by the session cookie check (Task 2)
    pub cookie: Option<&'a str>,
    pub real_ip: Option<IpAddr>,
    #[allow(dead_code)] // read by the body-carrying request types (Task 4)
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
}

/// Header and body stages in sequence, as the glue runs them around its body read.
#[cfg(test)]
pub async fn handle<A: Authenticator>(srv: &Server<A>, req: MapiRequest<'_>) -> MapiReply {
    let declared = u64::try_from(req.body.len()).ok();
    match check_headers(srv, &req, declared).await {
        Ok(()) => handle_body(&req),
        Err(rep) => rep,
    }
}

/// Everything decided before the body is read, in one fixed order (codes of 2.2.3.3.3).
/// `declared_len` is the Content-Length; the glue still caps chunked bodies itself.
pub async fn check_headers<A: Authenticator>(
    srv: &Server<A>,
    req: &MapiRequest<'_>,
    declared_len: Option<u64>,
) -> Result<(), MapiReply> {
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
    // Only PING so far; the other request types arrive with their endpoints.
    if request_type != "PING" {
        return Err(reply(req, 200, 5));
    }
    // Bearer and other schemes are challenged without reaching the authenticator.
    let BasicCredentials::Basic { user, password } = parse_authorization(req.authorization) else {
        return Err(reply(req, 401, 0));
    };
    if declared_len.is_some_and(|n| n > MAX_BODY as u64) {
        return Err(reply(req, 200, 9));
    }
    match srv.auth.authenticate(&user, &password, req.real_ip).await {
        AuthResult::Ok { .. } => Ok(()),
        AuthResult::BadCredentials => Err(reply(req, 401, 0)),
        AuthResult::TempFail => Err(reply(req, 503, 0)),
    }
}

/// Runs a request that passed `check_headers`, with its body read.
pub fn handle_body(req: &MapiRequest<'_>) -> MapiReply {
    match req.request_type {
        Some("PING") => reply(req, 200, 0),
        _ => reply(req, 200, 5),
    }
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
    use crate::auth::Password;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Accepts only `user:pass`, counts calls and records the last `rip`.
    #[derive(Default)]
    pub struct FakeAuth {
        pub calls: AtomicUsize,
        pub rip: Mutex<Option<IpAddr>>,
    }

    impl Authenticator for FakeAuth {
        async fn authenticate(&self, user: &str, pw: &Password, rip: Option<IpAddr>) -> AuthResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.rip.lock().unwrap() = rip;
            if user == "user" && pw.expose() == "pass" {
                AuthResult::Ok {
                    user: user.to_owned(),
                }
            } else if user == "temp" {
                AuthResult::TempFail
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

    pub fn call(req: MapiRequest<'_>) -> MapiReply {
        run(handle(
            &Server {
                auth: FakeAuth::default(),
            },
            req,
        ))
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

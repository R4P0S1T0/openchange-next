//! Dovecot auth protocol client (v1.3) for checking Basic credentials.

use crate::auth::{AuthResult, Authenticator, Password};
use base64::Engine;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Whole check (connect, handshake, AUTH reply); past it the request gets 503.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest line either side may send, newline included.
const MAX_LINE: u64 = 16384;

#[derive(Debug)]
pub struct ProtocolError(String);

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(e: std::io::Error) -> Self {
        ProtocolError(e.to_string())
    }
}

fn bad(what: &str) -> ProtocolError {
    ProtocolError(what.to_owned())
}

/// Reads one LF-terminated line without the LF; EOF or an overlong line is an error.
async fn read_line<R: AsyncRead + Unpin>(rd: &mut BufReader<R>) -> Result<String, ProtocolError> {
    let mut buf = Vec::new();
    (&mut *rd)
        .take(MAX_LINE)
        .read_until(b'\n', &mut buf)
        .await?;
    if buf.last() != Some(&b'\n') {
        return Err(bad(if buf.len() as u64 >= MAX_LINE {
            "line too long"
        } else {
            "connection closed"
        }));
    }
    buf.pop();
    String::from_utf8(buf).map_err(|_| bad("line is not UTF-8"))
}

/// Undoes the \001 escapes of a TAB-separated value.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\x01' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('1') => out.push('\x01'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some('0') => out.push('\0'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// Runs one PLAIN authentication on a fresh auth-client connection.
pub async fn auth_plain<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    service: &str,
    user: &str,
    password: &Password,
    rip: Option<IpAddr>,
) -> Result<AuthResult, ProtocolError> {
    let mut io = BufReader::new(stream);
    // Dovecot >= 2.4 sends its handshake only after our VERSION.
    let hello = format!("VERSION\t1\t3\nCPID\t{}\n", std::process::id());
    io.get_mut().write_all(hello.as_bytes()).await?;

    let (mut version_ok, mut plain) = (false, false);
    loop {
        let line = read_line(&mut io).await?;
        let mut f = line.split('\t');
        match f.next() {
            Some("VERSION") => version_ok = f.next() == Some("1"),
            Some("MECH") => plain |= f.next() == Some("PLAIN"),
            Some("DONE") => break,
            _ => {}
        }
    }
    if !version_ok {
        return Err(bad("unsupported auth protocol version"));
    }
    if !plain {
        return Err(bad("PLAIN mechanism not offered"));
    }

    // A NUL would shift the PLAIN fields (authzid\0authcid\0password).
    if user.contains('\0') || password.expose().contains('\0') {
        return Ok(AuthResult::BadCredentials);
    }
    let mut ir = Vec::with_capacity(user.len() + password.expose().len() + 2);
    ir.push(0);
    ir.extend_from_slice(user.as_bytes());
    ir.push(0);
    ir.extend_from_slice(password.expose().as_bytes());
    let resp = base64::engine::general_purpose::STANDARD.encode(ir);
    let rip = rip.map(|ip| format!("rip={ip}\t")).unwrap_or_default();
    // One request per connection, so the id is always 1; resp= must come last.
    let auth = format!("AUTH\t1\tPLAIN\tservice={service}\t{rip}secured\tresp={resp}\n");
    if auth.len() as u64 > MAX_LINE {
        return Err(bad("credentials too long"));
    }
    io.get_mut().write_all(auth.as_bytes()).await?;

    let line = read_line(&mut io).await?;
    let mut f = line.split('\t');
    let (kind, id) = (f.next(), f.next());
    if id != Some("1") {
        return Err(bad("reply for an unknown request id"));
    }
    match kind {
        Some("OK") => f
            .find_map(|p| p.strip_prefix("user="))
            .map(|u| AuthResult::Ok { user: unescape(u) })
            .ok_or_else(|| bad("OK without user")),
        Some("FAIL") if f.any(|p| p == "code=temp_fail") => Ok(AuthResult::TempFail),
        Some("FAIL") => Ok(AuthResult::BadCredentials),
        _ => Err(bad("unexpected reply to AUTH")),
    }
}

/// Checks credentials against Dovecot's auth-client socket, one connection per check.
pub struct DovecotAuthenticator {
    pub socket: PathBuf,
    pub service: String,
}

impl Authenticator for DovecotAuthenticator {
    async fn authenticate(
        &self,
        user: &str,
        password: &Password,
        rip: Option<IpAddr>,
    ) -> AuthResult {
        let check = self.check(user, password, rip);
        tokio::time::timeout(AUTH_TIMEOUT, check)
            .await
            .unwrap_or_else(|_| {
                eprintln!(
                    "openchange-mapihttpd: dovecot auth: no answer within {}s",
                    AUTH_TIMEOUT.as_secs()
                );
                AuthResult::TempFail
            })
    }
}

impl DovecotAuthenticator {
    async fn check(&self, user: &str, password: &Password, rip: Option<IpAddr>) -> AuthResult {
        // Errors never carry credentials: only static texts and I/O errors.
        let stream = match UnixStream::connect(&self.socket).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "openchange-mapihttpd: dovecot auth {}: {e}",
                    self.socket.display()
                );
                return AuthResult::TempFail;
            }
        };
        match auth_plain(stream, &self.service, user, password, rip).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("openchange-mapihttpd: dovecot auth: {e}");
                AuthResult::TempFail
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::tests::{ping, run};
    use crate::request::{handle, Server};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    const HANDSHAKE: &str = "VERSION\t1\t3\nMECH\tPLAIN\tplaintext\nMECH\tLOGIN\tplaintext\n\
                             SPID\t42\nCUID\t7\nCOOKIE\t0123456789abcdef\nDONE\n";

    /// Plays a Dovecot auth server on `sock`: sends `handshake`, then (if `reply` is set)
    /// waits for the AUTH line and answers it. Returns the AUTH line received, if any.
    async fn serve(sock: UnixStream, handshake: String, reply: Option<&'static str>) -> String {
        let (rd, mut wr) = sock.into_split();
        let _ = wr.write_all(handshake.as_bytes()).await;
        let mut lines = BufReader::new(rd).lines();
        let Some(reply) = reply else {
            // Half-close and drain, so the client sees EOF rather than a reset.
            let _ = wr.shutdown().await;
            while let Ok(Some(_)) = lines.next_line().await {}
            return String::new();
        };
        while let Ok(Some(line)) = lines.next_line().await {
            if line.starts_with("AUTH\t") {
                let _ = wr.write_all(reply.as_bytes()).await;
                return line;
            }
        }
        String::new()
    }

    fn script(
        handshake: &str,
        reply: Option<&'static str>,
        user: &str,
        password: &str,
    ) -> (Result<AuthResult, ProtocolError>, String) {
        run(async {
            let (client, server) = UnixStream::pair().unwrap();
            let fake = tokio::spawn(serve(server, handshake.to_owned(), reply));
            let rip = Some("192.0.2.7".parse().unwrap());
            let res = auth_plain(client, "openchange", user, &Password::from(password), rip).await;
            (res, fake.await.unwrap())
        })
    }

    #[test]
    fn test_auth_ok() {
        let (res, auth) = script(
            HANDSHAKE,
            Some("OK\t1\tuser=alice@example.invalid\n"),
            "alice@example.invalid",
            "secret",
        );
        assert_eq!(
            res.unwrap(),
            AuthResult::Ok {
                user: "alice@example.invalid".into()
            }
        );
        assert!(
            auth.starts_with("AUTH\t1\tPLAIN\tservice=openchange\trip=192.0.2.7\tsecured\t"),
            "{auth}"
        );
        assert!(!auth.contains("no-penalty"));
        assert!(auth.ends_with("\tresp=AGFsaWNlQGV4YW1wbGUuaW52YWxpZABzZWNyZXQ="));
    }

    #[test]
    fn test_auth_ok_escaped_user() {
        let (res, _) = script(HANDSHAKE, Some("OK\t1\tuser=a\x01tb\x011\n"), "x", "y");
        assert_eq!(
            res.unwrap(),
            AuthResult::Ok {
                user: "a\tb\x01".into()
            }
        );
    }

    #[test]
    fn test_auth_fail() {
        let (res, _) = script(HANDSHAKE, Some("FAIL\t1\tuser=alice\n"), "alice", "nope");
        assert_eq!(res.unwrap(), AuthResult::BadCredentials);
    }

    #[test]
    fn test_auth_tempfail() {
        let (res, _) = script(HANDSHAKE, Some("FAIL\t1\tcode=temp_fail\n"), "alice", "x");
        assert_eq!(res.unwrap(), AuthResult::TempFail);

        // Same reply through the real DovecotAuthenticator and the request handler.
        let path = std::env::temp_dir().join(format!("mapihttpd-t3-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let status = run(async {
            let listener = UnixListener::bind(&path).unwrap();
            let fake = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.unwrap();
                serve(
                    sock,
                    HANDSHAKE.to_owned(),
                    Some("FAIL\t1\tcode=temp_fail\n"),
                )
                .await
            });
            let srv = Server {
                auth: DovecotAuthenticator {
                    socket: path.clone(),
                    service: "openchange".into(),
                },
                sessions: crate::session::SessionTable::new(Duration::from_secs(1800)),
                autodiscover: crate::request::tests::settings(),
            };
            let rep = handle(&srv, ping("/mapi/emsmdb/")).await;
            assert!(fake.await.unwrap().starts_with("AUTH\t1\tPLAIN\t"));
            rep.http_status
        });
        let _ = std::fs::remove_file(&path);
        assert_eq!(status, 503);
    }

    #[test]
    fn test_auth_timeout() {
        let path =
            std::env::temp_dir().join(format!("mapihttpd-t3-to-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let (status, waited) = rt.block_on(async {
            let listener = UnixListener::bind(&path).unwrap();
            // Accepts and then never says anything.
            let _silent = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.unwrap();
                std::future::pending::<()>().await;
                drop(sock);
            });
            let srv = Server {
                auth: DovecotAuthenticator {
                    socket: path.clone(),
                    service: "openchange".into(),
                },
                sessions: crate::session::SessionTable::new(Duration::from_secs(1800)),
                autodiscover: crate::request::tests::settings(),
            };
            let t0 = tokio::time::Instant::now();
            let rep = handle(&srv, ping("/mapi/emsmdb/")).await;
            (rep.http_status, t0.elapsed())
        });
        let _ = std::fs::remove_file(&path);
        assert_eq!(status, 503);
        assert!(waited >= AUTH_TIMEOUT, "{waited:?}");
    }

    #[test]
    fn test_connect_failure_is_tempfail() {
        let srv = Server {
            auth: DovecotAuthenticator {
                socket: "/nonexistent/mapihttpd-auth".into(),
                service: "openchange".into(),
            },
            sessions: crate::session::SessionTable::new(Duration::from_secs(1800)),
            autodiscover: crate::request::tests::settings(),
        };
        let rep = run(handle(&srv, ping("/mapi/emsmdb/")));
        assert_eq!(rep.http_status, 503);
    }

    #[test]
    fn test_major_mismatch() {
        let hs = HANDSHAKE.replace("VERSION\t1\t3", "VERSION\t2\t0");
        let (res, auth) = script(&hs, Some("OK\t1\tuser=alice\n"), "alice", "secret");
        assert!(res.unwrap_err().0.contains("version"));
        assert_eq!(auth, "");
    }

    #[test]
    fn test_no_plain() {
        let hs = HANDSHAKE.replace("MECH\tPLAIN\tplaintext\n", "");
        let (res, auth) = script(&hs, Some("OK\t1\tuser=alice\n"), "alice", "secret");
        assert!(res.unwrap_err().0.contains("PLAIN"));
        assert_eq!(auth, "");
    }

    #[test]
    fn test_tab_in_password() {
        let (res, auth) = script(HANDSHAKE, Some("FAIL\t1\n"), "alice", "pa\tss\nword");
        assert_eq!(res.unwrap(), AuthResult::BadCredentials);
        // base64("\0alice\0pa\tss\nword")
        assert!(auth.ends_with("\tresp=AGFsaWNlAHBhCXNzCndvcmQ="), "{auth}");
        assert!(!auth.contains("pa\tss"));
    }

    #[test]
    fn test_nul_rejected() {
        let (res, auth) = script(HANDSHAKE, Some("OK\t1\tuser=bob\n"), "alice\0bob", "x");
        assert_eq!(res.unwrap(), AuthResult::BadCredentials);
        assert_eq!(auth, "");
    }

    #[test]
    fn test_truncated_reply() {
        let (res, _) = script("VERSION\t1\t3\nMECH\tPLA", None, "alice", "secret");
        assert_eq!(res.unwrap_err().0, "connection closed");
        let (res, _) = script(HANDSHAKE, Some("OK\t1\tuser=al"), "alice", "secret");
        assert_eq!(res.unwrap_err().0, "connection closed");
    }

    #[test]
    fn test_overlong_line() {
        let hs = format!("VERSION\t1\t3\nCOOKIE\t{}\n{HANDSHAKE}", "a".repeat(16385));
        let (res, _) = script(&hs, Some("OK\t1\tuser=alice\n"), "alice", "secret");
        assert_eq!(res.unwrap_err().0, "line too long");
    }

    #[test]
    fn test_wrong_id_or_reply() {
        let (res, _) = script(HANDSHAKE, Some("OK\t2\tuser=alice\n"), "alice", "secret");
        assert!(res.unwrap_err().0.contains("request id"));
        let (res, _) = script(HANDSHAKE, Some("CONT\t1\t\n"), "alice", "secret");
        assert!(res.unwrap_err().0.contains("unexpected"));
    }
}

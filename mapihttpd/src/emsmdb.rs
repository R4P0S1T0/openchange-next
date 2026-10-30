//! Mailbox endpoint request bodies (MS-OXCMAPIHTTP 2.2.4): codecs and handlers.
//! Little-endian, no alignment; every read is bounds-checked and fails with code 12.

use crate::auth::Authenticator;
use crate::backend::{Backend, ConnectParams, EC_RPC_FAILED};
use crate::request::{reply, MapiReply, MapiRequest, Server};
use crate::session::SessionGuard;
use std::time::Instant;

/// X-ResponseCode "Invalid Request Body" (2.2.3.3.3).
const BAD_BODY: u32 = 12;
/// pcmsPollsMax, pcRetry, pcmsRetryDelay of the RPC path (dcesrv_exchange_emsmdb.h).
const POLLS_MAX: u32 = 60_000;
const RETRY_COUNT: u32 = 6;
const RETRY_DELAY: u32 = 10_000;
/// MaxRopOut range the RPC path accepts (emsmdb_execute_buffer).
const MAX_ROP_OUT: std::ops::RangeInclusive<u32> = 8..=0x40000;
/// AuxiliaryBuffer of failure bodies: an RPC_HEADER_EXT (MS-OXCRPC 2.2.2.1) with Version 0,
/// Flags Last, Size and SizeActual 0, as 2.2.4.1.3 note <2> has current servers send.
const FAILURE_AUX: [u8; 8] = [0, 0, 4, 0, 0, 0, 0, 0];

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], u32> {
        if n > self.0.len() {
            return Err(BAD_BODY);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, u32> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A size field followed by that many bytes.
    fn sized(&mut self) -> Result<&'a [u8], u32> {
        let n = self.u32()?;
        self.take(usize::try_from(n).map_err(|_| BAD_BODY)?)
    }

    /// A NUL-terminated ASCII string.
    fn ascii_z(&mut self) -> Result<String, u32> {
        let len = self.0.iter().position(|&b| b == 0).ok_or(BAD_BODY)?;
        let s = self.take(len)?;
        self.take(1)?;
        if !s.is_ascii() {
            return Err(BAD_BODY);
        }
        String::from_utf8(s.to_vec()).map_err(|_| BAD_BODY)
    }

    /// AuxiliaryBufferSize and AuxiliaryBuffer: walked for well-formedness, then dropped.
    fn aux(&mut self) -> Result<Vec<u16>, u32> {
        walk_aux(self.sized()?)
    }
}

/// An RPC_HEADER_EXT and its AUX_HEADER blocks (MS-OXCRPC 2.2.2.1, 3.1.4.1.2); returns
/// the block sizes. Blocks are opaque: types outside exchange.idl are common (README).
fn walk_aux(buf: &[u8]) -> Result<Vec<u16>, u32> {
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    let mut r = Reader(buf);
    let (_version, flags, size, _size_actual) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    let payload = r.take(size.into())?;
    // Compressed: nothing to walk without decompressing, and the content is dropped anyway.
    if flags & 0x0001 != 0 {
        return Ok(Vec::new());
    }
    let key = if flags & 0x0002 != 0 { 0xA5 } else { 0 };
    let payload: Vec<u8> = payload.iter().map(|b| b ^ key).collect();
    let mut r = Reader(&payload);
    let mut sizes = Vec::new();
    while !r.0.is_empty() {
        // AUX_HEADER.Size counts the 4-byte header itself.
        let size = r.u16()?;
        if size < 4 {
            return Err(BAD_BODY);
        }
        r.take(usize::from(size) - 2)?;
        sizes.push(size);
    }
    Ok(sizes)
}

/// Connect request body (2.2.4.1.1) and its auxiliary block sizes.
fn parse_connect(body: &[u8], username: String) -> Result<(ConnectParams, Vec<u16>), u32> {
    let mut r = Reader(body);
    let user_dn = r.ascii_z()?;
    let params = ConnectParams {
        username,
        user_dn,
        flags: r.u32()?,
        code_page: r.u32()?,
        lcid_sort: r.u32()?,
        lcid_string: r.u32()?,
    };
    Ok((params, r.aux()?))
}

fn put(out: &mut Vec<u8>, words: &[u32]) {
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
}

/// Failure body shared by the mailbox request types (2.2.4.x.3).
fn failure_body(status: u32) -> Vec<u8> {
    let mut out = Vec::new();
    put(&mut out, &[status, FAILURE_AUX.len() as u32]);
    out.extend_from_slice(&FAILURE_AUX);
    out
}

fn with_body(req: &MapiRequest<'_>, body: Vec<u8>) -> MapiReply {
    let mut rep = reply(req, 200, 0);
    rep.body = body;
    rep
}

/// Connect (3.2.5.1): `user` is the authenticator's canonical name (decision 4).
pub async fn connect<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    user: String,
    cred_hash: [u8; 32],
) -> MapiReply {
    let params = match parse_connect(req.body, user) {
        Ok((params, _aux)) => params,
        Err(code) => return reply(req, 200, code),
    };
    // shortcut: a reconnect's previous Session Context (3.2.5.6) is left to the idle sweeper, destroy it here if sessions pile up.
    let c = match srv.backend.connect(params).await {
        Ok(c) => c,
        Err(status) => return with_body(req, failure_body(status)),
    };
    let mut body = Vec::new();
    put(&mut body, &[0, 0, POLLS_MAX, RETRY_COUNT, RETRY_DELAY]);
    // The backend's DN prefix comes from the directory; keep the field ASCII as 2.2.4.1.2 says.
    body.extend(c.dn_prefix.bytes().filter(|&b| b != 0 && b.is_ascii()));
    body.push(0);
    for unit in c.display_name.encode_utf16().filter(|&u| u != 0) {
        body.extend_from_slice(&unit.to_le_bytes());
    }
    body.extend_from_slice(&[0, 0]); // UTF-16 NUL
    put(&mut body, &[0]); // AuxiliaryBufferSize
    let mut rep = with_body(req, body);
    rep.set_cookie = Some(srv.sessions.create(cred_hash, c.id, Instant::now()));
    rep.expiration_ms = srv.sessions.idle_ms();
    rep
}

/// Execute (2.2.4.2): the RopBuffer goes to EMSMDB unchanged and comes back unchanged.
pub async fn execute<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    session: &SessionGuard<'_>,
) -> MapiReply {
    let parsed = (|| {
        let mut r = Reader(req.body);
        let flags = r.u32()?;
        let rop_in = r.sized()?;
        let max_out = r.u32()?;
        r.aux()?;
        Ok::<_, u32>((flags, rop_in, max_out))
    })();
    let (flags, rop_in, max_out) = match parsed {
        Ok(p) => p,
        Err(code) => return reply(req, 200, code),
    };
    let result = if MAX_ROP_OUT.contains(&max_out) {
        let max_out = usize::try_from(max_out).unwrap_or(usize::MAX);
        let id = session.backend();
        srv.backend
            .execute(id, flags, rop_in.to_vec(), max_out)
            .await
    } else {
        Err(EC_RPC_FAILED)
    };
    let (error, rop_out) = match result {
        Ok(out) => (0, out),
        Err(e) => (e, Vec::new()),
    };
    let mut body = Vec::new();
    // Execute replies are at most 0x40000 bytes (MAX_ROP_OUT), so the length fits.
    put(&mut body, &[0, error, 0, rop_out.len() as u32]);
    body.extend_from_slice(&rop_out);
    put(&mut body, &[0]);
    with_body(req, body)
}

/// Disconnect (3.2.5.4): ends the Session Context and its backend session.
pub async fn disconnect<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    session: SessionGuard<'_>,
) -> MapiReply {
    if let Err(code) = Reader(req.body).aux() {
        return reply(req, 200, code);
    }
    if let Some(id) = session.remove() {
        srv.backend.disconnect(id).await;
    }
    let mut body = Vec::new();
    put(&mut body, &[0, 0, 0]);
    with_body(req, body)
}

/// NotificationWait (3.2.5.5): no event source exists yet, so it always times out.
pub async fn notification_wait<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    session: &SessionGuard<'_>,
) -> MapiReply {
    let mut r = Reader(req.body);
    if let Err(code) = r.u32().and_then(|_flags| r.aux()) {
        return reply(req, 200, code);
    }
    tokio::time::sleep(srv.notification_wait).await;
    session.refresh(Instant::now());
    let mut body = Vec::new();
    put(&mut body, &[0, 0, 0, 0]); // StatusCode, ErrorCode, EventPending 0, AuxiliaryBufferSize
    with_body(req, body)
}

/// Drops idle Session Contexts and their backend sessions.
pub async fn sweep<A: Authenticator, B: Backend>(srv: &Server<A, B>, now: Instant) {
    for id in srv.sessions.expire(now) {
        srv.backend.disconnect(id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Call, Connected, MAPI_E_LOGON_FAILED};
    use crate::request::tests::{
        connect as new_session, ping, run, server, TestServer, CLIENT_INFO,
    };
    use crate::request::{format_reply, handle};
    use std::time::Duration;

    const CAPTURE: &str = "connect-m365-16.0.19127.20800.bin";

    fn fixture(name: &str) -> Vec<u8> {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testsuite/modernization/mapihttp/"
        );
        std::fs::read(format!("{dir}{name}")).unwrap()
    }

    fn post<'a>(t: &'a str, body: &'a [u8], cookie: Option<&'a str>) -> MapiRequest<'a> {
        MapiRequest {
            request_type: Some(t),
            body,
            cookie,
            ..ping("/mapi/emsmdb/")
        }
    }

    fn words(w: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, w);
        out
    }

    fn calls(srv: &TestServer) -> Vec<Call> {
        srv.backend.calls.lock().unwrap().clone()
    }

    fn cookie_of(set_cookie: &str) -> &str {
        set_cookie.split(';').next().unwrap()
    }

    fn connect_body(user_dn: &str, lcid: u32) -> Vec<u8> {
        let mut b = user_dn.as_bytes().to_vec();
        b.push(0);
        put(&mut b, &[0, 1252, lcid, lcid, 0]);
        b
    }

    fn is_failure_body(body: &[u8]) -> bool {
        body.len() == 16 && body[..4] != [0; 4] && body[4..] == words(&[8, 0x0004_0000, 0])[..]
    }

    #[test]
    fn test_connect_real_capture() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testsuite/modernization/mapihttp/"
        );
        let mut seen = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if name.starts_with("connect-") && name.ends_with(".bin") {
                assert!(parse_connect(&fixture(&name), "u".into()).is_ok(), "{name}");
                seen += 1;
            }
        }
        assert!(seen >= 1);

        let body = fixture(CAPTURE);
        let (p, aux) = parse_connect(&body, "user".into()).unwrap();
        let dn = "/o=Lab/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=spike";
        assert_eq!(p.user_dn, dn);
        assert_eq!((p.flags, p.code_page), (0, 1252));
        assert_eq!((p.lcid_sort, p.lcid_string), (0x0416, 0x0416));
        assert_eq!(body[97..101], 202u32.to_le_bytes());
        assert_eq!(body.len() - 101, 202);
        assert_eq!(aux, [50, 24, 28, 52, 32, 8]);

        // The fake fails like the SamDB-less C backend.
        let srv = server();
        let rep = run(handle(&srv, post("Connect", &body, None)));
        assert_eq!((rep.http_status, rep.response_code), (200, 0));
        assert_eq!(rep.client_info.as_deref(), Some(CLIENT_INFO));
        assert_eq!(rep.body[..4], MAPI_E_LOGON_FAILED.to_le_bytes());
        assert!(is_failure_body(&rep.body));
        assert!(rep.set_cookie.is_none());
        assert_eq!(calls(&srv), [Call::Connect(p)]);
    }

    #[test]
    fn test_connect_capture_truncated() {
        let body = fixture(CAPTURE);
        for n in 0..=302 {
            let srv = server();
            let rep = run(handle(&srv, post("Connect", &body[..n], None)));
            let ok = rep.response_code == 12 || is_failure_body(&rep.body);
            assert!(ok && rep.http_status == 200, "length {n}");
        }
    }

    #[test]
    fn test_bind_real_capture() {
        let body = fixture("nspi-bind-m365-16.0.19127.20800.bin");
        let req = MapiRequest {
            path: "/mapi/nspi/",
            ..post("Bind", &body, None)
        };
        let rep = run(handle(&server(), req));
        assert_eq!((rep.http_status, rep.response_code), (200, 5));
        assert_eq!(rep.request_type.as_deref(), Some("Bind"));
        let out = format_reply(&rep, 1, "Thu, 30 Oct 2026 11:30:11 GMT");
        assert!(out.starts_with(b"PROCESSING\r\nDONE\r\nX-ResponseCode: 5\r\n"));
        assert!(out.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn test_connect_body() {
        let srv = server();
        let connected = Connected {
            id: 7,
            display_name: "Alice Ünal".into(),
            dn_prefix: "/o=example/ou=first".into(),
        };
        srv.backend
            .connects
            .lock()
            .unwrap()
            .push_back(Ok(connected));
        let user_dn = "/o=example/ou=first/cn=Recipients/cn=alice";
        let body = connect_body(user_dn, 0x409);
        let rep = run(handle(&srv, post("Connect", &body, None)));
        assert_eq!((rep.http_status, rep.response_code), (200, 0));
        let expected = ConnectParams {
            username: "user".into(),
            user_dn: user_dn.into(),
            flags: 0,
            code_page: 1252,
            lcid_sort: 0x409,
            lcid_string: 0x409,
        };
        assert_eq!(calls(&srv), [Call::Connect(expected)]);

        let mut r = Reader(&rep.body);
        let head: Vec<u32> = (0..5).map(|_| r.u32().unwrap()).collect();
        assert_eq!(head, [0, 0, POLLS_MAX, RETRY_COUNT, RETRY_DELAY]);
        assert_eq!(r.ascii_z().unwrap(), "/o=example/ou=first");
        let mut name = Vec::new();
        loop {
            match r.u16().unwrap() {
                0 => break,
                u => name.push(u),
            }
        }
        assert_eq!(String::from_utf16(&name).unwrap(), "Alice Ünal");
        assert_eq!(r.u32(), Ok(0));
        assert!(r.0.is_empty());

        // The new session maps to backend session 7.
        let sc = rep.set_cookie.unwrap();
        assert_eq!(rep.expiration_ms, 1_800_000);
        let exec = words(&[0, 8, 0, 0, 0x8000, 0]);
        run(handle(&srv, post("Execute", &exec, Some(cookie_of(&sc)))));
        assert!(matches!(calls(&srv)[1], Call::Execute { id: 7, .. }));
    }

    #[test]
    fn test_connect_bad_credentials_no_backend() {
        let srv = server();
        let body = connect_body("/o=example/cn=alice", 0x409);
        let req = MapiRequest {
            authorization: Some("Basic dXNlcjpub3Bl"), // user:nope
            ..post("Connect", &body, None)
        };
        assert_eq!(run(handle(&srv, req)).http_status, 401);
        assert!(calls(&srv).is_empty());
    }

    #[test]
    fn test_execute_roundtrip() {
        let srv = server();
        let sc = new_session(&srv, Instant::now());
        srv.backend
            .executes
            .lock()
            .unwrap()
            .push_back(Ok(vec![9, 8, 7]));
        let rop: Vec<u8> = (1..=10).collect();
        let mut body = words(&[0x2, 10]);
        body.extend_from_slice(&rop);
        put(&mut body, &[0x8000, 0]);
        let rep = run(handle(&srv, post("Execute", &body, Some(cookie_of(&sc)))));
        assert_eq!((rep.http_status, rep.response_code), (200, 0));
        let exec = Call::Execute {
            id: 1,
            flags: 2,
            rop_in: rop,
            max_out: 0x8000,
        };
        assert_eq!(calls(&srv), [exec]);
        let mut want = words(&[0, 0, 0, 3]);
        want.extend_from_slice(&[9, 8, 7]);
        put(&mut want, &[0]);
        assert_eq!(rep.body, want);
        assert_eq!(rep.set_cookie.as_deref(), Some(sc.as_str()));
    }

    #[test]
    fn test_execute_truncated() {
        let srv = server();
        let sc = new_session(&srv, Instant::now());
        let mut body = words(&[0, 100]);
        body.extend_from_slice(&[0; 20]);
        let rep = run(handle(&srv, post("Execute", &body, Some(cookie_of(&sc)))));
        assert_eq!((rep.http_status, rep.response_code), (200, 12));
        assert!(calls(&srv).is_empty());
    }

    #[test]
    fn test_execute_maxropout_too_big() {
        let srv = server();
        let sc = new_session(&srv, Instant::now());
        let body = words(&[0, 8, 0, 0, 0x40001, 0]);
        let rep = run(handle(&srv, post("Execute", &body, Some(cookie_of(&sc)))));
        assert_eq!(rep.response_code, 0);
        assert_eq!(rep.body, words(&[0, EC_RPC_FAILED, 0, 0, 0]));
        assert!(calls(&srv).is_empty());
    }

    #[test]
    fn test_execute_backend_error() {
        let srv = server();
        let sc = new_session(&srv, Instant::now());
        let body = words(&[0, 8, 0, 0, 0x8000, 0]);
        let rep = run(handle(&srv, post("Execute", &body, Some(cookie_of(&sc)))));
        // The fake's empty queue fails with ecRpcFailed.
        assert_eq!(rep.body, words(&[0, EC_RPC_FAILED, 0, 0, 0]));
    }

    #[test]
    fn test_notification_wait_timeout() {
        let mut srv = server();
        srv.notification_wait = Duration::from_secs(1);
        let then = Instant::now() - Duration::from_secs(10);
        let sc = new_session(&srv, then);
        let value = &cookie_of(&sc)["MapiContext=".len()..];
        let body = words(&[0, 0]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let (rep, waited) = rt.block_on(async {
            let t0 = tokio::time::Instant::now();
            let rep = handle(&srv, post("NotificationWait", &body, Some(cookie_of(&sc)))).await;
            (rep, t0.elapsed())
        });
        assert!(waited >= Duration::from_secs(1));
        assert_eq!((rep.http_status, rep.response_code), (200, 0));
        assert_eq!(rep.body, words(&[0, 0, 0, 0]));
        assert!(srv.sessions.last_used(value).unwrap() > then);
        assert_eq!(rep.expiration_ms, 1_800_000);
    }

    #[test]
    fn test_disconnect_calls_backend() {
        let srv = server();
        let sc = new_session(&srv, Instant::now());
        let body = words(&[0]);
        let rep = run(handle(
            &srv,
            post("Disconnect", &body, Some(cookie_of(&sc))),
        ));
        assert_eq!((rep.http_status, rep.response_code), (200, 0));
        assert_eq!(rep.body, words(&[0, 0, 0]));
        assert_eq!(rep.set_cookie.as_deref(), Some(sc.as_str()));
        assert_eq!(calls(&srv), [Call::Disconnect(1)]);
        for t in ["Execute", "Disconnect"] {
            let rep = run(handle(&srv, post(t, &body, Some(cookie_of(&sc)))));
            assert_eq!(rep.response_code, 10, "{t}");
        }
        assert_eq!(calls(&srv).len(), 1);
    }

    #[test]
    fn test_disconnect_bad_body_keeps_session() {
        let srv = server();
        let sc = new_session(&srv, Instant::now());
        let rep = run(handle(
            &srv,
            post("Disconnect", &[1, 0], Some(cookie_of(&sc))),
        ));
        assert_eq!(rep.response_code, 12);
        assert!(calls(&srv).is_empty());
        let body = words(&[0]);
        let rep = run(handle(
            &srv,
            post("Disconnect", &body, Some(cookie_of(&sc))),
        ));
        assert_eq!(rep.response_code, 0);
    }

    #[test]
    fn test_sweep_disconnects_expired() {
        let srv = server();
        let now = Instant::now();
        new_session(&srv, now - Duration::from_secs(1801));
        run(sweep(&srv, now));
        assert_eq!(calls(&srv), [Call::Disconnect(1)]);
        run(sweep(&srv, now));
        assert_eq!(calls(&srv).len(), 1);
    }

    #[test]
    fn test_aux_walk() {
        let capture = fixture(CAPTURE);
        let aux = &capture[101..];
        // Obfuscated (XOR 0xA5, MS-OXCRPC 3.1.7.2) walks the same blocks.
        let mut obf = aux.to_vec();
        obf[2] |= 0x02;
        obf[8..].iter_mut().for_each(|b| *b ^= 0xA5);
        assert_eq!(walk_aux(&obf), Ok(vec![50, 24, 28, 52, 32, 8]));
        // Size beyond the buffer; a block shorter than its header; a header cut short.
        let mut long = aux.to_vec();
        long[4] = 0xFF;
        assert_eq!(walk_aux(&long), Err(BAD_BODY));
        assert_eq!(
            walk_aux(&[0, 0, 4, 0, 4, 0, 4, 0, 2, 0, 1, 1]),
            Err(BAD_BODY)
        );
        assert_eq!(walk_aux(&[0, 0, 4]), Err(BAD_BODY));
        assert_eq!(walk_aux(&FAILURE_AUX), Ok(vec![]));
    }
}

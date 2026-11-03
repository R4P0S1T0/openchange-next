//! Address book endpoint request bodies (MS-OXCMAPIHTTP 2.2.5), served from the directory
//! snapshot. Little-endian, no alignment; every read is bounds-checked and fails with code 12.

pub mod gal;

use crate::auth::Authenticator;
use crate::backend::Backend;
use crate::emsmdb::{put, with_body, Reader};
use crate::request::{reply, MapiReply, MapiRequest, Server};
use crate::session::{SessionGuard, SessionTable};
use std::time::{Duration, Instant};

pub const PATH: &str = "/mapi/nspi/";

/// Request types bound to an NSPI Session Context (everything but Bind and PING).
pub const SESSION_TYPES: &[&str] = &["Unbind"];

pub struct State {
    pub sessions: SessionTable,
    pub gal: gal::Gal,
    server_guid: [u8; 16],
}

impl State {
    pub fn new(idle: Duration, gal: gal::Gal) -> Self {
        let mut server_guid = [0u8; 16];
        getrandom::getrandom(&mut server_guid).expect("getrandom failed");
        State {
            sessions: SessionTable::for_path(idle, PATH),
            gal,
            server_guid,
        }
    }
}

/// STAT (MS-OXNSPI 2.2.8): the client's position in an address book table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub sort_type: u32,
    pub container_id: u32,
    pub current_rec: u32,
    pub delta: i32,
    pub num_pos: u32,
    pub total_recs: u32,
    pub code_page: u32,
    pub template_locale: u32,
    pub sort_locale: u32,
}

impl Stat {
    fn read(r: &mut Reader<'_>) -> Result<Self, u32> {
        Ok(Stat {
            sort_type: r.u32()?,
            container_id: r.u32()?,
            current_rec: r.u32()?,
            delta: r.u32()? as i32,
            num_pos: r.u32()?,
            total_recs: r.u32()?,
            code_page: r.u32()?,
            template_locale: r.u32()?,
            sort_locale: r.u32()?,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))] // replies carry a STAT from QueryRows on (Task 3)
    pub fn write(&self, out: &mut Vec<u8>) {
        let s = self;
        put(
            out,
            &[
                s.sort_type,
                s.container_id,
                s.current_rec,
                s.delta as u32,
                s.num_pos,
            ],
        );
        put(
            out,
            &[s.total_recs, s.code_page, s.template_locale, s.sort_locale],
        );
    }
}

/// A HasState byte, then a STAT when it is nonzero.
pub fn read_opt_stat(r: &mut Reader<'_>) -> Result<Option<Stat>, u32> {
    if r.u8()? == 0 {
        return Ok(None);
    }
    Stat::read(r).map(Some)
}

/// Bind (2.2.5.1): any authenticated user may read the address book.
pub async fn bind<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    cred_hash: [u8; 32],
) -> MapiReply {
    let mut r = Reader(req.body);
    let parsed = r
        .u32()
        .and_then(|_flags| read_opt_stat(&mut r))
        .and_then(|_| r.aux());
    if let Err(code) = parsed {
        return reply(req, 200, code);
    }
    let mut body = Vec::new();
    put(&mut body, &[0, 0]); // StatusCode, ErrorCode
    body.extend_from_slice(&srv.nspi.server_guid);
    put(&mut body, &[0]); // AuxiliaryBufferSize
    let mut rep = with_body(req, body);
    rep.set_cookie = Some(srv.nspi.sessions.create(cred_hash, 0, Instant::now()));
    rep.expiration_ms = srv.nspi.sessions.idle_ms();
    rep
}

/// Unbind (2.2.5.2): ends the Session Context.
pub fn unbind(req: &MapiRequest<'_>, session: SessionGuard<'_>) -> MapiReply {
    let mut r = Reader(req.body);
    if let Err(code) = r.u32().and_then(|_reserved| r.aux()) {
        return reply(req, 200, code);
    }
    session.remove();
    let mut body = Vec::new();
    // ErrorCode 1: NspiUnbind's UNBIND_SUCCESS (MS-OXNSPI 3.1.4.1.2).
    put(&mut body, &[0, 1, 0]);
    with_body(req, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::tests::{ping, run, server};
    use crate::request::{handle, MapiRequest};
    use crate::session::tests::cookie_of;
    use std::time::Instant;

    pub fn nspi<'a>(t: &'a str, body: &'a [u8], cookie: Option<&'a str>) -> MapiRequest<'a> {
        MapiRequest {
            request_type: Some(t),
            body,
            cookie,
            ..ping(PATH)
        }
    }

    pub fn bind_capture() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testsuite/modernization/mapihttp/nspi-bind-m365-16.0.19127.20800.bin"
        );
        std::fs::read(path).unwrap()
    }

    /// Unbind request body: Reserved, AuxiliaryBufferSize 0.
    const UNBIND: [u8; 8] = [0; 8];

    #[test]
    fn test_bind_real_capture() {
        let srv = server();
        let rep = run(handle(&srv, nspi("Bind", &bind_capture(), None)));
        assert_eq!((rep.http_status, rep.response_code), (200, 0));
        assert_eq!(rep.body.len(), 4 + 4 + 16 + 4);
        assert_eq!(&rep.body[..8], &[0; 8], "StatusCode and ErrorCode");
        assert_ne!(&rep.body[8..24], &[0; 16], "ServerGuid");
        assert_eq!(&rep.body[24..], &[0; 4], "AuxiliaryBufferSize");
        let sc = rep.set_cookie.expect("Bind creates a Session Context");
        assert!(sc.ends_with("; Path=/mapi/nspi/; Secure; HttpOnly"), "{sc}");
    }

    #[test]
    fn test_bind_truncated() {
        let body = bind_capture();
        for n in 0..body.len() {
            let rep = run(handle(&server(), nspi("Bind", &body[..n], None)));
            assert_eq!(
                (rep.http_status, rep.response_code),
                (200, 12),
                "length {n}"
            );
            assert!(rep.set_cookie.is_none());
        }
    }

    #[test]
    fn test_unbind_ends_session() {
        let srv = server();
        let sc = run(handle(&srv, nspi("Bind", &bind_capture(), None)))
            .set_cookie
            .unwrap();
        let rep = run(handle(&srv, nspi("Unbind", &UNBIND, Some(cookie_of(&sc)))));
        assert_eq!((rep.http_status, rep.response_code), (200, 0));
        assert_eq!(rep.body, [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        let again = run(handle(&srv, nspi("Unbind", &UNBIND, Some(cookie_of(&sc)))));
        assert_eq!(again.response_code, 10);
    }

    #[test]
    fn test_nspi_cookie_not_emsmdb() {
        let srv = server();
        let nspi_sc = run(handle(&srv, nspi("Bind", &bind_capture(), None)))
            .set_cookie
            .unwrap();
        let execute = MapiRequest {
            request_type: Some("Execute"),
            cookie: Some(cookie_of(&nspi_sc)),
            ..ping("/mapi/emsmdb/")
        };
        assert_eq!(run(handle(&srv, execute)).response_code, 10);
        let emsmdb_sc = crate::request::tests::connect(&srv, Instant::now());
        let unbind = nspi("Unbind", &UNBIND, Some(cookie_of(&emsmdb_sc)));
        assert_eq!(run(handle(&srv, unbind)).response_code, 10);
    }

    #[test]
    fn test_stat_roundtrip() {
        let body = bind_capture();
        let mut r = Reader(&body[4..]);
        let stat = read_opt_stat(&mut r).unwrap().unwrap();
        assert_eq!(
            (stat.code_page, stat.template_locale, stat.sort_locale),
            (1252, 0x416, 0x416)
        );
        let mut out = Vec::new();
        stat.write(&mut out);
        assert_eq!(out, &body[5..41]);
        assert_eq!(read_opt_stat(&mut Reader(&[0])).unwrap(), None);
    }
}

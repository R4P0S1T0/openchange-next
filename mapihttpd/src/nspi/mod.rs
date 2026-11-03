//! Address book endpoint request bodies (MS-OXCMAPIHTTP 2.2.5), served from the directory
//! snapshot. Little-endian, no alignment; every read is bounds-checked and fails with code 12.

pub mod gal;
pub mod props;

use crate::auth::Authenticator;
use crate::backend::Backend;
use crate::emsmdb::{put, with_body, Reader, BAD_BODY};
use crate::request::{reply, MapiReply, MapiRequest, Server};
use crate::session::{SessionGuard, SessionTable};
use std::time::{Duration, Instant};

pub const PATH: &str = "/mapi/nspi/";

/// Request types bound to an NSPI Session Context (everything but Bind and PING).
pub const SESSION_TYPES: &[&str] = &[
    "Unbind",
    "GetSpecialTable",
    "DNToMId",
    "QueryRows",
    "GetProps",
    "QueryColumns",
    "UpdateStat",
    "ResolveNames",
    "GetMatches",
    "SeekEntries",
];

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

/// MinimalEntryIDs with table-position meaning (MS-OXNSPI 2.2.1.8).
const MID_BEGINNING_OF_TABLE: u32 = 0;
const MID_END_OF_TABLE: u32 = 2;
/// ecWarnWithErrors: some requested properties are missing (MS-OXNSPI 2.2.1.2).
const EC_WARN_WITH_ERRORS: u32 = 0x0004_0380;
/// NspiUnicodeStrings (MS-OXNSPI 2.2.1.3).
const NSPI_UNICODE_STRINGS: u32 = 0x4;
/// LargePropertyTagArray limit (2.2.1.8).
const MAX_TAGS: u32 = 100_000;
const MAPI_E_TOO_COMPLEX: u32 = 0x8004_0117;

/// `count` items of `size` bytes each must fit in what is left: no allocation from a claimed count.
fn check_count(r: &Reader<'_>, count: u32, size: usize) -> Result<usize, u32> {
    let n = usize::try_from(count).map_err(|_| BAD_BODY)?;
    if n.checked_mul(size).is_none_or(|bytes| bytes > r.0.len()) {
        return Err(BAD_BODY);
    }
    Ok(n)
}

fn read_u32s(r: &mut Reader<'_>, count: u32) -> Result<Vec<u32>, u32> {
    let n = check_count(r, count, 4)?;
    (0..n).map(|_| r.u32()).collect()
}

/// A HasX byte, then a LargePropertyTagArray when it is nonzero.
fn read_opt_tags(r: &mut Reader<'_>) -> Result<Option<Vec<u32>>, u32> {
    if r.u8()? == 0 {
        return Ok(None);
    }
    let count = r.u32()?;
    if count > MAX_TAGS {
        return Err(BAD_BODY);
    }
    read_u32s(r, count).map(Some)
}

fn push_tags(out: &mut Vec<u8>, tags: &[u32]) {
    put(out, &[tags.len() as u32]);
    put(out, tags);
}

fn push_stat(out: &mut Vec<u8>, stat: &Stat) {
    out.push(0xFF);
    stat.write(out);
}

fn ok_body(req: &MapiRequest<'_>, mut body: Vec<u8>) -> MapiReply {
    put(&mut body, &[0]); // AuxiliaryBufferSize
    with_body(req, body)
}

/// The table position a STAT names, moved by its Delta and clamped to the table (MS-OXNSPI 3.1.4.5.2).
fn seek(gal: &gal::Snapshot, stat: &Stat) -> usize {
    let n = gal.entries().len();
    let start = match stat.current_rec {
        MID_BEGINNING_OF_TABLE => 0,
        MID_END_OF_TABLE => n,
        mid => gal.position(mid).unwrap_or((stat.num_pos as usize).min(n)),
    };
    let moved = i64::try_from(start).unwrap_or(i64::MAX) + i64::from(stat.delta);
    moved.clamp(0, n as i64) as usize
}

/// The STAT after positioning at row `pos`.
fn stat_at(gal: &gal::Snapshot, stat: &Stat, pos: usize) -> Stat {
    let entries = gal.entries();
    Stat {
        current_rec: entries.get(pos).map_or(MID_END_OF_TABLE, |e| e.mid),
        delta: 0,
        num_pos: pos as u32,
        total_recs: entries.len() as u32,
        ..*stat
    }
}

fn values_for(e: &gal::Entry, tags: &[u32], ctx: &props::Ctx<'_>) -> Vec<Option<props::Value>> {
    tags.iter()
        .map(|t| props::user_value(e, (t >> 16) as u16, ctx))
        .collect()
}

/// Request types bound to an NSPI session, other than Unbind.
pub fn handle<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    request_type: &str,
) -> MapiReply {
    let gal = srv.nspi.gal.current();
    let result = match request_type {
        "GetSpecialTable" => get_special_table(req.body),
        "DNToMId" => dn_to_mid(&gal, req.body),
        "QueryRows" => query_rows(&gal, req.body, &srv.nspi.server_guid),
        "GetProps" => get_props(&gal, req.body, &srv.nspi.server_guid),
        "QueryColumns" => query_columns(req.body),
        "UpdateStat" => update_stat(&gal, req.body),
        "ResolveNames" => resolve_names(&gal, req.body, &srv.nspi.server_guid),
        "GetMatches" => get_matches(&gal, req.body, &srv.nspi.server_guid),
        "SeekEntries" => seek_entries(&gal, req.body, &srv.nspi.server_guid),
        _ => Err(5),
    };
    match result {
        Ok(body) => ok_body(req, body),
        Err(code) => reply(req, 200, code),
    }
}

/// GetSpecialTable (2.2.5.8): the hierarchy table holds the GAL only (decision 3).
fn get_special_table(body: &[u8]) -> Result<Vec<u8>, u32> {
    let mut r = Reader(body);
    let flags = r.u32()?;
    let stat = read_opt_stat(&mut r)?.unwrap_or_default();
    if r.u8()? != 0 {
        r.u32()?; // the client's hierarchy table version
    }
    r.aux()?;
    let code_page = if stat.code_page == 0 {
        1252
    } else {
        stat.code_page
    };
    let mut out = Vec::new();
    put(&mut out, &[0, 0, code_page]);
    out.push(0xFF);
    put(&mut out, &[1]); // Version of our hierarchy table
    out.push(0xFF);
    // NspiAddressCreationTemplates (0x2) asks for templates instead: there are none.
    if flags & 0x2 != 0 {
        put(&mut out, &[0]);
        return Ok(out);
    }
    put(&mut out, &[1]);
    let row: Vec<_> = props::gal_row(flags & NSPI_UNICODE_STRINGS != 0)
        .into_iter()
        .map(|(t, v)| (t, Some(v)))
        .collect();
    props::push_value_list(&mut out, &row);
    Ok(out)
}

/// DNToMId (2.2.5.4): unknown DNs map to MId 0.
fn dn_to_mid(gal: &gal::Snapshot, body: &[u8]) -> Result<Vec<u8>, u32> {
    let mut r = Reader(body);
    r.u32()?;
    let mut mids = Vec::new();
    if r.u8()? != 0 {
        let count = r.u32()?;
        check_count(&r, count, 1)?;
        for _ in 0..count {
            let dn = r.ascii_z()?;
            mids.push(gal.by_legacy_dn(&dn).map_or(0, |e| e.mid));
        }
    }
    r.aux()?;
    let mut out = Vec::new();
    put(&mut out, &[0, 0]);
    out.push(0xFF);
    put(&mut out, &[mids.len() as u32]);
    put(&mut out, &mids);
    Ok(out)
}

/// QueryRows (2.2.5.12): explicit MIds, or RowCount rows from the STAT's position.
fn query_rows(gal: &gal::Snapshot, body: &[u8], server_guid: &[u8; 16]) -> Result<Vec<u8>, u32> {
    let mut r = Reader(body);
    let flags = r.u32()?;
    let stat = read_opt_stat(&mut r)?.unwrap_or_default();
    let explicit_count = r.u32()?;
    let explicit = read_u32s(&mut r, explicit_count)?;
    let row_count = r.u32()?;
    let columns = read_opt_tags(&mut r)?.unwrap_or_else(|| props::USER_TAGS.to_vec());
    r.aux()?;
    let ctx = props::Ctx { flags, server_guid };
    let (rows, new_stat): (Vec<Option<&gal::Entry>>, Stat) = if explicit.is_empty() {
        let pos = seek(gal, &stat);
        let end = pos
            .saturating_add(row_count as usize)
            .min(gal.entries().len());
        let rows = gal.entries()[pos..end].iter().map(Some).collect();
        (rows, stat_at(gal, &stat, end))
    } else {
        (explicit.iter().map(|&m| gal.by_mid(m)).collect(), stat)
    };
    let mut out = Vec::new();
    put(&mut out, &[0, 0]);
    push_stat(&mut out, &new_stat);
    out.push(0xFF);
    push_tags(&mut out, &columns);
    put(&mut out, &[rows.len() as u32]);
    for e in rows {
        let values = match e {
            Some(e) => values_for(e, &columns, &ctx),
            None => vec![None; columns.len()],
        };
        props::push_row(&mut out, &columns, &values);
    }
    Ok(out)
}

/// GetProps (2.2.5.7): the object is the STAT's CurrentRec.
fn get_props(gal: &gal::Snapshot, body: &[u8], server_guid: &[u8; 16]) -> Result<Vec<u8>, u32> {
    let mut r = Reader(body);
    let flags = r.u32()?;
    let stat = read_opt_stat(&mut r)?.unwrap_or_default();
    let tags = read_opt_tags(&mut r)?.unwrap_or_else(|| props::USER_TAGS.to_vec());
    r.aux()?;
    let mut out = Vec::new();
    let Some(e) = gal.by_mid(stat.current_rec) else {
        put(&mut out, &[0, props::MAPI_E_NOT_FOUND]);
        out.push(0);
        return Ok(out);
    };
    let ctx = props::Ctx { flags, server_guid };
    let values: Vec<_> = tags
        .iter()
        .copied()
        .zip(values_for(e, &tags, &ctx))
        .collect();
    let mut list = Vec::new();
    let complete = props::push_value_list(&mut list, &values);
    put(
        &mut out,
        &[0, if complete { 0 } else { EC_WARN_WITH_ERRORS }],
    );
    out.push(0xFF);
    out.extend(list);
    Ok(out)
}

/// A NUL-terminated UTF-16LE string; unpaired surrogates become U+FFFD.
fn utf16_z(r: &mut Reader<'_>) -> Result<String, u32> {
    let mut units = Vec::new();
    loop {
        match r.u16()? {
            0 => return Ok(String::from_utf16_lossy(&units)),
            u => units.push(u),
        }
    }
}

/// ResolveNames (2.2.5.14): one MId per name (0 unresolved, 1 ambiguous); rows for the resolved.
fn resolve_names(gal: &gal::Snapshot, body: &[u8], server_guid: &[u8; 16]) -> Result<Vec<u8>, u32> {
    let mut r = Reader(body);
    r.u32()?;
    let stat = read_opt_stat(&mut r)?.unwrap_or_default();
    let columns = read_opt_tags(&mut r)?.unwrap_or_else(|| props::USER_TAGS.to_vec());
    let mut names = Vec::new();
    if r.u8()? != 0 {
        let count = r.u32()?;
        check_count(&r, count, 2)?;
        for _ in 0..count {
            names.push(utf16_z(&mut r)?);
        }
    }
    r.aux()?;
    let mids: Vec<u32> = names
        .iter()
        .map(|n| match gal.resolve(n) {
            gal::Resolution::None => 0,
            gal::Resolution::Ambiguous => 1,
            gal::Resolution::One(mid) => mid,
        })
        .collect();
    let ctx = props::Ctx {
        flags: 0,
        server_guid,
    };
    let resolved: Vec<_> = mids.iter().filter_map(|&m| gal.by_mid(m)).collect();
    let code_page = if stat.code_page == 0 {
        1252
    } else {
        stat.code_page
    };
    let mut out = Vec::new();
    put(&mut out, &[0, 0, code_page]);
    out.push(0xFF);
    put(&mut out, &[mids.len() as u32]);
    put(&mut out, &mids);
    out.push(0xFF);
    push_tags(&mut out, &columns);
    put(&mut out, &[resolved.len() as u32]);
    for e in resolved {
        props::push_row(&mut out, &columns, &values_for(e, &columns, &ctx));
    }
    Ok(out)
}

/// GetMatches (2.2.5.5) without a filter: the CurrentRec object, as Outlook asks for a user's details. Filters (searches) answer MAPI_E_TOO_COMPLEX until their layout is captured.
fn get_matches(gal: &gal::Snapshot, body: &[u8], server_guid: &[u8; 16]) -> Result<Vec<u8>, u32> {
    let mut r = Reader(body);
    r.u32()?;
    let stat = read_opt_stat(&mut r)?.unwrap_or_default();
    if r.u8()? != 0 {
        let count = r.u32()?;
        read_u32s(&mut r, count)?;
    }
    r.u32()?; // InterfaceOptionFlags
    let has_filter = r.u8()? != 0;
    if has_filter {
        let mut out = Vec::new();
        put(&mut out, &[0, MAPI_E_TOO_COMPLEX]);
        out.extend_from_slice(&[0, 0]); // HasState, HasMinimalIds
        out.push(0); // HasColumnsAndRows
        return Ok(out);
    }
    if r.u8()? != 0 {
        r.take(16 + 4)?; // PropertyNameGuid, PropertyNameId
    }
    let row_count = r.u32()?;
    let columns = read_opt_tags(&mut r)?.unwrap_or_else(|| props::USER_TAGS.to_vec());
    r.aux()?;
    // No filter: the table is the CurrentRec object alone (MS-OXNSPI 3.1.4.1.10).
    let rows: Vec<&gal::Entry> = gal
        .by_mid(stat.current_rec)
        .into_iter()
        .take(row_count as usize)
        .collect();
    let ctx = props::Ctx {
        flags: 0,
        server_guid,
    };
    let mut out = Vec::new();
    put(&mut out, &[0, 0]);
    push_stat(&mut out, &stat);
    out.push(0xFF);
    put(&mut out, &[rows.len() as u32]);
    for e in &rows {
        put(&mut out, &[e.mid]);
    }
    out.push(0xFF);
    push_tags(&mut out, &columns);
    put(&mut out, &[rows.len() as u32]);
    for e in rows {
        props::push_row(&mut out, &columns, &values_for(e, &columns, &ctx));
    }
    Ok(out)
}

/// SeekEntries (2.2.5.16): moves to the first row whose display name sorts at or after the
/// target (Address Book "Name only" search) and returns that row. Explicit tables and other
/// target properties answer MAPI_E_TOO_COMPLEX.
fn seek_entries(gal: &gal::Snapshot, body: &[u8], server_guid: &[u8; 16]) -> Result<Vec<u8>, u32> {
    let mut r = Reader(body);
    r.u32()?;
    let stat = read_opt_stat(&mut r)?.unwrap_or_default();
    let target = if r.u8()? != 0 {
        let tag = r.u32()?;
        let ty = tag as u16;
        let value = match ty {
            props::PT_UNICODE if r.u8()? != 0 => Some(utf16_z(&mut r)?),
            props::PT_STRING8 if r.u8()? != 0 => Some(r.ascii_z()?),
            _ => None,
        };
        value.filter(|_| tag >> 16 == 0x3001)
    } else {
        None
    };
    let explicit = if r.u8()? != 0 {
        let count = r.u32()?;
        read_u32s(&mut r, count)?
    } else {
        Vec::new()
    };
    let columns = read_opt_tags(&mut r)?.unwrap_or_else(|| props::USER_TAGS.to_vec());
    r.aux()?;
    let mut out = Vec::new();
    let Some(target) = target.filter(|_| explicit.is_empty()) else {
        put(&mut out, &[0, MAPI_E_TOO_COMPLEX]);
        out.extend_from_slice(&[0, 0]); // HasState, HasColumnsAndRows
        return Ok(out);
    };
    let target = target.to_lowercase();
    let pos = gal
        .entries()
        .iter()
        .position(|e| e.display_name.to_lowercase() >= target)
        .unwrap_or(gal.entries().len());
    let found = gal.entries().get(pos);
    put(
        &mut out,
        &[
            0,
            if found.is_some() {
                0
            } else {
                props::MAPI_E_NOT_FOUND
            },
        ],
    );
    push_stat(&mut out, &stat_at(gal, &stat, pos));
    out.push(0xFF);
    push_tags(&mut out, &columns);
    let ctx = props::Ctx {
        flags: 0,
        server_guid,
    };
    put(&mut out, &[u32::from(found.is_some())]);
    if let Some(e) = found {
        props::push_row(&mut out, &columns, &values_for(e, &columns, &ctx));
    }
    Ok(out)
}

/// QueryColumns (2.2.5.13): the properties a mail user has.
fn query_columns(body: &[u8]) -> Result<Vec<u8>, u32> {
    let mut r = Reader(body);
    r.u32().and_then(|_| r.u32()).and_then(|_| r.aux())?;
    let mut out = Vec::new();
    put(&mut out, &[0, 0]);
    out.push(0xFF);
    push_tags(&mut out, props::USER_TAGS);
    Ok(out)
}

/// UpdateStat (2.2.5.17): applies Delta to the position.
fn update_stat(gal: &gal::Snapshot, body: &[u8]) -> Result<Vec<u8>, u32> {
    let mut r = Reader(body);
    r.u32()?;
    let stat = read_opt_stat(&mut r)?.unwrap_or_default();
    let delta_requested = r.u8()? != 0;
    r.aux()?;
    let before = seek(gal, &Stat { delta: 0, ..stat });
    let pos = seek(gal, &stat);
    let mut out = Vec::new();
    put(&mut out, &[0, 0]);
    push_stat(&mut out, &stat_at(gal, &stat, pos));
    if delta_requested {
        out.push(0xFF);
        put(&mut out, &[(pos as i64 - before as i64) as i32 as u32]);
    } else {
        out.push(0);
    }
    Ok(out)
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

    fn fixture(name: &str) -> Vec<u8> {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testsuite/modernization/mapihttp/"
        );
        std::fs::read(format!("{dir}{name}")).unwrap()
    }

    /// A bound session on a server whose GAL is `tsv`; returns the Cookie value.
    fn bound(tsv: Option<&str>) -> (crate::request::tests::TestServer, String) {
        let mut srv = server();
        if let Some(tsv) = tsv {
            let snap = gal::Snapshot::parse(tsv, &crate::request::tests::settings(), 1);
            srv.nspi = State::new(Duration::from_secs(1800), gal::Gal::preloaded(snap));
        }
        let sc = run(handle(&srv, nspi("Bind", &bind_capture(), None)))
            .set_cookie
            .unwrap();
        (srv, cookie_of(&sc).to_owned())
    }

    fn call(
        srv: &crate::request::tests::TestServer,
        cookie: &str,
        t: &str,
        body: &[u8],
    ) -> Vec<u8> {
        let rep = run(handle(srv, nspi(t, body, Some(cookie))));
        assert_eq!((rep.http_status, rep.response_code), (200, 0), "{t}");
        assert_eq!(
            &rep.body[rep.body.len() - 4..],
            &[0; 4],
            "AuxiliaryBufferSize"
        );
        rep.body
    }

    fn le(words: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, words);
        out
    }

    fn stat(current: u32, delta: i32) -> Vec<u8> {
        let mut out = vec![0xFF];
        Stat {
            current_rec: current,
            delta,
            code_page: 1252,
            ..Default::default()
        }
        .write(&mut out);
        out
    }

    fn query_rows_body(
        stat_bytes: &[u8],
        explicit: &[u32],
        count: u32,
        columns: &[u32],
    ) -> Vec<u8> {
        let mut b = le(&[0]);
        b.extend_from_slice(stat_bytes);
        b.extend(le(&[explicit.len() as u32]));
        b.extend(le(explicit));
        b.extend(le(&[count]));
        b.push(0xFF);
        b.extend(le(&[columns.len() as u32]));
        b.extend(le(columns));
        b.extend(le(&[0]));
        b
    }

    const LAB: &str = "teste@lab.fitasonline.com.br\tTeste\n";

    #[test]
    fn test_special_table_one_gal_row() {
        let (srv, c) = bound(None);
        let body = call(
            &srv,
            &c,
            "GetSpecialTable",
            &fixture("nspi-getspecialtable-m365-16.0.19127.20800.bin"),
        );
        assert_eq!(&body[..12], &le(&[0, 0, 1252])[..]);
        assert_eq!(&body[12..22], &[0xFF, 1, 0, 0, 0, 0xFF, 1, 0, 0, 0]);
        assert_eq!(&body[22..26], &le(&[6])[..], "six properties");
        assert_eq!(
            &body[26..30],
            &le(&[0x0FFF_0102])[..],
            "PidTagEntryId first"
        );
        let dn_tail = [0x00, 0x01, 0, 0, b'/', 0];
        assert!(
            body.windows(6).any(|w| w == dn_tail),
            "DT_CONTAINER, DN \"/\""
        );
        assert!(
            body.windows(5).any(|w| w == [0x1F, 0x00, 0x01, 0x30, 0x00]),
            "display name without value"
        );
    }

    #[test]
    fn test_dn_to_mid_from_capture() {
        let (srv, c) = bound(Some(LAB));
        let body = call(
            &srv,
            &c,
            "DNToMId",
            &fixture("nspi-dntomid-m365-16.0.19127.20800.bin"),
        );
        assert_eq!(
            &body[..17],
            &[&le(&[0, 0])[..], &[0xFF], &le(&[1, 0x100010])[..]].concat()[..]
        );
        let mut upper = fixture("nspi-dntomid-m365-16.0.19127.20800.bin");
        upper.iter_mut().for_each(|b| *b = b.to_ascii_uppercase());
        let body = call(&srv, &c, "DNToMId", &upper);
        assert_eq!(
            &body[13..17],
            &le(&[0x100010])[..],
            "DNs compare case-insensitively"
        );
    }

    #[test]
    fn test_query_rows_pages_with_stat() {
        let (srv, c) = bound(None);
        let cols = [0x39FE_001F];
        let body = call(
            &srv,
            &c,
            "QueryRows",
            &query_rows_body(&stat(0, 0), &[], 3, &cols),
        );
        let mut r = Reader(&body[8..]);
        let st = read_opt_stat(&mut r).unwrap().unwrap();
        assert_eq!(
            (st.num_pos, st.total_recs, st.current_rec),
            (3, 4, 0x100013)
        );
        assert_eq!(
            (r.u8().unwrap(), r.u32().unwrap(), r.u32().unwrap()),
            (0xFF, 1, cols[0])
        );
        assert_eq!(r.u32().unwrap(), 3, "RowCount");
        let next = call(
            &srv,
            &c,
            "QueryRows",
            &query_rows_body(&stat(st.current_rec, 0), &[], 3, &cols),
        );
        let mut r = Reader(&next[8..]);
        let st = read_opt_stat(&mut r).unwrap().unwrap();
        assert_eq!((st.num_pos, st.current_rec), (4, MID_END_OF_TABLE));
        r.take(9).unwrap();
        assert_eq!(r.u32().unwrap(), 1, "the last row");
    }

    #[test]
    fn test_query_rows_explicit_mids() {
        let (srv, c) = bound(None);
        let body = call(
            &srv,
            &c,
            "QueryRows",
            &query_rows_body(&stat(0, 0), &[0x100011, 0xDEAD], 9, &[0x0FFE_0003]),
        );
        let rows = &body[8 + 37 + 1 + 8..];
        assert_eq!(&rows[..4], &le(&[2])[..]);
        assert_eq!(&rows[4..9], &[0, 6, 0, 0, 0], "MAPI_MAILUSER");
        assert_eq!(
            &rows[9..15],
            &[1, 0x0A, 0x0F, 0x01, 0x04, 0x80],
            "unknown MId: NOT_FOUND"
        );
    }

    #[test]
    fn test_get_props_by_stat() {
        let (srv, c) = bound(None);
        let mut b = le(&[0]);
        b.extend(stat(0x100011, 0));
        b.push(0xFF);
        b.extend(le(&[2, 0x39FE_001F, 0x6666_0003, 0]));
        let body = call(&srv, &c, "GetProps", &b);
        assert_eq!(
            &body[..9],
            &[&le(&[0, EC_WARN_WITH_ERRORS])[..], &[0xFF]].concat()[..]
        );
        assert!(body
            .windows(10)
            .any(|w| w == [b'a', 0, b'l', 0, b'i', 0, b'c', 0, b'e', 0]));
        let mut b = le(&[0]);
        b.extend(stat(0xDEAD, 0));
        b.extend([0, 0, 0, 0, 0]);
        assert_eq!(
            &call(&srv, &c, "GetProps", &b)[..9],
            &[&le(&[0, 0x8004_010F])[..], &[0]].concat()[..]
        );
    }

    #[test]
    fn test_update_stat_delta() {
        let (srv, c) = bound(None);
        let mut b = le(&[0]);
        b.extend(stat(0x100011, 9));
        b.push(1);
        b.extend(le(&[0]));
        let body = call(&srv, &c, "UpdateStat", &b);
        let mut r = Reader(&body[8..]);
        let st = read_opt_stat(&mut r).unwrap().unwrap();
        assert_eq!((st.num_pos, st.current_rec), (4, MID_END_OF_TABLE));
        assert_eq!(
            (r.u8().unwrap(), r.u32().unwrap()),
            (0xFF, 3),
            "moved 3 rows, not 9"
        );
    }

    #[test]
    fn test_requests_truncated() {
        let (srv, c) = bound(None);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "GetSpecialTable",
                fixture("nspi-getspecialtable-m365-16.0.19127.20800.bin"),
            ),
            ("DNToMId", fixture("nspi-dntomid-m365-16.0.19127.20800.bin")),
            (
                "QueryRows",
                query_rows_body(&stat(0, 0), &[0x100011], 2, &[0x3001_001F]),
            ),
            ("QueryColumns", le(&[0, 0, 0])),
        ];
        for (t, body) in cases {
            for n in 0..body.len() {
                let rep = run(handle(&srv, nspi(t, &body[..n], Some(&c))));
                assert_eq!(rep.response_code, 12, "{t} length {n}");
            }
        }
        // Claimed counts far beyond the body are refused before any allocation.
        let huge = query_rows_body(&stat(0, 0), &[], 1, &[]);
        let mut claim = huge.clone();
        claim[4 + 37..4 + 37 + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            run(handle(&srv, nspi("QueryRows", &claim, Some(&c)))).response_code,
            12
        );
    }

    fn resolve_body(names: &[&str]) -> Vec<u8> {
        let mut b = le(&[0]);
        b.extend(stat(0, 0));
        b.push(0xFF);
        b.extend(le(&[1, 0x39FE_001F]));
        b.push(0xFF);
        b.extend(le(&[names.len() as u32]));
        for n in names {
            for u in n.encode_utf16() {
                b.extend_from_slice(&u.to_le_bytes());
            }
            b.extend_from_slice(&[0, 0]);
        }
        b.extend(le(&[0]));
        b
    }

    #[test]
    fn test_resolve_names() {
        let (srv, c) = bound(None);
        let body = call(
            &srv,
            &c,
            "ResolveNames",
            &resolve_body(&["teste", "al", "nobody"]),
        );
        assert_eq!(&body[..12], &le(&[0, 0, 1252])[..]);
        assert_eq!(
            &body[12..29],
            &[&[0xFF][..], &le(&[3, 0x100013, 1, 0])].concat()[..]
        );
        assert_eq!(
            &body[29..38],
            &[&[0xFF][..], &le(&[1, 0x39FE_001F])].concat()[..]
        );
        assert_eq!(&body[38..42], &le(&[1])[..], "one row: the resolved name");
        let addr: Vec<u8> = "teste@lab.example.invalid"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(&body[42..44], &[0, 0xFF]);
        assert_eq!(&body[44..44 + addr.len()], &addr[..]);
        let body = resolve_body(&["teste"]);
        for n in 0..body.len() {
            assert_eq!(
                run(handle(&srv, nspi("ResolveNames", &body[..n], Some(&c)))).response_code,
                12,
                "length {n}"
            );
        }
    }

    #[test]
    fn test_get_matches_from_capture() {
        let (srv, c) = bound(None);
        let capture = fixture("nspi-getmatches-m365-16.0.19127.20800.bin");
        let body = call(&srv, &c, "GetMatches", &capture);
        assert_eq!(&body[..8], &[0; 8]);
        let mut r = Reader(&body[8..]);
        let st = read_opt_stat(&mut r).unwrap().unwrap();
        assert_eq!(st.current_rec, 0x100013, "the STAT comes back unchanged");
        assert_eq!(
            (r.u8().unwrap(), r.u32().unwrap(), r.u32().unwrap()),
            (0xFF, 1, 0x100013)
        );
        assert_eq!(
            (r.u8().unwrap(), r.u32().unwrap()),
            (0xFF, 15),
            "the 15 columns asked for"
        );
        for n in 0..capture.len() {
            assert_eq!(
                run(handle(&srv, nspi("GetMatches", &capture[..n], Some(&c)))).response_code,
                12,
                "length {n}"
            );
        }
        let mut filtered = capture.clone();
        filtered[46] = 0xFF;
        assert_eq!(
            &call(&srv, &c, "GetMatches", &filtered)[..8],
            &le(&[0, MAPI_E_TOO_COMPLEX])[..]
        );
    }

    #[test]
    fn test_seek_entries_display_name() {
        let (srv, c) = bound(None);
        let capture = fixture("nspi-seekentries-m365-16.0.19127.20800.bin");
        let body = call(&srv, &c, "SeekEntries", &capture);
        assert_eq!(&body[..8], &[0; 8]);
        let mut r = Reader(&body[8..]);
        let st = read_opt_stat(&mut r).unwrap().unwrap();
        // "An" sorts after "Alfred Other" and "Alice Example": the cursor lands on "bob".
        assert_eq!((st.num_pos, st.current_rec), (2, 0x100012));
        assert_eq!((r.u8().unwrap(), r.u32().unwrap()), (0xFF, 16));
        r.take(16 * 4).unwrap();
        assert_eq!(r.u32().unwrap(), 1, "the row at the cursor");
        for n in 0..capture.len() {
            assert_eq!(
                run(handle(&srv, nspi("SeekEntries", &capture[..n], Some(&c)))).response_code,
                12,
                "length {n}"
            );
        }
        let mut past_end = capture.clone();
        past_end[47..51].copy_from_slice(&[b'z', 0, b'z', 0]);
        let body = call(&srv, &c, "SeekEntries", &past_end);
        assert_eq!(&body[..8], &le(&[0, 0x8004_010F])[..]);
    }
}

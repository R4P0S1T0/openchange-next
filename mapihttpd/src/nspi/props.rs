//! Address book object properties (MS-OXOABK) and their MAPI/HTTP encodings
//! (MS-OXCMAPIHTTP 2.2.1): AddressBookPropertyValue, ...ValueList and ...PropertyRow.

use super::gal::Entry;
use crate::emsmdb::put;

pub const PT_UNSPECIFIED: u16 = 0x0000;
pub const PT_LONG: u16 = 0x0003;
pub const PT_ERROR: u16 = 0x000A;
pub const PT_BOOLEAN: u16 = 0x000B;
pub const PT_STRING8: u16 = 0x001E;
pub const PT_UNICODE: u16 = 0x001F;
pub const PT_BINARY: u16 = 0x0102;
const MV: u16 = 0x1000;

pub const MAPI_E_NOT_FOUND: u32 = 0x8004_010F;
/// NSPI_PROVIDER: ProviderUID of permanent EntryIDs (MS-OXNSPI 2.2.9.3), GUID C840A7DC-42C0-1A10-B4B9-08002B2FE182.
pub const GUID_NSPI: [u8; 16] = [
    0xDC, 0xA7, 0x40, 0xC8, 0xC0, 0x42, 0x10, 0x1A, 0xB4, 0xB9, 0x08, 0x00, 0x2B, 0x2F, 0xE1, 0x82,
];
const DT_MAILUSER: u32 = 0x0000_0000;
const DT_CONTAINER: u32 = 0x0000_0100;
/// QueryRows/GetProps flag asking for Ephemeral EntryIDs (MS-OXNSPI 2.2.1.11).
pub const F_EPH_ID: u32 = 0x2;

/// Properties served for a mail user, in QueryColumns order.
pub const USER_TAGS: &[u32] = &[
    0x3001_001F, // PidTagDisplayName
    0x3003_001F, // PidTagEmailAddress (LegacyDN)
    0x3002_001F, // PidTagAddressType
    0x39FE_001F, // PidTagSmtpAddress
    0x3A00_001F, // PidTagAccount
    0x39FF_001F, // PidTagAddressBookDisplayNamePrintable
    0x3A20_001F, // PidTagTransmittableDisplayName
    0x0FFE_0003, // PidTagObjectType
    0x3900_0003, // PidTagDisplayType
    0x3905_0003, // PidTagDisplayTypeEx
    0x0FFF_0102, // PidTagEntryId
    0x0FF9_0102, // PidTagRecordKey
    0x0FF6_0102, // PidTagInstanceKey
    0x300B_0102, // PidTagSearchKey
    0x0FF8_0102, // PidTagMappingSignature
    0x3902_0102, // PidTagTemplateid
    0x800F_101F, // PidTagAddressBookProxyAddresses
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Long(u32),
    Bool(bool),
    /// A string; `None` is present-but-null (HasValue FALSE).
    Str(Option<String>),
    Bin(Vec<u8>),
    MvStr(Vec<String>),
}

/// What the property values depend on besides the entry.
pub struct Ctx<'a> {
    pub flags: u32,
    pub server_guid: &'a [u8; 16],
}

pub fn permanent_entry_id(display_type: u32, dn: &str) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0];
    out.extend_from_slice(&GUID_NSPI);
    put(&mut out, &[1, display_type]);
    out.extend(dn.bytes().filter(|&b| b != 0));
    out.push(0);
    out
}

/// Ephemeral EntryID (MS-OXNSPI 2.2.9.2): its ProviderUID is the server GUID sent in Bind.
fn ephemeral_entry_id(server_guid: &[u8; 16], display_type: u32, mid: u32) -> Vec<u8> {
    let mut out = vec![0x87, 0, 0, 0];
    out.extend_from_slice(server_guid);
    put(&mut out, &[1, display_type, mid]);
    out
}

/// The value of property `id` (tag high word) for a mail user, if it has one.
pub fn user_value(e: &Entry, id: u16, ctx: &Ctx<'_>) -> Option<Value> {
    let s = |v: &str| Some(Value::Str(Some(v.to_owned())));
    let permanent = || permanent_entry_id(DT_MAILUSER, &e.legacy_dn);
    match id {
        0x3001 | 0x39FF | 0x3A20 => s(&e.display_name),
        0x3003 => s(&e.legacy_dn),
        0x3002 => s("EX"),
        0x39FE => s(&e.address),
        0x3A00 => s(&e.nickname),
        0x0FFE => Some(Value::Long(6)), // MAPI_MAILUSER
        0x3900 | 0x3905 => Some(Value::Long(DT_MAILUSER)),
        0x0FFF if ctx.flags & F_EPH_ID != 0 => Some(Value::Bin(ephemeral_entry_id(
            ctx.server_guid,
            DT_MAILUSER,
            e.mid,
        ))),
        0x0FFF | 0x0FF9 | 0x3902 => Some(Value::Bin(permanent())),
        0x0FF6 => Some(Value::Bin(e.mid.to_le_bytes().to_vec())),
        0x300B => {
            let mut key = format!("EX:{}", e.legacy_dn.to_uppercase()).into_bytes();
            key.push(0);
            Some(Value::Bin(key))
        }
        0x0FF8 => Some(Value::Bin(GUID_NSPI.to_vec())),
        0x800F => Some(Value::MvStr(vec![format!("SMTP:{}", e.address)])),
        _ => None,
    }
}

/// The GAL's row in the hierarchy table (MS-OXNSPI 3.1.4.1.3), as the legacy emsabp built it.
pub fn gal_row(unicode: bool) -> Vec<(u32, Value)> {
    let string = if unicode { PT_UNICODE } else { PT_STRING8 };
    vec![
        (
            0x0FFF_0102,
            Value::Bin(permanent_entry_id(DT_CONTAINER, "/")),
        ),
        (0x3600_0003, Value::Long(0x1 | 0x8)), // AB_RECIPIENTS | AB_UNMODIFIABLE
        (0x3005_0003, Value::Long(0)),         // PidTagDepth
        (0xFFFD_0003, Value::Long(0)),         // PidTagAddressBookContainerId
        (0x3001_0000 | u32::from(string), Value::Str(None)), // Outlook names it in its language
        (0xFFFB_000B, Value::Bool(false)),     // PidTagAddressBookIsMaster
    ]
}

/// 8-bit strings: shortcut: characters outside Latin-1 (and its C1 range) become '?', whatever
/// the client's code page; add real code page tables if non-1252 clients need them.
fn string8(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| match c as u32 {
            0 => b'?',
            n @ (1..=0x7F | 0xA0..=0xFF) => n as u8,
            _ => b'?',
        })
        .collect()
}

fn push_string(out: &mut Vec<u8>, ty: u16, s: &str) {
    if ty == PT_STRING8 {
        out.extend(string8(s));
        out.push(0);
    } else {
        for unit in s.encode_utf16().filter(|&u| u != 0) {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]);
    }
}

/// The type `v` is sent as when the column asks for `ty`, or None if they do not fit.
fn wire_type(ty: u16, v: &Value) -> Option<u16> {
    match (ty, v) {
        (PT_UNSPECIFIED, Value::Long(_)) | (PT_LONG, Value::Long(_)) => Some(PT_LONG),
        (PT_UNSPECIFIED, Value::Bool(_)) | (PT_BOOLEAN, Value::Bool(_)) => Some(PT_BOOLEAN),
        (PT_UNSPECIFIED, Value::Str(_)) => Some(PT_UNICODE),
        (PT_STRING8 | PT_UNICODE, Value::Str(_)) => Some(ty),
        (PT_UNSPECIFIED, Value::Bin(_)) | (PT_BINARY, Value::Bin(_)) => Some(PT_BINARY),
        (PT_UNSPECIFIED, Value::MvStr(_)) => Some(MV | PT_UNICODE),
        (t, Value::MvStr(_)) if t == MV | PT_STRING8 || t == MV | PT_UNICODE => Some(t),
        _ => None,
    }
}

/// AddressBookPropertyValue (2.2.1.1) of `v` as type `ty` (from `wire_type`). Counts are 32-bit.
fn push_value(out: &mut Vec<u8>, ty: u16, v: &Value) {
    match v {
        Value::Long(n) => put(out, &[*n]),
        Value::Bool(b) => out.push(u8::from(*b)),
        Value::Str(None) => out.push(0x00),
        Value::Str(Some(s)) => {
            out.push(0xFF);
            push_string(out, ty, s);
        }
        Value::Bin(b) => {
            out.push(0xFF);
            put(out, &[b.len() as u32]);
            out.extend_from_slice(b);
        }
        Value::MvStr(items) => {
            out.push(0xFF);
            put(out, &[items.len() as u32]);
            for s in items {
                out.push(0xFF);
                push_string(out, ty & !MV, s);
            }
        }
    }
}

/// AddressBookPropertyValueList (2.2.1.3); a missing value becomes PtypErrorCode NOT_FOUND.
/// Returns whether every value was present.
pub fn push_value_list(out: &mut Vec<u8>, values: &[(u32, Option<Value>)]) -> bool {
    put(out, &[values.len() as u32]);
    let mut complete = true;
    for (tag, value) in values {
        let ty = *tag as u16;
        match value
            .as_ref()
            .and_then(|v| wire_type(ty, v).map(|t| (t, v)))
        {
            Some((t, v)) => {
                put(out, &[(tag & 0xFFFF_0000) | u32::from(t)]);
                push_value(out, t, v);
            }
            None => {
                complete = false;
                put(
                    out,
                    &[(tag & 0xFFFF_0000) | u32::from(PT_ERROR), MAPI_E_NOT_FOUND],
                );
            }
        }
    }
    complete
}

/// AddressBookPropertyRow (2.2.1.7) for known `columns`; flagged when a value is missing.
pub fn push_row(out: &mut Vec<u8>, columns: &[u32], values: &[Option<Value>]) {
    let typed: Vec<_> = columns
        .iter()
        .zip(values)
        .map(|(tag, v)| {
            v.as_ref()
                .and_then(|v| wire_type(*tag as u16, v).map(|t| (t, v)))
        })
        .collect();
    let flagged = typed.iter().any(Option::is_none);
    out.push(u8::from(flagged));
    for (tag, value) in columns.iter().zip(typed) {
        let unspecified = *tag as u16 == PT_UNSPECIFIED;
        match value {
            Some((t, v)) => {
                if unspecified {
                    out.extend_from_slice(&t.to_le_bytes());
                }
                if flagged {
                    out.push(0x0);
                }
                push_value(out, t, v);
            }
            None => {
                if unspecified {
                    out.extend_from_slice(&PT_ERROR.to_le_bytes());
                }
                out.push(0xA);
                put(out, &[MAPI_E_NOT_FOUND]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nspi::gal::tests::snapshot;

    fn teste() -> Entry {
        snapshot().entries()[3].clone()
    }

    #[test]
    fn test_get_props_entryid_layout() {
        let e = teste();
        let ctx = Ctx {
            flags: 0,
            server_guid: &[7; 16],
        };
        let Some(Value::Bin(id)) = user_value(&e, 0x0FFF, &ctx) else {
            panic!()
        };
        assert_eq!(&id[..4], &[0, 0, 0, 0]);
        assert_eq!(&id[4..20], &GUID_NSPI);
        assert_eq!(
            &id[20..28],
            &[1, 0, 0, 0, 0, 0, 0, 0],
            "version 1, DT_MAILUSER"
        );
        assert_eq!(&id[28..], format!("{}\0", e.legacy_dn).as_bytes());
        let eph = Ctx {
            flags: F_EPH_ID,
            server_guid: &[7; 16],
        };
        let Some(Value::Bin(id)) = user_value(&e, 0x0FFF, &eph) else {
            panic!()
        };
        assert_eq!(id.len(), 32);
        assert_eq!(
            (id[0], &id[4..20], &id[28..]),
            (0x87, &[7u8; 16][..], &e.mid.to_le_bytes()[..])
        );
    }

    #[test]
    fn test_unknown_tag_is_error_value() {
        let mut out = Vec::new();
        assert!(!push_value_list(
            &mut out,
            &[
                (0x3001_001F, Some(Value::Str(Some("A".into())))),
                (0x6666_0003, None)
            ]
        ));
        assert_eq!(
            out,
            [
                2, 0, 0, 0, 0x1F, 0, 0x01, 0x30, 0xFF, b'A', 0, 0, 0, 0x0A, 0, 0x66, 0x66, 0x0F,
                0x01, 0x04, 0x80
            ]
        );
        let mut row = Vec::new();
        push_row(
            &mut row,
            &[0x0FFE_0003, 0x6666_0003],
            &[Some(Value::Long(6)), None],
        );
        assert_eq!(row, [1, 0, 6, 0, 0, 0, 0x0A, 0x0F, 0x01, 0x04, 0x80]);
    }

    #[test]
    fn test_unicode_display_name() {
        let v = Value::Str(Some("José Ünal Ω".into()));
        let mut u = Vec::new();
        push_row(&mut u, &[0x3001_001F], &[Some(v.clone())]);
        let mut expect = vec![0, 0xFF];
        for c in "José Ünal Ω".encode_utf16() {
            expect.extend_from_slice(&c.to_le_bytes());
        }
        expect.extend_from_slice(&[0, 0]);
        assert_eq!(u, expect);
        let mut a = Vec::new();
        push_row(&mut a, &[0x3001_001E], &[Some(v)]);
        assert_eq!(a, [&[0u8, 0xFF][..], b"Jos\xE9 \xDCnal ?\0"].concat());
    }

    #[test]
    fn test_unspecified_column_is_typed() {
        let mut row = Vec::new();
        push_row(&mut row, &[0x0FFE_0000], &[Some(Value::Long(6))]);
        assert_eq!(row, [0, 0x03, 0x00, 6, 0, 0, 0]);
    }
}

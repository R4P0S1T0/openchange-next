# MAPI/HTTP captures from real Outlook (M1 Task 0)

Request bodies sent by a real Outlook to a lab listener, used as fixtures by
`check-mapihttp` (`docs/plans/2026-10-30-m1-mapihttp-autodiscover.md`, Task 4).
Results of the spike itself are recorded in that plan under Task 0.

## Provenance

| Field | Value |
|---|---|
| Date | 2026-10-30 |
| Client | Outlook 16.0.19127.20800, classic Microsoft 365 ("Pro"), new test profile |
| Windows | 10.0 build 26100 (terminal server) |
| Server | disposable Debian VM; nginx TLS (public certificate) in front of a Python standard-library listener on 127.0.0.1 |
| Listener answer | Autodiscover: MS-OXDSCLI 4.4-style `mapiHttp` Version 1 response; `/mapi/`: HTTP 200, `X-ResponseCode: 1`, empty body |

## Files

| File | Content |
|---|---|
| `connect-m365-16.0.19127.20800.bin` | 303 bytes, Connect request body to `/mapi/emsmdb/` (MS-OXCMAPIHTTP 2.2.4.1.1) |
| `nspi-bind-m365-16.0.19127.20800.bin` | 45 bytes, Bind request body to `/mapi/nspi/` (MS-OXCMAPIHTTP 2.2.5.1.1) |
| `headers.json` | Request metadata of 4 requests: Autodiscover with Bearer → 401, Autodiscover with Basic → 200, Bind, Connect |
| `autodiscover-request.xml` | Not a capture: MS-OXDSCLI 4.1 request for `alice@example.invalid` (Task 6 tests) |
| `autodiscover-response.xml` | Not a capture: the expected answer to it, in the layout Outlook accepted (Task 0 finding 4), for `--external-host mail.example.invalid` and the default `--org`/`--ou` |

SHA-256:

    9c680bea952cbb2441807a2b4cfdd8e59137202d65f4c5eb4eb21b4dc9d67a9b  connect-m365-16.0.19127.20800.bin
    20449fb87cb21b58f27791372378e9fe56b57d9f5838315ab638f6a6bbe4c46e  nspi-bind-m365-16.0.19127.20800.bin
    4aa7ffdbb96dc4e01ba1694ee37e49fceb3613301e39baee84d83984ab75b015  headers.json

## Sanitization

- Same-length byte replacement, so every size field stays valid. The lab
  account local part became `spike`, host and mail domain became
  `mail.example.invalid` / `example.invalid`, the client address became
  `192.0.2.10` (RFC 5737 documentation range).
- `headers.json`: `Authorization` keeps only the scheme (`Bearer <redacted>`,
  `Basic <redacted>`); `Cookie` only records that one was sent; the
  `MailboxId` query string was removed from the paths.
- Checked by hand (`od`) and by grep: no hostname, IP address, MAC address,
  machine name or Windows user name remains in the bodies.

## Decoded Connect body

Little-endian, no alignment (MS-OXCMAPIHTTP 2.2.4.1.1):

| Offset | Field | Value |
|---|---|---|
| 0 | UserDn (80 chars + NUL) | `/o=Lab/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=spike` |
| 81 | Flags | 0 |
| 85 | DefaultCodePage | 1252 |
| 89 | LcidSort | 0x0416 |
| 93 | LcidString | 0x0416 |
| 97 | AuxiliaryBufferSize | 202 |
| 101 | AuxiliaryBuffer | `RPC_HEADER_EXT` Version 0, Flags 0x0004 (Last, not compressed or obfuscated), Size = SizeActual = 194, then six `AUX_HEADER` blocks |

Auxiliary blocks (MS-OXCRPC 2.2.2.2; Size includes the 4-byte header):

| Size | Version | Type | Content |
|---|---|---|---|
| 50 | 1 | 0x02 `AUX_PERF_CLIENTINFO` | AdapterSpeed 1000000, ClientID 1, ClientMode 2, AdapterName `Ethernet`; machine name, user name, IP, mask and MAC are absent (offsets and sizes 0) |
| 24 | 1 | 0x18 `AUX_PERF_ACCOUNTINFO` | client GUID (same as the `X-ClientInfo` GUID) |
| 28 | 2 | 0x04 `AUX_PERF_SESSIONINFO_V2` | session GUID, connection ID |
| 52 | 2 | 0x0B `AUX_PERF_PROCESSINFO_V2` | process GUID, `OUTLOOK.EXE` |
| 32 | 1 | 0x4A `AUX_CLIENT_CONNECTION_INFO` | connection GUID, 1 attempt, flags 0 |
| 8 | 1 | 0x52 `AUX_ENDPOINT_CAPABILITIES` | flag 1 (single endpoint) |

Types 0x18, 0x4A and 0x52 are not in `exchange.idl`, so parsers must treat
unknown auxiliary blocks as opaque and walk them by `Size`.

## Decoded Bind body

Flags 0, HasState 0xFF, STAT (36 bytes: all zero except CodePage 1252,
TemplateLocale 0x0416, SortLocale 0x0416), AuxiliaryBufferSize 0.

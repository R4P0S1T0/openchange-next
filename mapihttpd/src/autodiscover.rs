//! Autodiscover POX answering MAPI/HTTP clients (MS-OXDSCLI 3.2.5, 3.2.5.1).

use crate::auth::Authenticator;
use crate::backend::Backend;
use crate::request::{self, MapiReply, MapiRequest, Server};
use quick_xml::escape::escape;
use quick_xml::events::Event;
use quick_xml::Reader;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub const PATH: &str = "/autodiscover/autodiscover.xml";
/// Autodiscover requests are a few hundred bytes.
pub const MAX_BODY: usize = 64 * 1024;

/// Identity strings of the deployment (decision 8).
pub struct Settings {
    pub external_host: String,
    pub org: String,
    pub ou: String,
}

pub fn is_path(path: &str) -> bool {
    path.eq_ignore_ascii_case(PATH)
}

/// Header stage, before the body is read: POST only, then the `/mapi/` credential
/// checks. Returns the authenticator's canonical user name.
pub async fn check_headers<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    declared_len: Option<u64>,
) -> Result<String, MapiReply> {
    if req.method != "POST" {
        return Err(request::reply(req, 405, 0));
    }
    let (user, password) = request::basic_credentials(req)?;
    if declared_len.is_some_and(|n| n > MAX_BODY as u64) {
        return Err(error(srv, req, 600));
    }
    request::authenticate(srv, req, &user, &password).await
}

/// Answers a request that passed `check_headers`, with its body read. Only the
/// authenticated user's own settings are returned; X-AnchorMailbox is not trusted.
pub fn handle_body<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    user: &str,
    mapihttp_capability: Option<&str>,
) -> MapiReply {
    let same = |a: &str, b: &str| a.to_lowercase() == b.to_lowercase();
    let s = &srv.autodiscover;
    let legacy_dn = format!(
        "/o={}/ou={}/cn=Recipients/cn={}",
        s.org,
        s.ou,
        user.split('@').next().unwrap_or(user)
    );
    // A LegacyDN takes precedence over EMailAddress (3.2.5).
    let own = match requested(req.body) {
        Some((Some(dn), _)) => same(&dn, &legacy_dn),
        Some((None, Some(address))) => same(&address, user),
        _ => return error(srv, req, 600),
    };
    if !own || user.contains(char::is_control) {
        return error(srv, req, 500);
    }
    // An invalid capability counts as absent (3.2.5.1); then there is nothing to offer (decision 7).
    let capability = mapihttp_capability.and_then(|v| v.trim().parse::<u32>().ok());
    if capability.is_none_or(|v| v == 0) {
        return error(srv, req, 601);
    }
    let guid = mailbox_guid(user);
    let (user, dn, host) = (escape(user), escape(&legacy_dn), escape(&s.external_host));
    let url = |endpoint: &str| format!("https://{host}/mapi/{endpoint}/?MailboxId={guid}@{host}");
    let (emsmdb, nspi) = (url("emsmdb"), url("nspi"));
    // Version 1 is the only response format, so the highest one <= any valid value.
    xml(
        req,
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
 <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
  <User>
   <DisplayName>{user}</DisplayName>
   <LegacyDN>{dn}</LegacyDN>
   <AutoDiscoverSMTPAddress>{user}</AutoDiscoverSMTPAddress>
   <DeploymentId>{guid}</DeploymentId>
  </User>
  <Account>
   <AccountType>email</AccountType>
   <Action>settings</Action>
   <MicrosoftOnline>False</MicrosoftOnline>
   <Protocol Type="mapiHttp" Version="1">
    <MailStore>
     <InternalUrl>{emsmdb}</InternalUrl>
     <ExternalUrl>{emsmdb}</ExternalUrl>
    </MailStore>
    <AddressBook>
     <InternalUrl>{nspi}</InternalUrl>
     <ExternalUrl>{nspi}</ExternalUrl>
    </AddressBook>
   </Protocol>
  </Account>
 </Response>
</Autodiscover>
"#
        ),
    )
}

/// An Error response (2.2.4.1.1.3, example 4.5); it never names the requested address.
pub fn error<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: &MapiRequest<'_>,
    code: u32,
) -> MapiReply {
    let message = match code {
        500 => "The email address cannot be found.",
        600 => "Invalid Request",
        _ => "The Autodiscover server was unable to provide configuration information of the requested type.",
    };
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() % 86400);
    let time = format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60);
    // Id is "a hash value of the name of the mail server".
    let h = Sha256::digest(srv.autodiscover.external_host.as_bytes());
    let id = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    xml(
        req,
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
 <Response>
  <Error Time="{time}" Id="{id}">
   <ErrorCode>{code}</ErrorCode>
   <Message>{message}</Message>
   <DebugData />
  </Error>
 </Response>
</Autodiscover>
"#
        ),
    )
}

fn xml(req: &MapiRequest<'_>, body: String) -> MapiReply {
    MapiReply {
        xml: true,
        body: body.into_bytes(),
        ..request::reply(req, 200, 0)
    }
}

/// `(LegacyDN, EMailAddress)` of a well-formed request (2.2.3.1); `None` if malformed.
fn requested(body: &[u8]) -> Option<(Option<String>, Option<String>)> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let (mut path, mut dn, mut address) = (Vec::new(), None, None);
    loop {
        match reader.read_event().ok()? {
            // Never interpret a DTD (entity expansion): stop here.
            Event::DocType(_) => return None,
            Event::Start(e) => path.push(e.local_name().as_ref().to_vec()),
            Event::End(_) => {
                path.pop();
            }
            Event::Text(t) => {
                let slot = match path.as_slice() {
                    [a, r, field] if a == b"Autodiscover" && r == b"Request" => match &field[..] {
                        b"LegacyDN" => &mut dn,
                        b"EMailAddress" => &mut address,
                        _ => continue,
                    },
                    _ => continue,
                };
                if slot.replace(t.unescape().ok()?.into_owned()).is_some() {
                    return None;
                }
            }
            Event::Eof if path.is_empty() => break,
            Event::Eof => return None,
            _ => {}
        }
    }
    (dn.is_some() || address.is_some()).then_some((dn, address))
}

/// RFC 9562 version 8 UUID from SHA-256 of the lower-cased address: stable per mailbox.
fn mailbox_guid(address: &str) -> String {
    let h = Sha256::digest(address.to_lowercase().as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    let mut out = String::new();
    for (i, x) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = write!(out, "{x:02x}");
    }
    out
}

/// Both stages in sequence, as the glue runs them around its body read.
#[cfg(test)]
pub async fn autodiscover<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    req: MapiRequest<'_>,
    mapihttp_capability: Option<&str>,
) -> MapiReply {
    let declared = u64::try_from(req.body.len()).ok();
    match check_headers(srv, &req, declared).await {
        Ok(user) => handle_body(srv, &req, &user, mapihttp_capability),
        Err(rep) => rep,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::tests::{run, server, TestServer};
    use std::sync::atomic::Ordering;

    const REQUEST: &[u8] =
        include_bytes!("../../testsuite/modernization/mapihttp/autodiscover-request.xml");
    const RESPONSE: &str =
        include_str!("../../testsuite/modernization/mapihttp/autodiscover-response.xml");
    /// `alice@example.invalid:pass`
    const ALICE: &str = "Basic YWxpY2VAZXhhbXBsZS5pbnZhbGlkOnBhc3M=";
    /// `bob@example.invalid:pass`
    const BOB: &str = "Basic Ym9iQGV4YW1wbGUuaW52YWxpZDpwYXNz";

    fn post(body: &[u8]) -> MapiRequest<'_> {
        MapiRequest {
            method: "POST",
            path: "/autodiscover/autodiscover.xml",
            request_type: None,
            request_id: None,
            client_info: None,
            content_type: Some("text/xml"),
            authorization: Some(ALICE),
            cookie: None,
            real_ip: None,
            body,
        }
    }

    fn ask(srv: &TestServer, req: MapiRequest<'_>, cap: Option<&str>) -> MapiReply {
        run(autodiscover(srv, req, cap))
    }

    fn text(rep: &MapiReply) -> &str {
        assert_eq!(rep.http_status, 200);
        assert!(rep.xml);
        std::str::from_utf8(&rep.body).unwrap()
    }

    /// The ErrorCode of an Error response, which says nothing about the address.
    fn error_code(rep: &MapiReply) -> String {
        let t = text(rep);
        assert!(!t.contains("alice"), "{t}");
        assert!(!t.contains("<User>") && !t.contains("<Protocol"), "{t}");
        let start = t.find("<ErrorCode>").expect(t) + "<ErrorCode>".len();
        t[start..start + 3].to_owned()
    }

    #[test]
    fn test_autodiscover_mapihttp() {
        let srv = server();
        let rep = ask(&srv, post(REQUEST), Some("1"));
        assert_eq!(text(&rep), RESPONSE);
        for want in [
            "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">",
            "<AutoDiscoverSMTPAddress>alice@example.invalid</AutoDiscoverSMTPAddress>",
            "<MicrosoftOnline>False</MicrosoftOnline>",
            "<Protocol Type=\"mapiHttp\" Version=\"1\">",
            "<InternalUrl>https://mail.example.invalid/mapi/emsmdb/?MailboxId=",
            "<ExternalUrl>https://mail.example.invalid/mapi/nspi/?MailboxId=",
        ] {
            assert!(text(&rep).contains(want), "{want}");
        }
        assert!(!text(&rep).contains("EXCH") && !text(&rep).contains("EXPR"));
        // Stable per mailbox, whatever the case of the login.
        let again = MapiRequest {
            authorization: Some("Basic QUxJQ0VAZXhhbXBsZS5pbnZhbGlkOnBhc3M="), // ALICE@example.invalid:pass
            ..post(REQUEST)
        };
        assert_eq!(text(&ask(&srv, again, Some("1"))), RESPONSE);
        assert!(rep.set_cookie.is_none());
    }

    #[test]
    fn test_mailbox_guid() {
        assert_eq!(
            mailbox_guid("Alice@Example.invalid"),
            "78d66dbf-bec6-8c3f-b4aa-150451ce5c0c"
        );
    }

    #[test]
    fn test_autodiscover_bearer() {
        let srv = server();
        for authorization in [Some("Bearer x"), None] {
            let rep = ask(
                &srv,
                MapiRequest {
                    authorization,
                    ..post(REQUEST)
                },
                Some("1"),
            );
            assert_eq!(rep.http_status, 401);
        }
        assert_eq!(srv.auth.calls.load(Ordering::SeqCst), 0);
        let bad = MapiRequest {
            authorization: Some("Basic YWxpY2VAZXhhbXBsZS5pbnZhbGlkOm5vcGU="), // alice@...:nope
            ..post(REQUEST)
        };
        assert_eq!(ask(&srv, bad, Some("1")).http_status, 401);
        let temp = MapiRequest {
            authorization: Some("Basic dGVtcDpwYXNz"), // temp:pass
            ..post(REQUEST)
        };
        assert_eq!(ask(&srv, temp, Some("1")).http_status, 503);
    }

    #[test]
    fn test_autodiscover_capability_2() {
        let rep = ask(&server(), post(REQUEST), Some("2"));
        assert_eq!(text(&rep), RESPONSE);
    }

    #[test]
    fn test_autodiscover_capability_invalid() {
        for cap in [Some("0"), Some("abc"), Some("-1"), None] {
            assert_eq!(error_code(&ask(&server(), post(REQUEST), cap)), "601");
        }
    }

    #[test]
    fn test_autodiscover_other_user() {
        let srv = server();
        let rep = ask(
            &srv,
            MapiRequest {
                authorization: Some(BOB),
                ..post(REQUEST)
            },
            Some("1"),
        );
        assert_eq!(error_code(&rep), "500");
        assert!(!text(&rep).contains("bob"));
        // A LegacyDN takes precedence over EMailAddress (3.2.5).
        let dn = |cn: &str| {
            format!(
                "<Autodiscover><Request><EMailAddress>alice@example.invalid</EMailAddress>\
                 <LegacyDN>/o=First Organization/ou=Exchange Administrative Group \
                 (FYDIBOHF23SPDLT)/cn=Recipients/cn={cn}</LegacyDN></Request></Autodiscover>"
            )
        };
        let bob_dn = dn("bob");
        assert_eq!(
            error_code(&ask(&srv, post(bob_dn.as_bytes()), Some("1"))),
            "500"
        );
        let alice_dn = dn("ALICE");
        assert_eq!(
            text(&ask(&srv, post(alice_dn.as_bytes()), Some("1"))),
            RESPONSE
        );
    }

    #[test]
    fn test_autodiscover_malformed_xml() {
        for body in [
            &b""[..],
            b"not xml",
            b"<Autodiscover><Request><EMailAddress>alice@example.invalid</Request></Autodiscover>",
            b"<Autodiscover><Request><EMailAddress>alice@example.invalid</EMailAddress>",
            b"<Autodiscover><Request></Request></Autodiscover>",
            b"<Other><Request><EMailAddress>alice@example.invalid</EMailAddress></Request></Other>",
            b"<Autodiscover><Request><EMailAddress>alice@example.invalid</EMailAddress>\
              <EMailAddress>bob@example.invalid</EMailAddress></Request></Autodiscover>",
            b"<Autodiscover><Request><EMailAddress>\xff</EMailAddress></Request></Autodiscover>",
        ] {
            let rep = ask(&server(), post(body), Some("1"));
            assert_eq!(error_code(&rep), "600", "{}", String::from_utf8_lossy(body));
        }
        let big = vec![b' '; MAX_BODY + 1];
        assert_eq!(error_code(&ask(&server(), post(&big), Some("1"))), "600");
    }

    #[test]
    fn test_autodiscover_doctype() {
        for doctype in [
            "<!DOCTYPE Autodiscover>",
            "<!DOCTYPE x [<!ENTITY a \"alice@example.invalid\">]>",
        ] {
            let body = format!(
                "<?xml version=\"1.0\"?>{doctype}<Autodiscover><Request>\
                 <EMailAddress>alice@example.invalid</EMailAddress></Request></Autodiscover>"
            );
            let rep = ask(&server(), post(body.as_bytes()), Some("1"));
            assert_eq!(error_code(&rep), "600");
        }
    }

    #[test]
    fn test_autodiscover_escapes() {
        let srv = Server {
            autodiscover: Settings {
                external_host: "mail.example.invalid".into(),
                org: "A&B <Org>".into(),
                ou: "\"OU\"".into(),
            },
            ..server()
        };
        let t = text(&ask(&srv, post(REQUEST), Some("1"))).to_owned();
        assert!(
            t.contains("/o=A&amp;B &lt;Org&gt;/ou=&quot;OU&quot;/"),
            "{t}"
        );
    }

    #[test]
    fn test_autodiscover_get() {
        let srv = server();
        let rep = ask(
            &srv,
            MapiRequest {
                method: "GET",
                ..post(b"")
            },
            Some("1"),
        );
        assert_eq!(rep.http_status, 405);
        assert_eq!(srv.auth.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_autodiscover_cookie_ignored() {
        let srv = server();
        let rep = ask(
            &srv,
            MapiRequest {
                cookie: Some("MapiContext=zz; OutlookSession=\"{A}\""),
                ..post(REQUEST)
            },
            Some("1"),
        );
        assert_eq!(text(&rep), RESPONSE);
        assert!(rep.set_cookie.is_none());
    }
}

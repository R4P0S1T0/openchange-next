//! HTTP Basic credential parsing and the authenticator interface.

use base64::Engine;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;

/// A password that never appears in `Debug` output.
pub struct Password(String);

impl Password {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Password {
    fn from(s: &str) -> Self {
        Password(s.to_owned())
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthResult {
    Ok { user: String },
    BadCredentials,
    TempFail,
}

pub trait Authenticator: Send + Sync {
    fn authenticate(
        &self,
        user: &str,
        password: &Password,
        rip: Option<IpAddr>,
    ) -> impl Future<Output = AuthResult> + Send;
}

#[derive(Debug)]
pub enum BasicCredentials {
    Missing,
    OtherScheme,
    Malformed,
    Basic { user: String, password: Password },
}

pub fn parse_authorization(value: Option<&str>) -> BasicCredentials {
    let Some(value) = value else {
        return BasicCredentials::Missing;
    };
    let value = value.trim();
    let (scheme, token) = value.split_once(' ').unwrap_or((value, ""));
    if !scheme.eq_ignore_ascii_case("Basic") {
        return BasicCredentials::OtherScheme;
    }
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(token.trim()) else {
        return BasicCredentials::Malformed;
    };
    let Ok(text) = String::from_utf8(raw) else {
        return BasicCredentials::Malformed;
    };
    match text.split_once(':') {
        Some((user, password)) if !user.is_empty() => BasicCredentials::Basic {
            user: user.to_owned(),
            password: Password::from(password),
        },
        _ => BasicCredentials::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_debug_redacted() {
        assert!(!format!("{:?}", Password::from("secret")).contains("secret"));
    }

    #[test]
    fn test_parse_authorization() {
        assert!(matches!(
            parse_authorization(None),
            BasicCredentials::Missing
        ));
        assert!(matches!(
            parse_authorization(Some("Bearer eyJ0eXAi")),
            BasicCredentials::OtherScheme
        ));
        assert!(matches!(
            parse_authorization(Some("Basic !!!")),
            BasicCredentials::Malformed
        ));
        // "nocolon"
        assert!(matches!(
            parse_authorization(Some("Basic bm9jb2xvbg==")),
            BasicCredentials::Malformed
        ));
        match parse_authorization(Some("basic dXNlcjpwOmFzcw==")) {
            BasicCredentials::Basic { user, password } => {
                assert_eq!(user, "user");
                assert_eq!(password.expose(), "p:ass");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

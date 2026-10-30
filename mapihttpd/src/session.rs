//! Session Contexts keyed by the MapiContext cookie (MS-OXCMAPIHTTP 3.2.5.1).

use crate::auth::Password;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Key of the C worker's handle table (Task 4).
pub type SessionId = u64;

const COOKIE_NAME: &str = "MapiContext";

struct Session {
    user: String,
    cred_hash: [u8; 32],
    backend: SessionId,
    last_used: Instant,
    busy: bool,
}

/// No Debug: it holds cookies and credential hashes.
pub struct SessionTable {
    idle: Duration,
    key: [u8; 32],
    sessions: Mutex<HashMap<String, Session>>,
}

/// One request in flight on a session; clears the busy flag on drop.
/// From `touch`, it marks nothing busy and clears nothing.
pub struct SessionGuard<'a> {
    table: &'a SessionTable,
    cookie: String,
    user: String,
    holds_busy: bool,
}

fn random<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf
}

/// The MapiContext value among the request's cookies: 13 if absent, 6 if not ours in form.
fn find_cookie(header: Option<&str>) -> Result<&str, u32> {
    let value = header
        .into_iter()
        .flat_map(|h| h.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find_map(|(name, value)| (name == COOKIE_NAME).then_some(value))
        .ok_or(13u32)?;
    let ours = value.len() == 32
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if ours {
        Ok(value)
    } else {
        Err(6)
    }
}

impl SessionTable {
    pub fn new(idle: Duration) -> Self {
        SessionTable {
            idle,
            key: random(),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        // A panic elsewhere must not lock every user out.
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Live and owned by these credentials; the hash is compared in constant time.
    fn usable(&self, s: &Session, cred_hash: &[u8; 32], now: Instant) -> bool {
        bool::from(s.cred_hash.ct_eq(cred_hash)) && !self.expired(s, now)
    }

    fn expired(&self, s: &Session, now: Instant) -> bool {
        now.saturating_duration_since(s.last_used) > self.idle
    }

    pub fn credential_hash(&self, user: &str, password: &Password) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes any key length");
        // Length prefix: ("ab", "c") and ("a", "bc") must not collide.
        mac.update(&(user.len() as u64).to_le_bytes());
        mac.update(user.as_bytes());
        mac.update(password.expose().as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Returns the Set-Cookie value of the new session.
    pub fn create(
        &self,
        user: &str,
        cred_hash: [u8; 32],
        backend: SessionId,
        now: Instant,
    ) -> String {
        let cookie = format!("{:032x}", u128::from_ne_bytes(random()));
        let session = Session {
            user: user.to_owned(),
            cred_hash,
            backend,
            last_used: now,
            busy: false,
        };
        self.lock().insert(cookie.clone(), session);
        set_cookie(&cookie)
    }

    pub fn begin(
        &self,
        cookie_header: Option<&str>,
        cred_hash: [u8; 32],
        now: Instant,
    ) -> Result<SessionGuard<'_>, u32> {
        let cookie = find_cookie(cookie_header)?;
        let mut sessions = self.lock();
        // Other credentials look like an unknown cookie (3.2.5.1), and are checked before busy.
        let s = sessions
            .get_mut(cookie)
            .filter(|s| self.usable(s, &cred_hash, now))
            .ok_or(10u32)?;
        if s.busy {
            return Err(15);
        }
        s.busy = true;
        s.last_used = now;
        Ok(SessionGuard {
            table: self,
            cookie: cookie.to_owned(),
            user: s.user.clone(),
            holds_busy: true,
        })
    }

    /// PING keep-alive (3.1.5.3): refreshes the idle clock even while the session is busy.
    /// None when the cookie or credentials do not name a live session.
    pub fn touch(
        &self,
        cookie_header: Option<&str>,
        cred_hash: [u8; 32],
        now: Instant,
    ) -> Option<SessionGuard<'_>> {
        let cookie = find_cookie(cookie_header).ok()?;
        let mut sessions = self.lock();
        let s = sessions
            .get_mut(cookie)
            .filter(|s| self.usable(s, &cred_hash, now))?;
        s.last_used = now;
        Some(SessionGuard {
            table: self,
            cookie: cookie.to_owned(),
            user: s.user.clone(),
            holds_busy: false,
        })
    }

    pub fn remove(&self, cookie: &str) -> Option<SessionId> {
        self.lock().remove(cookie).map(|s| s.backend)
    }

    /// Drops idle sessions; callers disconnect the returned backend sessions.
    pub fn expire(&self, now: Instant) -> Vec<SessionId> {
        let mut gone = Vec::new();
        self.lock().retain(|_, s| {
            let keep = s.busy || !self.expired(s, now);
            if !keep {
                gone.push(s.backend);
            }
            keep
        });
        gone
    }

    #[cfg(test)]
    pub fn last_used(&self, cookie: &str) -> Option<Instant> {
        self.lock().get(cookie).map(|s| s.last_used)
    }
}

fn set_cookie(cookie: &str) -> String {
    format!("{COOKIE_NAME}={cookie}; Path=/mapi/; Secure; HttpOnly")
}

impl SessionGuard<'_> {
    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn set_cookie(&self) -> String {
        set_cookie(&self.cookie)
    }

    /// X-ExpirationInfo: `begin`/`touch` just reset the idle clock, so the full idle time remains.
    pub fn expiration_ms(&self) -> u32 {
        u32::try_from(self.table.idle.as_millis()).unwrap_or(u32::MAX)
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if !self.holds_busy {
            return;
        }
        if let Some(s) = self.table.lock().get_mut(&self.cookie) {
            s.busy = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: Duration = Duration::from_secs(1800);

    fn table() -> SessionTable {
        SessionTable::new(IDLE)
    }

    /// The `Cookie` header a client sends back for a `Set-Cookie` value.
    pub fn cookie_of(set_cookie: &str) -> &str {
        set_cookie.split(';').next().unwrap()
    }

    #[test]
    fn test_connect_sets_cookie() {
        let t = table();
        let now = Instant::now();
        let h = t.credential_hash("user", &Password::from("pass"));
        let sc = t.create("user", h, 7, now);
        let value = sc
            .strip_prefix("MapiContext=")
            .and_then(|r| r.strip_suffix("; Path=/mapi/; Secure; HttpOnly"))
            .unwrap_or_else(|| panic!("bad Set-Cookie {sc}"));
        assert_eq!(value.len(), 32);
        assert!(value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        let g = t.begin(Some(cookie_of(&sc)), h, now).ok().unwrap();
        assert_eq!(g.expiration_ms(), 1_800_000);
        assert_eq!(g.set_cookie(), sc);
        assert_ne!(t.create("user", h, 8, now), sc);
    }

    #[test]
    fn test_credential_hash() {
        let t = table();
        let h = t.credential_hash("user", &Password::from("pass"));
        assert_eq!(h, t.credential_hash("user", &Password::from("pass")));
        assert_ne!(h, t.credential_hash("user", &Password::from("other")));
        assert_ne!(h, t.credential_hash("use", &Password::from("rpass")));
        // Per-process key: another table hashes differently.
        assert_ne!(h, table().credential_hash("user", &Password::from("pass")));
    }

    #[test]
    fn test_begin_codes() {
        let t = table();
        let now = Instant::now();
        let h = t.credential_hash("user", &Password::from("pass"));
        let sc = t.create("user", h, 1, now);
        let code = |c: Option<&str>| t.begin(c, h, now).err();
        assert_eq!(code(None), Some(13));
        assert_eq!(code(Some("other=1")), Some(13));
        assert_eq!(code(Some("MapiContext=zz")), Some(6));
        assert_eq!(code(Some("MapiContext=")), Some(6));
        assert_eq!(
            code(Some("MapiContext=0123456789ABCDEF0123456789ABCDEF")),
            Some(6)
        );
        assert_eq!(
            code(Some("MapiContext=0123456789abcdef0123456789abcdef")),
            Some(10)
        );
        let other = t.credential_hash("other", &Password::from("pass"));
        assert_eq!(t.begin(Some(cookie_of(&sc)), other, now).err(), Some(10));
        // Among other cookies, as clients send them.
        let mixed = format!("a=b; {}; c=d", cookie_of(&sc));
        assert!(t.begin(Some(&mixed), h, now).is_ok());
    }

    #[test]
    fn test_busy_session() {
        let t = table();
        let now = Instant::now();
        let h = t.credential_hash("user", &Password::from("pass"));
        let sc = t.create("user", h, 1, now);
        let g = t.begin(Some(cookie_of(&sc)), h, now).ok().unwrap();
        assert_eq!(t.begin(Some(cookie_of(&sc)), h, now).err(), Some(15));
        drop(g);
        assert!(t.begin(Some(cookie_of(&sc)), h, now).is_ok());
    }

    #[test]
    fn test_disconnect_invalidates() {
        let t = table();
        let now = Instant::now();
        let h = t.credential_hash("user", &Password::from("pass"));
        let sc = t.create("user", h, 42, now);
        let value = &cookie_of(&sc)["MapiContext=".len()..];
        assert_eq!(t.remove(value), Some(42));
        assert_eq!(t.remove(value), None);
        assert_eq!(t.begin(Some(cookie_of(&sc)), h, now).err(), Some(10));
    }

    #[test]
    fn test_touch() {
        let t = table();
        let now = Instant::now();
        let later = now + Duration::from_secs(60);
        let h = t.credential_hash("user", &Password::from("pass"));
        let sc = t.create("user", h, 1, now);
        let value = &cookie_of(&sc)["MapiContext=".len()..];
        let other = t.credential_hash("other", &Password::from("pass"));
        assert!(t.touch(Some(cookie_of(&sc)), other, later).is_none());
        assert!(t.touch(None, h, later).is_none());
        assert!(t.touch(Some("MapiContext=zz"), h, later).is_none());
        assert_eq!(t.last_used(value), Some(now));
        // Busy sessions are refreshed without waiting, and stay busy.
        let held = t.begin(Some(cookie_of(&sc)), h, now).ok().unwrap();
        let touched = t.touch(Some(cookie_of(&sc)), h, later).unwrap();
        assert_eq!(touched.set_cookie(), sc);
        assert_eq!(touched.expiration_ms(), 1_800_000);
        assert_eq!(t.last_used(value), Some(later));
        drop(touched);
        assert_eq!(t.begin(Some(cookie_of(&sc)), h, later).err(), Some(15));
        drop(held);
        let late = now + Duration::from_secs(1801);
        assert!(t.touch(Some(cookie_of(&sc)), h, late + IDLE).is_none());
    }

    #[test]
    fn test_user_stored() {
        let t = table();
        let now = Instant::now();
        let h = t.credential_hash("user", &Password::from("pass"));
        let sc = t.create("user", h, 1, now);
        let g = t.begin(Some(cookie_of(&sc)), h, now).ok().unwrap();
        assert_eq!(g.user(), "user");
    }

    #[test]
    fn test_idle_expiry() {
        let t = table();
        let now = Instant::now();
        let h = t.credential_hash("user", &Password::from("pass"));
        let sc = t.create("user", h, 9, now);
        let keep = t.create("user", h, 10, now + Duration::from_secs(1000));
        let later = now + Duration::from_secs(1801);
        assert_eq!(t.begin(Some(cookie_of(&sc)), h, later).err(), Some(10));
        assert_eq!(t.expire(later), vec![9]);
        assert_eq!(t.expire(later), Vec::<SessionId>::new());
        assert!(t.begin(Some(cookie_of(&keep)), h, later).is_ok());
    }
}

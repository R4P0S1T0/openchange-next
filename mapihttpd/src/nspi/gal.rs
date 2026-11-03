//! The Global Address List: active mailboxes from the directory snapshot that
//! openchange_directory_sync writes ("address TAB display name" lines).

use crate::autodiscover::{legacy_dn, nickname, Settings};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// MIds below this are reserved (MS-OXNSPI 2.2.1.8: beginning, current, end of table).
const FIRST_MID: u32 = 0x10;
/// MId = generation << GEN_SHIFT | (FIRST_MID + row): a MId from an older snapshot never names a row.
const GEN_SHIFT: u32 = 20;
const MAX_ROWS: usize = (1 << GEN_SHIFT) - FIRST_MID as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub mid: u32,
    pub address: String,
    pub display_name: String,
    pub nickname: String,
    pub legacy_dn: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    None,
    One(u32),
    Ambiguous,
}

#[derive(Debug, Default)]
pub struct Snapshot {
    generation: u32,
    entries: Vec<Entry>,
}

impl Snapshot {
    /// Rows sorted by display name, then address (SortTypeDisplayName); malformed lines are skipped.
    pub fn parse(text: &str, settings: &Settings, generation: u32) -> Snapshot {
        let generation = generation & ((1 << (32 - GEN_SHIFT)) - 1);
        let mut rows: Vec<(String, String)> = text
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .filter(|(a, _)| a.contains('@') && !a.contains(char::is_control))
            .map(|(a, n)| (a.to_lowercase(), n.to_owned()))
            .collect();
        rows.sort_by_key(|(a, n)| (n.to_lowercase(), a.clone()));
        rows.dedup_by(|x, y| x.0 == y.0);
        rows.truncate(MAX_ROWS);
        let entries = rows
            .into_iter()
            .enumerate()
            .map(|(i, (address, display_name))| Entry {
                mid: generation << GEN_SHIFT | (FIRST_MID + i as u32),
                nickname: nickname(&address),
                legacy_dn: legacy_dn(settings, &address),
                address,
                display_name,
            })
            .collect();
        Snapshot { generation, entries }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Row position of a MId of this snapshot.
    pub fn position(&self, mid: u32) -> Option<usize> {
        if mid >> GEN_SHIFT != self.generation {
            return None;
        }
        let row = (mid & ((1 << GEN_SHIFT) - 1)).checked_sub(FIRST_MID)? as usize;
        (row < self.entries.len()).then_some(row)
    }

    pub fn by_mid(&self, mid: u32) -> Option<&Entry> {
        self.position(mid).map(|i| &self.entries[i])
    }

    pub fn by_legacy_dn(&self, dn: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.legacy_dn.eq_ignore_ascii_case(dn))
    }

    /// Ambiguous name resolution (MS-OXNSPI 3.1.4.7): an exact address or LegacyDN wins; otherwise
    /// a case-insensitive prefix of the address, local part, nickname or a display-name word.
    pub fn resolve(&self, name: &str) -> Resolution {
        let name = name.trim().to_lowercase();
        if name.is_empty() {
            return Resolution::None;
        }
        let exact = self
            .entries
            .iter()
            .find(|e| e.address == name || e.legacy_dn.to_lowercase() == name);
        if let Some(e) = exact {
            return Resolution::One(e.mid);
        }
        let mut hits = self.matching(&name);
        match (hits.next(), hits.next()) {
            (None, _) => Resolution::None,
            (Some(e), None) => Resolution::One(e.mid),
            _ => Resolution::Ambiguous,
        }
    }

    /// Entries whose address, nickname or display-name words start with `prefix` (lower case).
    pub fn matching<'s>(&'s self, prefix: &'s str) -> impl Iterator<Item = &'s Entry> + 's {
        self.entries.iter().filter(move |e| {
            let display = e.display_name.to_lowercase();
            e.address.starts_with(prefix)
                || e.nickname.starts_with(prefix)
                || display.starts_with(prefix)
                || display.split_whitespace().any(|w| w.starts_with(prefix))
        })
    }
}

/// The snapshot file, reloaded when its mtime changes; the generation moves only when its
/// content does, so the timer's rewrites every minute keep MIds valid.
pub struct Gal {
    path: PathBuf,
    settings: Settings,
    state: Mutex<Loaded>,
}

struct Loaded {
    mtime: Option<SystemTime>,
    digest: [u8; 32],
    snapshot: Arc<Snapshot>,
}

impl Gal {
    pub fn new(path: PathBuf, settings: Settings) -> Self {
        Gal {
            path,
            settings,
            state: Mutex::new(Loaded {
                mtime: None,
                digest: [0; 32],
                snapshot: Arc::new(Snapshot::default()),
            }),
        }
    }

    /// A GAL that never reloads (its path does not exist).
    #[cfg(test)]
    pub fn preloaded(snapshot: Snapshot) -> Self {
        let gal = Gal::new(PathBuf::new(), crate::request::tests::settings());
        gal.state.lock().unwrap().snapshot = Arc::new(snapshot);
        gal
    }

    /// The current snapshot; a missing or unreadable file is an empty GAL.
    pub fn current(&self) -> Arc<Snapshot> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mtime = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if mtime.is_some() && mtime != st.mtime {
            let text = std::fs::read_to_string(&self.path).unwrap_or_default();
            let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
            if digest != st.digest {
                let generation = st.snapshot.generation.wrapping_add(1);
                st.snapshot = Arc::new(Snapshot::parse(&text, &self.settings, generation));
                st.digest = digest;
            }
            st.mtime = mtime;
        }
        st.snapshot.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::request::tests::settings;

    pub const TSV: &str = "teste@lab.example.invalid\tTeste Lab\n\
        bob@example.invalid\tbob\n\
        alice@example.invalid\tAlice Example\n\
        alfred@example.invalid\tAlfred Other\n\
        malformed line\n";

    pub fn snapshot() -> Snapshot {
        Snapshot::parse(TSV, &settings(), 1)
    }

    #[test]
    fn test_gal_sorted_mids() {
        let s = snapshot();
        let names: Vec<_> = s.entries().iter().map(|e| e.display_name.as_str()).collect();
        assert_eq!(names, ["Alfred Other", "Alice Example", "bob", "Teste Lab"]);
        let mids: Vec<_> = s.entries().iter().map(|e| e.mid).collect();
        assert_eq!(mids, [0x100010, 0x100011, 0x100012, 0x100013]);
        assert_eq!(s.by_mid(0x100011).unwrap().address, "alice@example.invalid");
        assert!(s.by_mid(0x100014).is_none() && s.by_mid(1).is_none());
        let e = s.by_mid(0x100013).unwrap();
        assert_eq!(e.legacy_dn, legacy_dn(&settings(), "teste@lab.example.invalid"));
        assert!(s.by_legacy_dn(&e.legacy_dn.to_uppercase()).is_some());
    }

    #[test]
    fn test_stale_mid_after_reload() {
        let old = snapshot();
        let alfred = old.entries()[0].mid;
        let new = Snapshot::parse("bob@example.invalid\tAaron\nzed@example.invalid\tZed\n", &settings(), 2);
        assert!(new.by_mid(alfred).is_none(), "a MId of the old snapshot names nobody");
    }

    #[test]
    fn test_resolve_prefix_unique_ambiguous_none() {
        let s = snapshot();
        let mid = |a: &str| s.entries().iter().find(|e| e.address == a).unwrap().mid;
        assert_eq!(s.resolve("teste"), Resolution::One(mid("teste@lab.example.invalid")));
        assert_eq!(s.resolve("Example"), Resolution::One(mid("alice@example.invalid")));
        assert_eq!(s.resolve("al"), Resolution::Ambiguous);
        assert_eq!(s.resolve("ALICE@example.invalid"), Resolution::One(mid("alice@example.invalid")));
        assert_eq!(s.resolve("nobody"), Resolution::None);
        assert_eq!(s.resolve("  "), Resolution::None);
    }

    #[test]
    fn test_snapshot_missing_is_empty_gal() {
        let gal = Gal::new(PathBuf::from("/nonexistent/directory.tsv"), settings());
        assert!(gal.current().entries().is_empty());
    }

    #[test]
    fn test_reload_only_on_change() {
        let dir = std::env::temp_dir().join(format!("gal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("directory.tsv");
        std::fs::write(&path, TSV).unwrap();
        let gal = Gal::new(path.clone(), settings());
        let first = gal.current().entries()[0].mid;
        std::fs::write(&path, TSV).unwrap(); // the timer's rewrite, same content
        assert_eq!(gal.current().entries()[0].mid, first);
        std::fs::write(&path, "zed@example.invalid\tZed\n").unwrap();
        let filetime = SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(filetime).unwrap();
        assert!(gal.current().by_mid(first).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

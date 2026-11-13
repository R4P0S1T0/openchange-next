//! M5: one IMAP connection per online user tells Outlook which folders changed.
//!
//! The watcher logs in to the loopback Dovecot the IMAP backend uses (master login), asks for
//! NOTIFY STATUS events (RFC 5465) and reports changed mailboxes to every EMSMDB session of the
//! user, whose next NotificationWait then returns. Without NOTIFY it polls LIST-STATUS. A STATUS
//! that matches the last known state is not a change: Dovecot repeats them after NOTIFY SET and
//! after a flag change.

use crate::auth::Authenticator;
use crate::backend::{Backend, FolderChange, WatchParams};
use crate::request::Server;
use base64::Engine;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};

const MAX_LINE: usize = 64 * 1024;
const NOTIFY: &str =
    "NOTIFY SET STATUS (personal (MessageNew MessageExpunge FlagChange MailboxName))";
const POLL: &str =
    "LIST \"\" \"*\" RETURN (STATUS (MESSAGES UNSEEN UIDNEXT UIDVALIDITY HIGHESTMODSEQ))";
/// The STATUS items that make up a mailbox's state, whichever response carried them.
const STATE_ITEMS: [&str; 5] = [
    "HIGHESTMODSEQ",
    "MESSAGES",
    "UIDNEXT",
    "UIDVALIDITY",
    "UNSEEN",
];

/// Where log lines go; never handed a password or a command line.
pub type Log = Arc<dyn Fn(String) + Send + Sync>;

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Events for the same mailbox within this window make one report.
    pub coalesce: Duration,
    /// LIST-STATUS interval when the server refuses NOTIFY.
    pub poll: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// How often an idle watcher checks that its user still has sessions.
    pub idle_check: Duration,
    /// Connect, greeting and command replies.
    pub command: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            coalesce: Duration::from_secs(1),
            poll: Duration::from_secs(60),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            idle_check: Duration::from_secs(60),
            command: Duration::from_secs(30),
        }
    }
}

/// Starts and stops the per-user watchers; cheap to call on every Connect and Disconnect.
pub struct WatchManager {
    tx: Option<mpsc::UnboundedSender<String>>,
}

impl WatchManager {
    /// A manager and the receiver `supervise` runs on.
    pub fn new() -> (Self, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (WatchManager { tx: Some(tx) }, rx)
    }

    /// Watches nothing (tests).
    #[cfg(test)]
    pub fn disabled() -> Self {
        WatchManager { tx: None }
    }

    pub fn session_started(&self, user: &str) {
        self.nudge(user);
    }

    pub fn session_ended(&self, user: &str) {
        self.nudge(user);
    }

    fn nudge(&self, user: &str) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(user.to_owned());
        }
    }
}

/// Runs the watchers: one per user with a live session, stopped when the user has none.
pub async fn supervise<A, B>(
    srv: Arc<Server<A, B>>,
    mut rx: mpsc::UnboundedReceiver<String>,
    timing: Timing,
    log: Log,
) where
    A: Authenticator + 'static,
    B: Backend + 'static,
{
    let Some(params) = srv.backend.watch_params().await else {
        log("IMAP watcher off: mapistore:imap_host/imap_master_password_file not usable".into());
        while rx.recv().await.is_some() {}
        return;
    };
    let params = Arc::new(params);
    let mut running: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    while let Some(user) = rx.recv().await {
        let online = !srv.sessions.sessions_of(&user).is_empty();
        match running.get(&user) {
            Some(task) if !online => {
                task.abort();
                running.remove(&user);
            }
            Some(task) if !task.is_finished() => {}
            _ if online => {
                let task = tokio::spawn(watch_user(
                    srv.clone(),
                    params.clone(),
                    user.clone(),
                    timing,
                    log.clone(),
                ));
                running.insert(user, task);
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Atom(String),
    Str(String),
    Open,
    Close,
}

impl Tok {
    fn is(&self, word: &str) -> bool {
        matches!(self, Tok::Atom(a) if a.eq_ignore_ascii_case(word))
    }

    /// An astring (mailbox names and values).
    fn text(&self) -> Option<&str> {
        match self {
            Tok::Atom(s) | Tok::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// Appends the tokens of one response line; returns the size of a literal it ends with.
fn lex(line: &[u8], out: &mut Vec<Tok>) -> Option<usize> {
    let mut i = 0;
    while i < line.len() {
        match line[i] {
            b' ' => i += 1,
            b'(' => {
                out.push(Tok::Open);
                i += 1;
            }
            b')' => {
                out.push(Tok::Close);
                i += 1;
            }
            b'"' => {
                let mut s = Vec::new();
                i += 1;
                while i < line.len() && line[i] != b'"' {
                    if line[i] == b'\\' && i + 1 < line.len() {
                        i += 1;
                    }
                    s.push(line[i]);
                    i += 1;
                }
                i += 1;
                out.push(Tok::Str(String::from_utf8_lossy(&s).into_owned()));
            }
            b'{' if line.ends_with(b"}") => {
                let digits = line[i + 1..line.len() - 1]
                    .strip_suffix(b"+")
                    .unwrap_or(&line[i + 1..line.len() - 1]);
                return std::str::from_utf8(digits).ok()?.parse().ok();
            }
            _ => {
                let start = i;
                while i < line.len() && !matches!(line[i], b' ' | b'(' | b')') {
                    i += 1;
                }
                out.push(Tok::Atom(
                    String::from_utf8_lossy(&line[start..i]).into_owned(),
                ));
            }
        }
    }
    None
}

/// What one untagged response says about the user's mailboxes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MailboxEvent {
    /// A mailbox's STATUS: messages arrived, left or changed flags (`state` is comparable).
    Changed { mailbox: String, state: String },
    /// A mailbox was created, renamed or deleted.
    ListChanged,
}

fn parse_event(toks: &[Tok]) -> Option<MailboxEvent> {
    if !toks.first()?.is("*") {
        return None;
    }
    if toks.get(1)?.is("LIST") {
        return Some(MailboxEvent::ListChanged);
    }
    if !toks[1].is("STATUS") {
        return None;
    }
    let mailbox = toks.get(2)?.text()?.to_owned();
    let mut items: BTreeMap<String, String> = BTreeMap::new();
    let mut rest = toks.get(4..)?.iter();
    while let (Some(Tok::Atom(k)), Some(v)) = (rest.next(), rest.next()) {
        let k = k.to_ascii_uppercase();
        if STATE_ITEMS.contains(&k.as_str()) {
            items.insert(k, v.text().unwrap_or_default().to_owned());
        }
    }
    let state = items
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ");
    Some(MailboxEvent::Changed { mailbox, state })
}

/// Mailbox name to state, from LIST-STATUS.
type Snapshot = BTreeMap<String, String>;

fn diff(old: &Snapshot, new: &Snapshot) -> Vec<(String, FolderChange)> {
    let mut out = Vec::new();
    for (name, state) in new {
        match old.get(name) {
            None => out.push((name.clone(), FolderChange::Added)),
            Some(s) if s != state => out.push((name.clone(), FolderChange::Modified)),
            _ => {}
        }
    }
    out.extend(
        old.keys()
            .filter(|n| !new.contains_key(*n))
            .map(|n| (n.clone(), FolderChange::Deleted)),
    );
    out
}

enum Failure {
    Io(io::Error),
    /// The server answered NO or BAD; only the command's verb is kept.
    Refused(&'static str),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Io(e) => write!(f, "IMAP connection: {e}"),
            Failure::Refused(verb) => write!(f, "IMAP {verb} refused"),
        }
    }
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Failure::Io(e)
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "no answer")
}

struct Conn {
    rd: BufReader<OwnedReadHalf>,
    wr: OwnedWriteHalf,
    tag: u32,
    wait: Duration,
    delimiter: u8,
}

impl Conn {
    async fn open(p: &WatchParams, wait: Duration) -> Result<Conn, Failure> {
        let sock = timeout(wait, TcpStream::connect((p.host.as_str(), p.port)))
            .await
            .map_err(|_| timed_out())??;
        let (rd, wr) = sock.into_split();
        let mut c = Conn {
            rd: BufReader::new(rd),
            wr,
            tag: 0,
            wait,
            delimiter: b'/',
        };
        let greeting = timeout(wait, c.response())
            .await
            .map_err(|_| timed_out())??;
        if !(greeting.first().is_some_and(|t| t.is("*"))
            && greeting.get(1).is_some_and(|t| t.is("OK")))
        {
            return Err(Failure::Refused("greeting"));
        }
        Ok(c)
    }

    /// One response, literals included.
    async fn response(&mut self) -> io::Result<Vec<Tok>> {
        let mut toks = Vec::new();
        loop {
            let mut line = Vec::new();
            (&mut self.rd)
                .take(MAX_LINE as u64)
                .read_until(b'\n', &mut line)
                .await?;
            if line.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if line.pop() != Some(b'\n') {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            match lex(&line, &mut toks) {
                Some(n) if n <= MAX_LINE => {
                    let mut buf = vec![0u8; n];
                    self.rd.read_exact(&mut buf).await?;
                    toks.push(Tok::Str(String::from_utf8_lossy(&buf).into_owned()));
                }
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "literal too long",
                    ))
                }
                None => return Ok(toks),
            }
        }
    }

    /// Runs a command; its untagged responses on OK. `verb` names it in errors: `args` may
    /// hold credentials and appears nowhere else.
    async fn command(&mut self, verb: &'static str, args: &str) -> Result<Vec<Vec<Tok>>, Failure> {
        self.tag += 1;
        let tag = format!("w{}", self.tag);
        let line = format!(
            "{tag} {verb}{}{args}\r\n",
            if args.is_empty() { "" } else { " " }
        );
        self.wr.write_all(line.as_bytes()).await?;
        let mut untagged = Vec::new();
        loop {
            let r = timeout(self.wait, self.response())
                .await
                .map_err(|_| timed_out())??;
            if r.first().is_some_and(|t| t.is(&tag)) {
                return if r.get(1).is_some_and(|t| t.is("OK")) {
                    Ok(untagged)
                } else {
                    Err(Failure::Refused(verb))
                };
            }
            untagged.push(r);
        }
    }

    async fn login(&mut self, p: &WatchParams, user: &str) -> Result<(), Failure> {
        if user.bytes().any(|b| b.is_ascii_control()) {
            return Err(Failure::Refused("AUTHENTICATE"));
        }
        // PLAIN (RFC 4616) with an initial response; Dovecot reads "<user>*<master>" as a master login.
        let plain = format!("\0{user}*{}\0{}", p.master_user, p.master_password.expose());
        let b64 = base64::engine::general_purpose::STANDARD.encode(plain);
        self.command("AUTHENTICATE", &format!("PLAIN {b64}"))
            .await?;
        let list = self.command("LIST", "\"\" \"\"").await?;
        if let Some(d) = list.iter().find_map(|r| list_delimiter(r)) {
            self.delimiter = d;
        }
        Ok(())
    }

    async fn poll(&mut self) -> Result<Snapshot, Failure> {
        let mut snap = Snapshot::new();
        for r in self.command("LIST", &POLL["LIST ".len()..]).await? {
            if let Some(d) = list_delimiter(&r) {
                self.delimiter = d;
            }
            if let Some(MailboxEvent::Changed { mailbox, state }) = parse_event(&r) {
                snap.insert(mailbox, state);
            }
        }
        Ok(snap)
    }
}

/// The hierarchy delimiter of a `* LIST (flags) "d" name` response; 0 for NIL (flat).
fn list_delimiter(toks: &[Tok]) -> Option<u8> {
    if !(toks.first()?.is("*") && toks.get(1)?.is("LIST")) {
        return None;
    }
    let close = toks.iter().position(|t| *t == Tok::Close)?;
    match toks.get(close + 1)? {
        Tok::Str(d) => d.bytes().next(),
        t if t.is("NIL") => Some(0),
        _ => None,
    }
}

/// Tells every session of `user` about the changes; raises those with notifications queued.
async fn report<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    user: &str,
    delimiter: u8,
    changes: &[(String, FolderChange)],
) {
    if changes.is_empty() {
        return;
    }
    for (id, signal) in srv.sessions.sessions_of(user) {
        let mut pending = false;
        for (mailbox, kind) in changes {
            pending |= srv
                .backend
                .folder_changed(id, mailbox.clone(), delimiter, *kind)
                .await;
        }
        if pending {
            signal.raise();
        }
    }
}

async fn watch_user<A: Authenticator, B: Backend>(
    srv: Arc<Server<A, B>>,
    p: Arc<WatchParams>,
    user: String,
    t: Timing,
    log: Log,
) {
    let mut snapshot: Option<Snapshot> = None;
    let mut backoff = t.backoff_min;
    while !srv.sessions.sessions_of(&user).is_empty() {
        let started = Instant::now();
        match watch_once(&srv, &p, &user, &t, &log, &mut snapshot).await {
            Ok(()) => return,
            Err(e) => log(format!(
                "IMAP watcher for {user}: {e}; retrying in {}s",
                backoff.as_secs_f32()
            )),
        }
        // A connection that lived long was not the reason to wait longer.
        if started.elapsed() >= t.backoff_max {
            backoff = t.backoff_min;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(t.backoff_max);
    }
}

/// One connection's life; Ok when the user has no session left.
async fn watch_once<A: Authenticator, B: Backend>(
    srv: &Server<A, B>,
    p: &WatchParams,
    user: &str,
    t: &Timing,
    log: &Log,
    snapshot: &mut Option<Snapshot>,
) -> Result<(), Failure> {
    let mut c = Conn::open(p, t.command).await?;
    c.login(p, user).await?;
    // Catches up with what changed while there was no connection.
    let fresh = c.poll().await?;
    if let Some(old) = snapshot.as_ref() {
        report(srv, user, c.delimiter, &diff(old, &fresh)).await;
    }
    let snap = snapshot.insert(fresh);
    match c.command("NOTIFY", &NOTIFY["NOTIFY ".len()..]).await {
        Ok(_) => {}
        Err(Failure::Refused(_)) => {
            log(format!(
                "IMAP watcher for {user}: NOTIFY refused, polling every {}s",
                t.poll.as_secs()
            ));
            loop {
                tokio::time::sleep(t.poll).await;
                if srv.sessions.sessions_of(user).is_empty() {
                    return Ok(());
                }
                let fresh = c.poll().await?;
                report(srv, user, c.delimiter, &diff(snap, &fresh)).await;
                *snap = fresh;
            }
        }
        Err(e) => return Err(e),
    }
    let mut pending: BTreeMap<String, String> = BTreeMap::new();
    let mut list_changed = false;
    let mut first: Option<Instant> = None;
    loop {
        let wait = first.map_or(t.idle_check, |f| {
            (f + t.coalesce).saturating_duration_since(Instant::now())
        });
        match timeout(wait, c.response()).await {
            Ok(r) => match parse_event(&r?) {
                Some(MailboxEvent::Changed { mailbox, state }) => {
                    pending.insert(mailbox, state);
                    first.get_or_insert_with(Instant::now);
                }
                Some(MailboxEvent::ListChanged) => {
                    list_changed = true;
                    first.get_or_insert_with(Instant::now);
                }
                None => {}
            },
            Err(_) => {
                if first.take().is_some() {
                    let changes = if std::mem::take(&mut list_changed) {
                        pending.clear();
                        let fresh = c.poll().await?;
                        let changes = diff(snap, &fresh);
                        *snap = fresh;
                        changes
                    } else {
                        let mut changes = Vec::new();
                        for (mailbox, state) in std::mem::take(&mut pending) {
                            if snap.get(&mailbox) != Some(&state) {
                                changes.push((mailbox.clone(), FolderChange::Modified));
                                snap.insert(mailbox, state);
                            }
                        }
                        changes
                    };
                    report(srv, user, c.delimiter, &changes).await;
                }
                if srv.sessions.sessions_of(user).is_empty() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Password;
    use crate::backend::Call;
    use crate::request::tests::{server, TestServer};
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    fn toks(line: &str) -> Vec<Tok> {
        let mut out = Vec::new();
        assert_eq!(lex(line.as_bytes(), &mut out), None);
        out
    }

    #[test]
    fn test_parse_status_event() {
        let ev = parse_event(&toks("* STATUS \"Lixo Eletr&APQ-nico\" (MESSAGES 3)"));
        assert_eq!(
            ev,
            Some(MailboxEvent::Changed {
                mailbox: "Lixo Eletr&APQ-nico".into(),
                state: "MESSAGES=3".into()
            })
        );
        // NOTIFY's STATUS and LIST-STATUS order items differently; the state compares equal.
        let a = parse_event(&toks(
            "* STATUS INBOX (MESSAGES 1 UIDNEXT 2 UIDVALIDITY 9 UNSEEN 1 HIGHESTMODSEQ 3)",
        ));
        let b = parse_event(&toks(
            "* STATUS INBOX (UNSEEN 1 MESSAGES 1 HIGHESTMODSEQ 3 UIDNEXT 2 UIDVALIDITY 9)",
        ));
        assert_eq!(a, b);
        assert_eq!(
            parse_event(&toks("* LIST (\\NonExistent) \"/\" Probe2")),
            Some(MailboxEvent::ListChanged)
        );
        assert_eq!(parse_event(&toks("* 3 EXISTS")), None);
        assert_eq!(
            list_delimiter(&toks("* LIST (\\Noselect) \".\" \"\"")),
            Some(b'.')
        );
        assert_eq!(
            list_delimiter(&toks("* LIST (\\Noselect) NIL \"\"")),
            Some(0)
        );
        let mut out = Vec::new();
        assert_eq!(lex(b"* STATUS {5}", &mut out), Some(5));
    }

    #[test]
    fn test_diff() {
        let old: Snapshot = [("INBOX".into(), "a".into()), ("Old".into(), "a".into())].into();
        let new: Snapshot = [("INBOX".into(), "b".into()), ("New".into(), "a".into())].into();
        let mut d = diff(&old, &new);
        d.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(
            d,
            [
                ("INBOX".to_owned(), FolderChange::Modified),
                ("New".to_owned(), FolderChange::Added),
                ("Old".to_owned(), FolderChange::Deleted)
            ]
        );
    }

    /// A scripted Dovecot: answers the watcher's commands from `mailboxes`, and NOTIFY with
    /// `notify_ok`; lines sent on `push` go to the client as they come.
    struct FakeImap {
        port: u16,
        mailboxes: Arc<Mutex<Vec<(String, String)>>>,
        commands: Arc<Mutex<Vec<String>>>,
        accepts: Arc<Mutex<Vec<Instant>>>,
        closed: Arc<tokio::sync::Notify>,
        push: mpsc::UnboundedSender<String>,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        NotifyOk,
        NotifyNo,
        AuthNo,
        Hangup,
    }

    /// The untagged lines and the tagged answer for one command.
    fn answer(
        mode: Mode,
        cmd: &str,
        mailboxes: &Mutex<Vec<(String, String)>>,
    ) -> (String, &'static str) {
        if cmd.starts_with("AUTHENTICATE") {
            (
                String::new(),
                if mode == Mode::AuthNo {
                    "NO denied"
                } else {
                    "OK in"
                },
            )
        } else if cmd == "LIST \"\" \"\"" {
            ("* LIST (\\Noselect) \"/\" \"\"\r\n".into(), "OK done")
        } else if cmd.starts_with("LIST") {
            let mut lines = String::new();
            for (name, state) in mailboxes.lock().unwrap().iter() {
                lines +=
                    &format!("* LIST () \"/\" \"{name}\"\r\n* STATUS \"{name}\" ({state})\r\n");
            }
            (lines, "OK done")
        } else if cmd.starts_with("NOTIFY") {
            (
                String::new(),
                if mode == Mode::NotifyNo {
                    "NO not here"
                } else {
                    "OK notifying"
                },
            )
        } else {
            (String::new(), "BAD what")
        }
    }

    async fn fake_imap(mode: Mode) -> FakeImap {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mailboxes = Arc::new(Mutex::new(vec![(
            "INBOX".to_owned(),
            "MESSAGES 1 UIDNEXT 2 UNSEEN 1 HIGHESTMODSEQ 1".to_owned(),
        )]));
        let commands = Arc::new(Mutex::new(Vec::new()));
        let accepts = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(tokio::sync::Notify::new());
        let (push, pushed) = mpsc::unbounded_channel::<String>();
        let pushed = Arc::new(tokio::sync::Mutex::new(pushed));
        let (m, cmds, acc, cl) = (
            mailboxes.clone(),
            commands.clone(),
            accepts.clone(),
            closed.clone(),
        );
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                acc.lock().unwrap().push(Instant::now());
                if mode == Mode::Hangup {
                    continue; // dropped: the client sees the connection close
                }
                let (rd, wr) = sock.into_split();
                let wr = Arc::new(tokio::sync::Mutex::new(wr));
                let pusher = {
                    let (wr, pushed) = (wr.clone(), pushed.clone());
                    tokio::spawn(async move {
                        while let Some(line) = pushed.lock().await.recv().await {
                            if wr.lock().await.write_all(line.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    })
                };
                let _ = wr.lock().await.write_all(b"* OK fake ready\r\n").await;
                let mut rd = BufReader::new(rd);
                let mut line = String::new();
                while rd.read_line(&mut line).await.unwrap_or(0) > 0 {
                    let (tag, cmd) = line.trim_end().split_once(' ').unwrap_or(("", ""));
                    cmds.lock().unwrap().push(cmd.to_owned());
                    let (untagged, tagged) = answer(mode, cmd, &m);
                    let reply = format!("{untagged}{tag} {tagged}\r\n");
                    line.clear();
                    if wr.lock().await.write_all(reply.as_bytes()).await.is_err() {
                        break;
                    }
                }
                pusher.abort();
                cl.notify_one();
            }
        });
        FakeImap {
            port,
            mailboxes,
            commands,
            accepts,
            closed,
            push,
        }
    }

    fn fast() -> Timing {
        Timing {
            coalesce: Duration::from_millis(300),
            poll: Duration::from_millis(200),
            backoff_min: Duration::from_millis(200),
            backoff_max: Duration::from_secs(2),
            idle_check: Duration::from_millis(200),
            command: Duration::from_secs(5),
        }
    }

    const SECRET: &str = "m4st3r-s3cret";

    /// A server whose backend points the watcher at `port`, the user's session, and the log.
    type Logs = Arc<Mutex<Vec<String>>>;

    fn watched(
        port: u16,
    ) -> (
        Arc<TestServer>,
        mpsc::UnboundedReceiver<String>,
        String,
        Logs,
    ) {
        let mut srv = server();
        *srv.backend.watch.lock().unwrap() = Some(WatchParams {
            host: "127.0.0.1".into(),
            port,
            master_user: "openchange".into(),
            master_password: Password::from(SECRET),
        });
        let (manager, rx) = WatchManager::new();
        srv.watch = manager;
        let h = srv
            .sessions
            .credential_hash("user", &Password::from("pass"));
        let cookie = srv.sessions.create("user", h, 1, std::time::Instant::now());
        (Arc::new(srv), rx, cookie, Arc::new(Mutex::new(Vec::new())))
    }

    fn start(srv: &Arc<TestServer>, rx: mpsc::UnboundedReceiver<String>, logs: &Logs) {
        let sink = logs.clone();
        let log: Log = Arc::new(move |l| sink.lock().unwrap().push(l));
        tokio::spawn(supervise(srv.clone(), rx, fast(), log));
        srv.watch.session_started("user");
    }

    fn changes(srv: &TestServer) -> Vec<(String, FolderChange)> {
        srv.backend
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter_map(|c| match c {
                Call::FolderChanged {
                    mailbox,
                    kind,
                    delimiter,
                    ..
                } => {
                    assert_eq!(*delimiter, b'/');
                    Some((mailbox.clone(), *kind))
                }
                _ => None,
            })
            .collect()
    }

    async fn until(what: &str, mut ok: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while !ok() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_watch_coalesces() {
        rt().block_on(async {
            let imap = fake_imap(Mode::NotifyOk).await;
            let (srv, rx, _, logs) = watched(imap.port);
            start(&srv, rx, &logs);
            until("NOTIFY", || {
                imap.commands
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|c| c.starts_with("NOTIFY"))
            })
            .await;
            tokio::time::sleep(Duration::from_millis(100)).await; // its OK is on the wire
                                                                  // Dovecot repeats the known state after NOTIFY SET: not a change.
            imap.push
                .send("* STATUS INBOX (MESSAGES 1 UIDNEXT 2 UNSEEN 1 HIGHESTMODSEQ 1)\r\n".into())
                .unwrap();
            for seq in 2..7 {
                imap.push
                    .send(format!(
                        "* STATUS INBOX (MESSAGES 1 UIDNEXT 2 UNSEEN 1 HIGHESTMODSEQ {seq})\r\n"
                    ))
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            until("a report", || !changes(&srv).is_empty()).await;
            tokio::time::sleep(Duration::from_millis(600)).await;
            assert_eq!(
                changes(&srv),
                [("INBOX".to_owned(), FolderChange::Modified)]
            );
            let signal = srv.sessions.sessions_of("user").pop().unwrap().1;
            assert!(
                signal.wait(Duration::ZERO).await,
                "the session's NotificationWait is woken"
            );
            // The state already reported again (Dovecot sends STATUS twice per flag change): nothing new.
            imap.push
                .send("* STATUS INBOX (MESSAGES 1 UIDNEXT 2 UNSEEN 1 HIGHESTMODSEQ 6)\r\n".into())
                .unwrap();
            tokio::time::sleep(Duration::from_millis(600)).await;
            assert_eq!(changes(&srv).len(), 1);
            // A new folder: LIST event, then LIST-STATUS finds it (INBOX as last reported).
            imap.mailboxes.lock().unwrap()[0].1 =
                "MESSAGES 1 UIDNEXT 2 UNSEEN 1 HIGHESTMODSEQ 6".into();
            imap.mailboxes.lock().unwrap().push((
                "Projects".into(),
                "MESSAGES 0 UIDNEXT 1 UNSEEN 0 HIGHESTMODSEQ 1".into(),
            ));
            imap.push
                .send("* LIST () \"/\" Projects\r\n".into())
                .unwrap();
            until("the new folder", || changes(&srv).len() == 2).await;
            assert_eq!(
                changes(&srv)[1],
                ("Projects".to_owned(), FolderChange::Added)
            );
        });
    }

    #[test]
    fn test_watch_falls_back_to_poll() {
        rt().block_on(async {
            let imap = fake_imap(Mode::NotifyNo).await;
            imap.mailboxes.lock().unwrap().push((
                "Old".into(),
                "MESSAGES 0 UIDNEXT 1 UNSEEN 0 HIGHESTMODSEQ 1".into(),
            ));
            let (srv, rx, _, logs) = watched(imap.port);
            start(&srv, rx, &logs);
            until("NOTIFY", || {
                imap.commands
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|c| c.starts_with("NOTIFY"))
            })
            .await;
            {
                let mut m = imap.mailboxes.lock().unwrap();
                m.retain(|(n, _)| n != "Old");
                m[0].1 = "MESSAGES 2 UIDNEXT 3 UNSEEN 2 HIGHESTMODSEQ 2".into();
                m.push((
                    "New".into(),
                    "MESSAGES 0 UIDNEXT 1 UNSEEN 0 HIGHESTMODSEQ 1".into(),
                ));
            }
            until("the poll's report", || changes(&srv).len() == 3).await;
            let mut got = changes(&srv);
            got.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(
                got,
                [
                    ("INBOX".to_owned(), FolderChange::Modified),
                    ("New".to_owned(), FolderChange::Added),
                    ("Old".to_owned(), FolderChange::Deleted)
                ]
            );
            assert!(
                imap.commands
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|c| c.contains("RETURN (STATUS"))
                    .count()
                    >= 2
            );
            assert!(logs
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("NOTIFY refused")));
        });
    }

    #[test]
    fn test_watch_reconnect_backoff() {
        rt().block_on(async {
            let imap = fake_imap(Mode::Hangup).await;
            let (srv, rx, _, logs) = watched(imap.port);
            start(&srv, rx, &logs);
            until("three attempts", || imap.accepts.lock().unwrap().len() >= 3).await;
            let a = imap.accepts.lock().unwrap().clone();
            assert!(
                a[1] - a[0] >= Duration::from_millis(200),
                "{:?}",
                a[1] - a[0]
            );
            assert!(
                a[2] - a[1] >= Duration::from_millis(400),
                "{:?}",
                a[2] - a[1]
            );
        });
    }

    #[test]
    fn test_watch_stops_with_last_session() {
        rt().block_on(async {
            let imap = fake_imap(Mode::NotifyOk).await;
            let (srv, rx, cookie, logs) = watched(imap.port);
            start(&srv, rx, &logs);
            until("NOTIFY", || {
                imap.commands
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|c| c.starts_with("NOTIFY"))
            })
            .await;
            let value = &crate::session::tests::cookie_of(&cookie)["MapiContext=".len()..];
            assert!(srv.sessions.remove(value).is_some());
            srv.watch.session_ended("user");
            timeout(Duration::from_secs(5), imap.closed.notified())
                .await
                .expect("the watcher hangs up");
            // A later Connect starts it again.
            let h = srv
                .sessions
                .credential_hash("user", &Password::from("pass"));
            srv.sessions.create("user", h, 2, std::time::Instant::now());
            srv.watch.session_started("user");
            until("a second login", || imap.accepts.lock().unwrap().len() == 2).await;
        });
    }

    #[test]
    fn test_password_not_logged() {
        rt().block_on(async {
            let imap = fake_imap(Mode::AuthNo).await;
            let (srv, rx, _, logs) = watched(imap.port);
            start(&srv, rx, &logs);
            until("two attempts", || imap.accepts.lock().unwrap().len() >= 2).await;
            let logs = logs.lock().unwrap();
            assert!(
                logs.iter().any(|l| l.contains("AUTHENTICATE refused")),
                "{logs:?}"
            );
            let b64 = base64::engine::general_purpose::STANDARD
                .encode(format!("\0user*openchange\0{SECRET}"));
            assert!(logs
                .iter()
                .all(|l| !l.contains(SECRET) && !l.contains(&b64)));
        });
    }
}

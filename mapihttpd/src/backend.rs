//! EMSMDB behind the MAPI/HTTP endpoints: the C library in production, a fake in tests.

use crate::auth::Password;
use crate::session::SessionId;
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::sync::Mutex;

/// MAPI status codes (MS-OXCDATA 2.4) the service produces itself.
pub const MAPI_E_LOGON_FAILED: u32 = 0x8004_0111;
pub const EC_RPC_FAILED: u32 = 0x8004_0115;

/// Connect request fields EMSMDB needs (MS-OXCMAPIHTTP 2.2.4.1.1).
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectParams {
    /// Account verified by Dovecot.
    pub username: String,
    /// The Basic password Dovecot verified; mapistore backends log in to other servers with it.
    pub password: Password,
    pub user_dn: String,
    pub flags: u32,
    pub code_page: u32,
    pub lcid_sort: u32,
    pub lcid_string: u32,
}

impl fmt::Debug for ConnectParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectParams")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("user_dn", &self.user_dn)
            .field("flags", &self.flags)
            .field("code_page", &self.code_page)
            .field("lcid_sort", &self.lcid_sort)
            .field("lcid_string", &self.lcid_string)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connected {
    pub id: SessionId,
    pub display_name: String,
    pub dn_prefix: String,
}

/// What happened to an IMAP mailbox (oc_emsmdb_folder_changed kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderChange {
    Modified = 0,
    Added = 1,
    Deleted = 2,
}

/// The loopback Dovecot and master login the IMAP backend uses (oc_emsmdb_imap_watch_params).
#[derive(Debug, Clone)]
pub struct WatchParams {
    pub host: String,
    pub port: u16,
    pub master_user: String,
    pub master_password: Password,
}

/// Errors are MAPI status codes for the response's ErrorCode field.
pub trait Backend: Send + Sync {
    fn connect(&self, req: ConnectParams) -> impl Future<Output = Result<Connected, u32>> + Send;
    fn execute(
        &self,
        id: SessionId,
        flags: u32,
        rop_in: Vec<u8>,
        max_out: usize,
    ) -> impl Future<Output = Result<Vec<u8>, u32>> + Send;
    fn disconnect(&self, id: SessionId) -> impl Future<Output = ()> + Send;
    /// An IMAP mailbox (modified UTF-7; `delimiter` 0 when flat) changed; true when the session
    /// now has notifications queued for its next Execute.
    fn folder_changed(
        &self,
        id: SessionId,
        mailbox: String,
        delimiter: u8,
        kind: FolderChange,
    ) -> impl Future<Output = bool> + Send;
    /// None when the IMAP backend is not configured.
    fn watch_params(&self) -> impl Future<Output = Option<WatchParams>> + Send;
    /// Asks the mapistore backends what other clients changed since the session's last poll; true when
    /// the session now has notifications queued for its next Execute.
    fn poll_changes(&self, id: SessionId) -> impl Future<Output = bool> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Connect(ConnectParams),
    Execute {
        id: SessionId,
        flags: u32,
        rop_in: Vec<u8>,
        max_out: usize,
    },
    Disconnect(SessionId),
    FolderChanged {
        id: SessionId,
        mailbox: String,
        delimiter: u8,
        kind: FolderChange,
    },
    PollChanges(SessionId),
}

/// Records every call; answers from the scripted queues, failing once they are empty.
#[derive(Default)]
pub struct FakeBackend {
    pub calls: Mutex<Vec<Call>>,
    pub connects: Mutex<VecDeque<Result<Connected, u32>>>,
    pub executes: Mutex<VecDeque<Result<Vec<u8>, u32>>>,
    /// What watch_params answers.
    pub watch: Mutex<Option<WatchParams>>,
    /// What poll_changes answers, in order; false once empty.
    pub polls: Mutex<VecDeque<bool>>,
}

impl FakeBackend {
    fn record(&self, call: Call) {
        self.calls.lock().unwrap().push(call);
    }
}

impl Backend for FakeBackend {
    async fn connect(&self, req: ConnectParams) -> Result<Connected, u32> {
        self.record(Call::Connect(req));
        let next = self.connects.lock().unwrap().pop_front();
        next.unwrap_or(Err(MAPI_E_LOGON_FAILED))
    }

    async fn execute(
        &self,
        id: SessionId,
        flags: u32,
        rop_in: Vec<u8>,
        max_out: usize,
    ) -> Result<Vec<u8>, u32> {
        self.record(Call::Execute {
            id,
            flags,
            rop_in,
            max_out,
        });
        let next = self.executes.lock().unwrap().pop_front();
        next.unwrap_or(Err(EC_RPC_FAILED))
    }

    async fn disconnect(&self, id: SessionId) {
        self.record(Call::Disconnect(id));
    }

    /// Every change leaves notifications pending.
    async fn folder_changed(
        &self,
        id: SessionId,
        mailbox: String,
        delimiter: u8,
        kind: FolderChange,
    ) -> bool {
        self.record(Call::FolderChanged {
            id,
            mailbox,
            delimiter,
            kind,
        });
        true
    }

    async fn watch_params(&self) -> Option<WatchParams> {
        self.watch.lock().unwrap().clone()
    }

    async fn poll_changes(&self, id: SessionId) -> bool {
        self.record(Call::PollChanges(id));
        let next = self.polls.lock().unwrap().pop_front();
        next.unwrap_or(false)
    }
}

/// Stands in for EMSMDB in builds without the C library: every Connect fails closed.
#[cfg(not(feature = "c-backend"))]
pub struct NoBackend;

#[cfg(not(feature = "c-backend"))]
impl Backend for NoBackend {
    async fn connect(&self, _req: ConnectParams) -> Result<Connected, u32> {
        Err(MAPI_E_LOGON_FAILED)
    }

    async fn execute(&self, _: SessionId, _: u32, _: Vec<u8>, _: usize) -> Result<Vec<u8>, u32> {
        Err(EC_RPC_FAILED)
    }

    async fn disconnect(&self, _id: SessionId) {}

    async fn folder_changed(&self, _: SessionId, _: String, _: u8, _: FolderChange) -> bool {
        false
    }

    async fn watch_params(&self) -> Option<WatchParams> {
        None
    }

    async fn poll_changes(&self, _: SessionId) -> bool {
        false
    }
}

#[cfg(feature = "c-backend")]
pub mod c {
    use super::{Backend, ConnectParams, Connected, FolderChange, WatchParams, EC_RPC_FAILED};
    use crate::ffi;
    use crate::session::SessionId;
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use tokio::sync::oneshot;

    /// liboc_emsmdb keeps process-wide state: one worker per process.
    static STARTED: AtomicBool = AtomicBool::new(false);

    enum Job {
        Connect(ConnectParams, oneshot::Sender<Result<Connected, u32>>),
        Execute {
            id: SessionId,
            flags: u32,
            rop_in: Vec<u8>,
            max_out: usize,
            reply: oneshot::Sender<Result<Vec<u8>, u32>>,
        },
        Disconnect(SessionId, oneshot::Sender<()>),
        FolderChanged {
            id: SessionId,
            mailbox: String,
            delimiter: u8,
            kind: FolderChange,
            reply: oneshot::Sender<bool>,
        },
        WatchParams(oneshot::Sender<Option<WatchParams>>),
        PollChanges(SessionId, oneshot::Sender<bool>),
    }

    /// One OS thread makes every C call and owns every C session handle.
    pub struct CBackend {
        jobs: mpsc::Sender<Job>,
    }

    impl CBackend {
        /// Starts the worker and runs `oc_emsmdb_init` on it; only the first call may succeed.
        pub fn start(smb_conf: CString) -> Result<Self, u32> {
            if STARTED.swap(true, Ordering::SeqCst) {
                return Err(EC_RPC_FAILED);
            }
            let (jobs, rx) = mpsc::channel();
            let (ready_tx, ready) = mpsc::channel();
            std::thread::Builder::new()
                .name("emsmdb".into())
                .spawn(move || {
                    let status = ffi::init(&smb_conf);
                    let _ = ready_tx.send(status);
                    if status == 0 {
                        worker(rx);
                    }
                })
                .map_err(|_| EC_RPC_FAILED)?;
            match ready.recv() {
                Ok(0) => Ok(CBackend { jobs }),
                Ok(status) => Err(status),
                Err(_) => Err(EC_RPC_FAILED),
            }
        }

        async fn ask<T>(&self, job: impl FnOnce(oneshot::Sender<T>) -> Job) -> Option<T> {
            let (tx, rx) = oneshot::channel();
            self.jobs.send(job(tx)).ok()?;
            rx.await.ok()
        }
    }

    /// A session whose Connect caller went away (client hung up) never reaches the session table,
    /// so nothing would disconnect it: drop it here, which forgets the user's password.
    fn reply_connect<S>(
        sessions: &mut HashMap<SessionId, S>,
        reply: oneshot::Sender<Result<Connected, u32>>,
        result: Result<Connected, u32>,
    ) {
        if let Err(Ok(c)) = reply.send(result) {
            sessions.remove(&c.id);
        }
    }

    fn worker(rx: mpsc::Receiver<Job>) {
        let mut sessions: HashMap<SessionId, ffi::Session> = HashMap::new();
        let mut next: SessionId = 0;
        for job in rx {
            match job {
                Job::Connect(req, reply) => {
                    let result = ffi::connect(&req).map(|(session, display_name, dn_prefix)| {
                        next += 1;
                        sessions.insert(next, session);
                        Connected {
                            id: next,
                            display_name,
                            dn_prefix,
                        }
                    });
                    reply_connect(&mut sessions, reply, result);
                }
                Job::Execute {
                    id,
                    flags,
                    rop_in,
                    max_out,
                    reply,
                } => {
                    let result = match sessions.get_mut(&id) {
                        Some(s) => s.execute(flags, &rop_in, max_out),
                        None => Err(EC_RPC_FAILED),
                    };
                    let _ = reply.send(result);
                }
                Job::Disconnect(id, reply) => {
                    sessions.remove(&id);
                    let _ = reply.send(());
                }
                Job::FolderChanged {
                    id,
                    mailbox,
                    delimiter,
                    kind,
                    reply,
                } => {
                    let pending = sessions
                        .get_mut(&id)
                        .is_some_and(|s| s.folder_changed(&mailbox, delimiter, kind as u32));
                    let _ = reply.send(pending);
                }
                Job::WatchParams(reply) => {
                    let _ = reply.send(ffi::watch_params());
                }
                Job::PollChanges(id, reply) => {
                    let pending = sessions.get_mut(&id).is_some_and(|s| s.poll_changes());
                    let _ = reply.send(pending);
                }
            }
        }
    }

    impl Backend for CBackend {
        async fn connect(&self, req: ConnectParams) -> Result<Connected, u32> {
            self.ask(|tx| Job::Connect(req, tx))
                .await
                .unwrap_or(Err(EC_RPC_FAILED))
        }

        async fn execute(
            &self,
            id: SessionId,
            flags: u32,
            rop_in: Vec<u8>,
            max_out: usize,
        ) -> Result<Vec<u8>, u32> {
            self.ask(|reply| Job::Execute {
                id,
                flags,
                rop_in,
                max_out,
                reply,
            })
            .await
            .unwrap_or(Err(EC_RPC_FAILED))
        }

        async fn disconnect(&self, id: SessionId) {
            self.ask(|tx| Job::Disconnect(id, tx)).await;
        }

        async fn folder_changed(
            &self,
            id: SessionId,
            mailbox: String,
            delimiter: u8,
            kind: FolderChange,
        ) -> bool {
            self.ask(|reply| Job::FolderChanged {
                id,
                mailbox,
                delimiter,
                kind,
                reply,
            })
            .await
            .unwrap_or(false)
        }

        async fn watch_params(&self) -> Option<WatchParams> {
            self.ask(Job::WatchParams).await.flatten()
        }

        async fn poll_changes(&self, id: SessionId) -> bool {
            self.ask(|reply| Job::PollChanges(id, reply))
                .await
                .unwrap_or(false)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;

        /// Counts drops, standing in for ffi::Session (whose drop runs oc_emsmdb_disconnect).
        struct Counted(Arc<AtomicUsize>);
        impl Drop for Counted {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn connected(id: SessionId) -> Result<Connected, u32> {
            Ok(Connected {
                id,
                display_name: String::new(),
                dn_prefix: String::new(),
            })
        }

        #[test]
        fn test_connect_caller_gone_disconnects() {
            let drops = Arc::new(AtomicUsize::new(0));
            let mut sessions = HashMap::new();
            sessions.insert(1, Counted(drops.clone()));
            sessions.insert(2, Counted(drops.clone()));

            let (tx, rx) = oneshot::channel();
            reply_connect(&mut sessions, tx, connected(1));
            assert!(rx.blocking_recv().unwrap().is_ok());
            assert!(sessions.contains_key(&1));

            // The client hung up while Connect was in flight: nobody will ever disconnect id 2.
            let (tx, rx) = oneshot::channel();
            drop(rx);
            reply_connect(&mut sessions, tx, connected(2));
            assert!(!sessions.contains_key(&2));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::tests::run;

    fn params() -> ConnectParams {
        ConnectParams {
            username: "user@example.invalid".into(),
            password: Password::from("s3cret-marker"),
            user_dn: "/o=example.invalid/cn=user".into(),
            flags: 0,
            code_page: 1252,
            lcid_sort: 1033,
            lcid_string: 1033,
        }
    }

    #[test]
    fn test_connect_params_debug_redacts() {
        let debug = format!("{:?}", params());
        assert!(debug.contains(r#"password: "<redacted>""#), "{debug}");
        assert!(!debug.contains("s3cret-marker"), "{debug}");
        assert!(debug.contains("user@example.invalid"), "{debug}");
    }

    #[test]
    fn test_fake_backend_records() {
        let fake = FakeBackend::default();
        let ok = Connected {
            id: 7,
            display_name: "User".into(),
            dn_prefix: "/O=EXAMPLE.INVALID".into(),
        };
        fake.connects.lock().unwrap().push_back(Ok(ok.clone()));
        fake.executes.lock().unwrap().push_back(Ok(vec![1, 2]));
        run(async {
            assert_eq!(fake.connect(params()).await, Ok(ok));
            assert_eq!(fake.connect(params()).await, Err(MAPI_E_LOGON_FAILED));
            assert_eq!(fake.execute(7, 1, vec![9], 64).await, Ok(vec![1, 2]));
            assert_eq!(fake.execute(7, 1, vec![9], 64).await, Err(EC_RPC_FAILED));
            fake.disconnect(7).await;
            assert!(
                fake.folder_changed(7, "INBOX".into(), b'/', FolderChange::Added)
                    .await
            );
            assert!(fake.watch_params().await.is_none());
            assert!(!fake.poll_changes(7).await);
        });
        let exec = Call::Execute {
            id: 7,
            flags: 1,
            rop_in: vec![9],
            max_out: 64,
        };
        assert_eq!(
            *fake.calls.lock().unwrap(),
            [
                Call::Connect(params()),
                Call::Connect(params()),
                exec.clone(),
                exec,
                Call::Disconnect(7),
                Call::FolderChanged {
                    id: 7,
                    mailbox: "INBOX".into(),
                    delimiter: b'/',
                    kind: FolderChange::Added
                },
                Call::PollChanges(7)
            ]
        );
    }
}

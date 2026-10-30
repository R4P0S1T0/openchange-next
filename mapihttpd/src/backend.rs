//! EMSMDB behind the MAPI/HTTP endpoints: the C library in production, a fake in tests.

use crate::session::SessionId;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Mutex;

/// MAPI status codes (MS-OXCDATA 2.4) the service produces itself.
pub const MAPI_E_LOGON_FAILED: u32 = 0x8004_0111;
pub const EC_RPC_FAILED: u32 = 0x8004_0115;

/// Connect request fields EMSMDB needs (MS-OXCMAPIHTTP 2.2.4.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectParams {
    /// Account verified by Dovecot.
    pub username: String,
    pub user_dn: String,
    pub flags: u32,
    pub code_page: u32,
    pub lcid_sort: u32,
    pub lcid_string: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connected {
    pub id: SessionId,
    pub display_name: String,
    pub dn_prefix: String,
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
}

/// Records every call; answers from the scripted queues, failing once they are empty.
#[derive(Default)]
pub struct FakeBackend {
    pub calls: Mutex<Vec<Call>>,
    pub connects: Mutex<VecDeque<Result<Connected, u32>>>,
    pub executes: Mutex<VecDeque<Result<Vec<u8>, u32>>>,
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
}

#[cfg(feature = "c-backend")]
pub mod c {
    use super::{Backend, ConnectParams, Connected, EC_RPC_FAILED};
    use crate::ffi;
    use crate::session::SessionId;
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::sync::mpsc;
    use tokio::sync::oneshot;

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
    }

    /// One OS thread makes every C call and owns every C session handle.
    pub struct CBackend {
        jobs: mpsc::Sender<Job>,
    }

    impl CBackend {
        /// Starts the worker and runs `oc_emsmdb_init` on it.
        pub fn start(smb_conf: CString) -> Result<Self, u32> {
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
                    let _ = reply.send(result);
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::tests::run;

    fn params() -> ConnectParams {
        ConnectParams {
            username: "user@example.invalid".into(),
            user_dn: "/o=example.invalid/cn=user".into(),
            flags: 0,
            code_page: 1252,
            lcid_sort: 1033,
            lcid_string: 1033,
        }
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
                Call::Disconnect(7)
            ]
        );
    }
}

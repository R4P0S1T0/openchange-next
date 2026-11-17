//! M6: every 60 s each EMSMDB session asks the backend what other clients changed (CardDAV address
//! books edited in webmail or on a phone); when that queued notifications, its NotificationWait returns.

use crate::auth::Authenticator;
use crate::backend::Backend;
use crate::request::Server;
use crate::session::{SessionId, SessionSignal};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval_at, Instant, MissedTickBehavior};

pub const POLL_EVERY: Duration = Duration::from_secs(60);

enum Msg {
    Start(SessionId, Arc<SessionSignal>),
    Stop(SessionId),
}

/// Starts and stops the per-session poll tasks; cheap to call on every Connect, Disconnect and expiry.
pub struct PollManager {
    tx: Option<mpsc::UnboundedSender<Msg>>,
}

pub struct PollReceiver(mpsc::UnboundedReceiver<Msg>);

impl PollManager {
    /// A manager and the receiver `supervise` runs on.
    pub fn new() -> (Self, PollReceiver) {
        let (tx, rx) = mpsc::unbounded_channel();
        (PollManager { tx: Some(tx) }, PollReceiver(rx))
    }

    /// Polls nothing (tests).
    #[cfg(test)]
    pub fn disabled() -> Self {
        PollManager { tx: None }
    }

    pub fn session_started(&self, id: SessionId, signal: Arc<SessionSignal>) {
        self.send(Msg::Start(id, signal));
    }

    pub fn session_ended(&self, id: SessionId) {
        self.send(Msg::Stop(id));
    }

    fn send(&self, msg: Msg) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(msg);
        }
    }
}

/// Runs one task per session: a poll every `every`, the first one `every` after the start.
pub async fn supervise<A, B>(srv: Arc<Server<A, B>>, rx: PollReceiver, every: Duration)
where
    A: Authenticator + 'static,
    B: Backend + 'static,
{
    let PollReceiver(mut rx) = rx;
    let mut running: HashMap<SessionId, tokio::task::JoinHandle<()>> = HashMap::new();
    while let Some(msg) = rx.recv().await {
        match msg {
            Msg::Start(id, signal) => {
                let srv = srv.clone();
                let task = tokio::spawn(async move {
                    let mut tick = interval_at(Instant::now() + every, every);
                    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    loop {
                        tick.tick().await;
                        // Through the backend's queue, so never inside an Execute of the session.
                        if srv.backend.poll_changes(id).await {
                            signal.raise();
                        }
                    }
                });
                if let Some(old) = running.insert(id, task) {
                    old.abort();
                }
            }
            Msg::Stop(id) => {
                if let Some(task) = running.remove(&id) {
                    task.abort();
                }
            }
        }
        running.retain(|_, t| !t.is_finished());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Call;
    use crate::request::tests::{server, TestServer};

    fn paused() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
    }

    fn polls(srv: &TestServer, id: SessionId) -> usize {
        let calls = srv.backend.calls.lock().unwrap();
        calls
            .iter()
            .filter(|c| **c == Call::PollChanges(id))
            .count()
    }

    fn started() -> (Arc<TestServer>, PollReceiver) {
        let (poll, rx) = PollManager::new();
        let mut srv = server();
        srv.poll = poll;
        (Arc::new(srv), rx)
    }

    #[test]
    fn test_poll_interval_calls_backend() {
        let (srv, rx) = started();
        paused().block_on(async {
            tokio::spawn(supervise(srv.clone(), rx, POLL_EVERY));
            srv.poll.session_started(7, Arc::default());
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(polls(&srv, 7), 0, "the first poll waits a full interval");
            tokio::time::sleep(POLL_EVERY).await;
            assert_eq!(polls(&srv, 7), 1);
            tokio::time::sleep(POLL_EVERY).await;
            assert_eq!(polls(&srv, 7), 2);
            srv.poll.session_ended(7);
            tokio::time::sleep(POLL_EVERY * 3).await;
            assert_eq!(polls(&srv, 7), 2);
        });
    }

    #[test]
    fn test_poll_pending_wakes_notification_wait() {
        let (srv, rx) = started();
        srv.backend.polls.lock().unwrap().push_back(true);
        let signal: Arc<SessionSignal> = Arc::default();
        let (woke, waited) = paused().block_on(async {
            tokio::spawn(supervise(srv.clone(), rx, POLL_EVERY));
            srv.poll.session_started(3, signal.clone());
            let t0 = Instant::now();
            let woke = signal.wait(Duration::from_secs(300)).await;
            (woke, t0.elapsed())
        });
        assert!(woke);
        assert!(
            waited >= POLL_EVERY && waited < POLL_EVERY * 2,
            "{waited:?}"
        );
        // Nothing new on the next poll: the next wait times out.
        let woke = paused().block_on(signal.wait(Duration::from_secs(1)));
        assert!(!woke);
    }
}

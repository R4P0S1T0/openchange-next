//! The only unsafe code: calls into liboc_emsmdb, declared by hand from
//! `mapiproxy/servers/default/emsmdb/oc_emsmdb.h` (change both in one commit).
//! Every call happens on the CBackend worker thread; C never calls back into Rust.
#![allow(unsafe_code)]

use std::ptr::NonNull;

/// Opaque `oc_emsmdb_session`.
#[repr(C)]
pub struct OcEmsmdbSession {
    _private: [u8; 0],
}

#[cfg(feature = "c-backend")]
pub use linked::{connect, init};

#[cfg(feature = "c-backend")]
mod linked {
    use super::{OcEmsmdbSession, Session};
    use crate::backend::{ConnectParams, EC_RPC_FAILED};
    use std::ffi::{c_char, CStr, CString};
    use std::ptr;

    const MAPI_E_INVALID_PARAMETER: u32 = 0x8007_0057;

    extern "C" {
        pub(super) fn oc_emsmdb_init(smb_conf_path: *const c_char) -> u32;
        pub(super) fn oc_emsmdb_connect(
            username: *const c_char,
            user_dn: *const c_char,
            flags: u32,
            code_page: u32,
            lcid_sort: u32,
            lcid_string: u32,
            session: *mut *mut OcEmsmdbSession,
            display_name: *mut *const c_char,
            dn_prefix: *mut *const c_char,
        ) -> u32;
        pub(super) fn oc_emsmdb_execute(
            session: *mut OcEmsmdbSession,
            flags: u32,
            rop_in: *const u8,
            rop_in_len: usize,
            rop_out: *mut u8,
            rop_out_cap: usize,
            rop_out_len: *mut usize,
        ) -> u32;
        pub(super) fn oc_emsmdb_disconnect(session: *mut OcEmsmdbSession);
    }

    pub fn init(smb_conf: &CStr) -> u32 {
        // SAFETY: smb_conf is a NUL-terminated string that outlives the call; C copies what it keeps.
        unsafe { oc_emsmdb_init(smb_conf.as_ptr()) }
    }

    /// Copies a string C lent from the session; "" for NULL.
    ///
    /// # Safety
    /// `p` is NULL or a NUL-terminated string valid for the duration of this call.
    unsafe fn copy(p: *const c_char) -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: guaranteed by the caller.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    /// Returns the session with its display name and DN prefix.
    pub fn connect(req: &ConnectParams) -> Result<(Session, String, String), u32> {
        let (Ok(username), Ok(user_dn)) = (
            CString::new(req.username.as_str()),
            CString::new(req.user_dn.as_str()),
        ) else {
            return Err(MAPI_E_INVALID_PARAMETER);
        };
        let mut raw: *mut OcEmsmdbSession = ptr::null_mut();
        let mut display_name: *const c_char = ptr::null();
        let mut dn_prefix: *const c_char = ptr::null();
        // SAFETY: the strings are NUL-terminated and outlive the call; the three out pointers
        // point at live locals of the declared types.
        let status = unsafe {
            oc_emsmdb_connect(
                username.as_ptr(),
                user_dn.as_ptr(),
                req.flags,
                req.code_page,
                req.lcid_sort,
                req.lcid_string,
                &mut raw,
                &mut display_name,
                &mut dn_prefix,
            )
        };
        // SAFETY: a non-NULL handle from connect is owned by us until oc_emsmdb_disconnect.
        let session = unsafe { Session::from_raw(raw, oc_emsmdb_disconnect) };
        // SAFETY: C sets both to NULL, a static "" or strings owned by the session, which is
        // still alive here and has had no call since connect.
        let names = unsafe { (copy(display_name), copy(dn_prefix)) };
        match (status, session) {
            (0, Some(s)) => Ok((s, names.0, names.1)),
            (0, None) => Err(EC_RPC_FAILED),
            (status, _) => Err(status),
        }
    }

    impl Session {
        /// Runs one ROP request frame; the reply is at most `max_out` (capped at 0x40000) bytes.
        pub fn execute(
            &mut self,
            flags: u32,
            rop_in: &[u8],
            max_out: usize,
        ) -> Result<Vec<u8>, u32> {
            let mut out = vec![0u8; max_out.min(0x40000)];
            let mut len = 0usize;
            // SAFETY: the handle is live (owned by self); rop_in is valid for rop_in.len() bytes
            // and out for out.len() writable bytes; C writes at most rop_out_cap bytes and
            // copies nothing it keeps from rop_in.
            let status = unsafe {
                oc_emsmdb_execute(
                    self.ptr.as_ptr(),
                    flags,
                    rop_in.as_ptr(),
                    rop_in.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut len,
                )
            };
            if status != 0 {
                return Err(status);
            }
            if len > out.len() {
                return Err(EC_RPC_FAILED);
            }
            out.truncate(len);
            Ok(out)
        }
    }
}

/// An `oc_emsmdb_session` handle; disconnects exactly once when dropped.
/// Not `Send` (NonNull): the handle never leaves the thread that created it.
pub struct Session {
    ptr: NonNull<OcEmsmdbSession>,
    disconnect: unsafe extern "C" fn(*mut OcEmsmdbSession),
}

impl Session {
    /// None for NULL.
    ///
    /// # Safety
    /// A non-NULL `ptr` must be a live handle that nothing else frees, and `disconnect` must
    /// free it.
    unsafe fn from_raw(
        ptr: *mut OcEmsmdbSession,
        disconnect: unsafe extern "C" fn(*mut OcEmsmdbSession),
    ) -> Option<Self> {
        NonNull::new(ptr).map(|ptr| Session { ptr, disconnect })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: from_raw's contract; drop runs once, so the handle is freed once.
        unsafe { (self.disconnect)(self.ptr.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DISCONNECTS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn count_disconnect(_: *mut OcEmsmdbSession) {
        DISCONNECTS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn test_session_drop_disconnects_once() {
        let mut handle = 0u8;
        let raw = (&mut handle as *mut u8).cast::<OcEmsmdbSession>();
        // SAFETY: count_disconnect never dereferences the handle.
        let session = unsafe { Session::from_raw(raw, count_disconnect) }.unwrap();
        // SAFETY: as above.
        assert!(unsafe { Session::from_raw(std::ptr::null_mut(), count_disconnect) }.is_none());
        assert_eq!(DISCONNECTS.load(Ordering::SeqCst), 0);
        drop(session);
        assert_eq!(DISCONNECTS.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "c-backend")]
    #[test]
    fn test_c_backend_calls() {
        use crate::backend::{c::CBackend, Backend, ConnectParams, EC_RPC_FAILED};
        use crate::request::tests::run;
        use std::ffi::CString;

        let conf = std::env::var("OC_EMSMDB_SMB_CONF")
            .expect("OC_EMSMDB_SMB_CONF names the test smb.conf (make check-mapihttp sets it)");
        let conf = CString::new(conf).unwrap();
        let req = ConnectParams {
            username: "user".into(),
            user_dn: "/o=example.invalid/cn=user".into(),
            flags: 0,
            code_page: 1252,
            lcid_sort: 1033,
            lcid_string: 1033,
        };
        // check-oc-emsmdb seeds the openchangedb this smb.conf names.
        assert_eq!(init(&conf), 0, "run make check-oc-emsmdb first");
        // SamDB is unavailable (decision 5): connect fails and keeps nothing.
        let failed = connect(&req).map(|_| ()).unwrap_err();
        assert_ne!(failed, 0);

        let (mut out, mut len) = ([0xEEu8; 16], 99usize);
        // SAFETY: NULL session is rejected before any buffer is touched; the buffers are valid.
        let status = unsafe {
            linked::oc_emsmdb_execute(
                std::ptr::null_mut(),
                0,
                out.as_ptr(),
                out.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
            )
        };
        assert_eq!((status, len), (EC_RPC_FAILED, 0));
        assert_eq!(out, [0xEE; 16]);
        // SAFETY: disconnecting NULL is a no-op.
        unsafe { linked::oc_emsmdb_disconnect(std::ptr::null_mut()) };

        // The same calls through the worker thread.
        let backend = CBackend::start(conf.clone()).unwrap_or_else(|s| panic!("init {s:#x}"));
        assert_eq!(CBackend::start(conf).err(), Some(EC_RPC_FAILED));
        run(async {
            assert_eq!(backend.connect(req).await, Err(failed));
            assert_eq!(
                backend.execute(1, 0, vec![0; 8], 64).await,
                Err(EC_RPC_FAILED)
            );
            backend.disconnect(1).await;
        });
    }
}

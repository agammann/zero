use crate::AppResult;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use std::ffi::c_void;
use std::io;
use std::ptr;
use zeroize::Zeroizing;

// A DPAPI blob in writable state is not a writer credential: another Windows
// user can create a machine-scope blob. CredRead uses this token's user store.
const TARGET: &str = "Zero/recovery-record-signing-key/v1";
const DOMAIN: &[u8] = b"zero-pending-recovery-v2\0";
const CRED_TYPE_GENERIC: u32 = 1;
const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
const ERROR_NOT_FOUND: i32 = 1168;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_ABANDONED: u32 = 0x80;

#[repr(C)]
struct Credential {
    flags: u32,
    kind: u32,
    target_name: *mut u16,
    comment: *mut u16,
    last_written: [u32; 2],
    blob_size: u32,
    blob: *mut u8,
    persist: u32,
    attribute_count: u32,
    attributes: *mut c_void,
    target_alias: *mut u16,
    user_name: *mut u16,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn CredReadW(target: *const u16, kind: u32, flags: u32, value: *mut *mut Credential) -> i32;
    fn CredWriteW(value: *const Credential, flags: u32) -> i32;
    fn CredFree(value: *mut c_void);
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateMutexW(attributes: *const c_void, initial_owner: i32, name: *const u16)
    -> *mut c_void;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn ReleaseMutex(handle: *mut c_void) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

struct CredentialLock(*mut c_void);

impl CredentialLock {
    fn acquire() -> AppResult<Self> {
        let name = format!(
            "Global\\Zero-Recovery-Credential-{}",
            crate::scheduler::current_sid()?
        );
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let handle = unsafe { CreateMutexW(ptr::null(), 0, wide.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        match unsafe { WaitForSingleObject(handle, 30_000) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(handle)),
            _ => {
                unsafe { CloseHandle(handle) };
                Err("could not acquire the recovery credential lock".into())
            }
        }
    }
}

impl Drop for CredentialLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

fn target_name() -> Vec<u16> {
    TARGET.encode_utf16().chain([0]).collect()
}

fn read_key() -> AppResult<Option<SigningKey>> {
    let mut value = ptr::null_mut();
    let target = target_name();
    let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut value) };
    if ok == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NOT_FOUND) {
            return Ok(None);
        }
        return Err(
            format!("could not read the current user's recovery credential: {error}").into(),
        );
    }
    if value.is_null() {
        return Err("Windows returned an empty recovery credential".into());
    }
    let result = (|| {
        let stored = unsafe { &*value };
        if stored.kind != CRED_TYPE_GENERIC
            || stored.persist != CRED_PERSIST_LOCAL_MACHINE
            || stored.blob_size != 32
            || stored.blob.is_null()
        {
            return Err("recovery credential has an unsupported format".into());
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(unsafe { std::slice::from_raw_parts(stored.blob, 32) });
        Ok(Some(SigningKey::from_bytes(&seed)))
    })();
    unsafe { CredFree(value.cast()) };
    result
}

fn create_key() -> AppResult<SigningKey> {
    let _lock = CredentialLock::acquire()?;
    if let Some(key) = read_key()? {
        return Ok(key);
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed)?;
    let mut target = target_name();
    let value = Credential {
        flags: 0,
        kind: CRED_TYPE_GENERIC,
        target_name: target.as_mut_ptr(),
        comment: ptr::null_mut(),
        last_written: [0, 0],
        blob_size: seed.len() as u32,
        blob: seed.as_mut_ptr(),
        persist: CRED_PERSIST_LOCAL_MACHINE,
        attribute_count: 0,
        attributes: ptr::null_mut(),
        target_alias: ptr::null_mut(),
        user_name: ptr::null_mut(),
    };
    if unsafe { CredWriteW(&value, 0) } == 0 {
        return Err(format!(
            "could not save the current user's recovery credential: {}",
            io::Error::last_os_error()
        )
        .into());
    }
    read_key()?.ok_or_else(|| "Windows did not retain the recovery credential".into())
}

fn message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + body.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(body);
    message
}

pub fn sign(body: &[u8]) -> AppResult<[u8; 64]> {
    Ok(create_key()?.sign(&message(body)).to_bytes())
}

pub fn verify(body: &[u8], signature: &[u8; 64]) -> AppResult<()> {
    let key =
        read_key()?.ok_or("recovery credential is unavailable; automatic recovery refused")?;
    key.verifying_key()
        .verify(&message(body), &Signature::from_bytes(signature))
        .map_err(|_| "recovery record authentication failed".into())
}

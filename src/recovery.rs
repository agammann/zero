use crate::AppResult;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::ptr;
use zeroize::Zeroizing;

// A DPAPI blob in writable state is not a writer credential: another Windows
// user can create a machine-scope blob. CredRead uses this token's user store.
const RECOVERY_TARGET: &str = "Zero/recovery-record-signing-key/v1";
const PENDING_DOMAIN: &[u8] = b"zero-pending-recovery-v2\0";
const CRED_TYPE_GENERIC: u32 = 1;
const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
const ERROR_NOT_FOUND: i32 = 1168;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_ABANDONED: u32 = 0x80;

// Only the current unit-test thread can opt into ephemeral signing keys. This
// avoids touching the operator's Credential Manager during loopback tests.
#[cfg(test)]
thread_local! {
    static TEST_KEYS: std::cell::RefCell<Option<(SigningKey, SigningKey)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_test_keys(keys: Option<(SigningKey, SigningKey)>) {
    TEST_KEYS.with(|current| *current.borrow_mut() = keys);
}

#[cfg(test)]
fn test_key(target: &str) -> Option<AppResult<Option<SigningKey>>> {
    TEST_KEYS.with(|current| {
        let keys = current.borrow();
        let (state, result) = keys.as_ref()?;
        Some(match target {
            RECOVERY_TARGET => Ok(Some(state.clone())),
            target if target.starts_with("Zero/receipt-result-signing-key/v1/") => {
                Ok(Some(result.clone()))
            }
            _ => Err("unexpected loopback credential target".into()),
        })
    })
}

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
                Err("could not acquire the signing credential lock".into())
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

fn target_name(target: &str) -> Vec<u16> {
    target.encode_utf16().chain([0]).collect()
}

fn read_key(target: &str) -> AppResult<Option<SigningKey>> {
    #[cfg(test)]
    if let Some(key) = test_key(target) {
        return key;
    }
    let mut value = ptr::null_mut();
    let wide_target = target_name(target);
    let ok = unsafe { CredReadW(wide_target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut value) };
    if ok == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NOT_FOUND) {
            return Ok(None);
        }
        return Err(
            format!("could not read the current user's signing credential: {error}").into(),
        );
    }
    if value.is_null() {
        return Err("Windows returned an empty signing credential".into());
    }
    let result = (|| {
        let stored = unsafe { &*value };
        if stored.kind != CRED_TYPE_GENERIC
            || stored.persist != CRED_PERSIST_LOCAL_MACHINE
            || stored.blob_size != 32
            || stored.blob.is_null()
        {
            return Err("signing credential has an unsupported format".into());
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(unsafe { std::slice::from_raw_parts(stored.blob, 32) });
        Ok(Some(SigningKey::from_bytes(&seed)))
    })();
    unsafe { CredFree(value.cast()) };
    result
}

fn create_key(target: &str) -> AppResult<SigningKey> {
    #[cfg(test)]
    if let Some(key) = test_key(target) {
        return key?.ok_or_else(|| "loopback credential unavailable".into());
    }
    let _lock = CredentialLock::acquire()?;
    if let Some(key) = read_key(target)? {
        return Ok(key);
    }
    write_key(target)
}

fn write_key(target: &str) -> AppResult<SigningKey> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed)?;
    let mut wide_target = target_name(target);
    let value = Credential {
        flags: 0,
        kind: CRED_TYPE_GENERIC,
        target_name: wide_target.as_mut_ptr(),
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
            "could not save the current user's signing credential: {}",
            io::Error::last_os_error()
        )
        .into());
    }
    read_key(target)?.ok_or_else(|| "Windows did not retain the signing credential".into())
}

fn receipt_target(state_dir: &Path) -> AppResult<String> {
    let identity = crate::state::directory_identity(state_dir)?;
    Ok(format!(
        "Zero/receipt-result-signing-key/v1/{:08x}-{:016x}-{:016x}",
        identity.volume, identity.index, identity.creation_time
    ))
}

pub fn receipt_key(state_dir: &Path) -> AppResult<SigningKey> {
    let target = receipt_target(state_dir)?;
    read_key(&target)?.ok_or_else(|| {
        "receipt/result signing credential is unavailable; initialize it explicitly after reviewing legacy keys".into()
    })
}

pub fn initialize_receipt_key(state_dir: &Path) -> AppResult<SigningKey> {
    let target = receipt_target(state_dir)?;
    let _lock = CredentialLock::acquire()?;
    if let Some(key) = read_key(&target)? {
        return Ok(key);
    }
    if state_dir.join("receipt-signing-key.dpapi").try_exists()?
        || state_dir.join("receipt-public-key.hex").try_exists()?
    {
        return Err("legacy receipt/result signing state requires operator-reviewed migration or explicit rotation; no key was imported or replaced".into());
    }
    write_key(&target)
}

fn message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + body.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    message
}

pub fn sign(body: &[u8]) -> AppResult<[u8; 64]> {
    sign_for(PENDING_DOMAIN, body)
}

pub fn verify(body: &[u8], signature: &[u8; 64]) -> AppResult<()> {
    verify_for(PENDING_DOMAIN, body, signature)
}

pub fn sign_for(domain: &[u8], body: &[u8]) -> AppResult<[u8; 64]> {
    Ok(create_key(RECOVERY_TARGET)?
        .sign(&message(domain, body))
        .to_bytes())
}

pub fn verify_for(domain: &[u8], body: &[u8], signature: &[u8; 64]) -> AppResult<()> {
    let key = read_key(RECOVERY_TARGET)?
        .ok_or("recovery credential is unavailable; automatic recovery refused")?;
    key.verifying_key()
        .verify(&message(domain, body), &Signature::from_bytes(signature))
        .map_err(|_| "state record authentication failed".into())
}

fn scoped_message(domain: &[u8], state_dir: &Path, label: &str, body: &[u8]) -> AppResult<Vec<u8>> {
    let identity = crate::state::directory_identity(state_dir)?;
    let label_size: u32 = label.len().try_into()?;
    let mut message = message(domain, &[]);
    message.extend_from_slice(&identity.volume.to_le_bytes());
    message.extend_from_slice(&identity.index.to_le_bytes());
    message.extend_from_slice(&identity.creation_time.to_le_bytes());
    message.extend_from_slice(&label_size.to_le_bytes());
    message.extend_from_slice(label.as_bytes());
    message.extend_from_slice(body);
    Ok(message)
}

pub fn sign_scoped(
    domain: &[u8],
    state_dir: &Path,
    label: &str,
    body: &[u8],
) -> AppResult<[u8; 64]> {
    Ok(create_key(RECOVERY_TARGET)?
        .sign(&scoped_message(domain, state_dir, label, body)?)
        .to_bytes())
}

pub fn verify_scoped(
    domain: &[u8],
    state_dir: &Path,
    label: &str,
    body: &[u8],
    signature: &[u8; 64],
) -> AppResult<()> {
    let key = read_key(RECOVERY_TARGET)?
        .ok_or("state authentication credential is unavailable; processing refused")?;
    key.verifying_key()
        .verify(
            &scoped_message(domain, state_dir, label, body)?,
            &Signature::from_bytes(signature),
        )
        .map_err(|_| "state record authentication failed".into())
}

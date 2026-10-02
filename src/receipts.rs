use crate::storage::StorageAssessment;
use crate::{AppResult, state_directory};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

#[repr(C)]
struct DataBlob {
    length: u32,
    data: *mut u8,
}

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CryptProtectData(
        input: *const DataBlob,
        description: *const u16,
        entropy: *const DataBlob,
        reserved: *mut c_void,
        prompt: *const c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
    fn CryptUnprotectData(
        input: *const DataBlob,
        description: *mut *mut u16,
        entropy: *const DataBlob,
        reserved: *mut c_void,
        prompt: *const c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 1;

fn dpapi(input: &[u8], protect: bool) -> AppResult<Zeroizing<Vec<u8>>> {
    let input_len: u32 = input.len().try_into()?;
    let source = DataBlob {
        length: input_len,
        data: input.as_ptr() as *mut u8,
    };
    let mut output = DataBlob {
        length: 0,
        data: std::ptr::null_mut(),
    };
    let ok = if protect {
        // Source and destination buffers remain valid until this synchronous Windows call returns.
        unsafe {
            CryptProtectData(
                &source,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    } else {
        unsafe {
            CryptUnprotectData(
                &source,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Windows owns the allocated output. Copy it into a zeroizing buffer before freeing it.
    let result = Zeroizing::new(unsafe {
        std::slice::from_raw_parts(output.data, output.length as usize).to_vec()
    });
    // Clear the DPAPI allocation before returning it to the Windows heap.
    unsafe { std::slice::from_raw_parts_mut(output.data, output.length as usize).zeroize() };
    unsafe { LocalFree(output.data.cast()) };
    Ok(result)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn unhex<const N: usize>(value: &str) -> AppResult<[u8; N]> {
    if value.len() != N * 2 {
        return Err("incorrect hexadecimal value length".into());
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("hexadecimal values must contain only ASCII hex digits".into());
    }
    let mut bytes = [0u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

pub(crate) fn signing_key(state_dir: &Path) -> AppResult<SigningKey> {
    fs::create_dir_all(state_dir)?;
    let path = state_dir.join("receipt-signing-key.dpapi");
    let secret = if path.try_exists()? {
        let protected = fs::read(&path)?;
        if protected.len() > 64 * 1024 {
            return Err("protected receipt key is too large".into());
        }
        dpapi(&protected, false)?
    } else {
        let mut generated = Zeroizing::new(vec![0u8; 32]);
        getrandom::fill(&mut generated)?;
        let protected = dpapi(&generated, true)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&protected)?;
        file.sync_all()?;
        generated
    };
    let array = Zeroizing::new(<[u8; 32]>::try_from(secret.as_slice())?);
    let key = SigningKey::from_bytes(&array);
    let public_path = state_dir.join("receipt-public-key.hex");
    let public = hex(&key.verifying_key().to_bytes());
    if public_path.try_exists()? {
        if fs::read_to_string(public_path)?.trim() != public {
            return Err("receipt public key does not match the protected signing key".into());
        }
    } else {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(public_path)?;
        file.write_all(public.as_bytes())?;
        file.sync_all()?;
    }
    Ok(key)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptBody {
    pub format_version: u8,
    pub app_version: String,
    pub completed_unix_seconds: u64,
    pub selected_path: String,
    pub original_bytes: u64,
    pub method: String,
    pub verification: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageAssessment>,
}

#[derive(Deserialize, Serialize)]
struct SignedReceipt {
    body: ReceiptBody,
    public_key: String,
    signature: String,
}

pub fn write_receipt(
    selected_path: &Path,
    original_bytes: u64,
    storage: &StorageAssessment,
    output: &Path,
) -> AppResult<PathBuf> {
    fs::create_dir_all(output)?;
    let state_dir = state_directory()?;
    let key = signing_key(&state_dir)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let body = ReceiptBody {
        format_version: 2,
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        completed_unix_seconds: now,
        selected_path: selected_path.to_string_lossy().into_owned(),
        original_bytes,
        method: "AES-256-GCM stage; encrypted logical readback; key clearing; one random overwrite; Windows deletion".to_owned(),
        verification: "authenticated stage, ciphertext readback, overwrite readback, selected path absent".to_owned(),
        storage: Some(storage.clone()),
    };
    let signature = key.sign(&serde_json::to_vec(&body)?);
    let record = SignedReceipt {
        body,
        public_key: hex(&key.verifying_key().to_bytes()),
        signature: hex(&signature.to_bytes()),
    };
    let mut id = [0u8; 12];
    getrandom::fill(&mut id)?;
    let path = output.join(format!("zero-{now}-{}.json", hex(&id)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    serde_json::to_writer_pretty(&mut file, &record)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(path)
}

pub fn verify_receipt(path: &Path, trusted_public_key: &str) -> AppResult<ReceiptBody> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > 64 * 1024 {
        return Err("receipt is too large".into());
    }
    let record: SignedReceipt = serde_json::from_reader(file)?;
    if !(1..=2).contains(&record.body.format_version)
        || (record.body.format_version == 1 && record.body.storage.is_some())
        || (record.body.format_version == 2 && record.body.storage.is_none())
        || record.public_key != trusted_public_key.trim()
    {
        return Err("receipt format or trusted public key does not match".into());
    }
    let public = VerifyingKey::from_bytes(&unhex::<32>(&record.public_key)?)?;
    let signature = Signature::from_bytes(&unhex::<64>(&record.signature)?);
    public.verify(&serde_json::to_vec(&record.body)?, &signature)?;
    Ok(record.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_records_reject_non_ascii_without_panicking() {
        assert_eq!(unhex::<2>("aB09").unwrap(), [0xab, 0x09]);
        assert!(unhex::<2>("abxz").is_err());
        assert!(unhex::<2>("abc").is_err());
        let malformed_key = format!("€{}", "0".repeat(61));
        let malformed_signature = format!("0€{}", "0".repeat(124));
        assert_eq!(malformed_key.len(), 64);
        assert_eq!(malformed_signature.len(), 128);
        assert!(unhex::<32>(&malformed_key).is_err());
        assert!(unhex::<64>(&malformed_signature).is_err());
    }

    #[test]
    fn dpapi_round_trip_and_receipt_tampering_check() {
        let protected = dpapi(b"secret round trip", true).unwrap();
        let recovered = dpapi(&protected, false).unwrap();
        assert_eq!(recovered.as_slice(), b"secret round trip");

        let state = state_directory().unwrap();
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).unwrap();
        let output = std::env::temp_dir().join(format!("zero-receipts-{}", hex(&id)));
        let receipt = write_receipt(
            Path::new("test-file.txt"),
            17,
            &StorageAssessment {
                kind: crate::storage::StorageKind::Unknown,
                file_system: None,
                shared_block_capable: None,
            },
            &output,
        )
        .unwrap();
        let trusted = fs::read_to_string(state.join("receipt-public-key.hex")).unwrap();
        assert_eq!(
            verify_receipt(&receipt, &trusted).unwrap().original_bytes,
            17
        );
        let original = fs::read_to_string(&receipt).unwrap();
        fs::write(&receipt, original.replace("17", "18")).unwrap();
        assert!(verify_receipt(&receipt, &trusted).is_err());
        fs::remove_dir_all(output).unwrap();
    }

    #[test]
    fn old_signed_receipts_still_verify() {
        let old_body = r#"{"format_version":1,"app_version":"0.4.0","completed_unix_seconds":42,"selected_path":"example.txt","original_bytes":17,"method":"old","verification":"old"}"#;
        let body: ReceiptBody = serde_json::from_str(old_body).unwrap();
        assert!(body.storage.is_none());
        assert_eq!(serde_json::to_string(&body).unwrap(), old_body);
        let key = SigningKey::from_bytes(&[31u8; 32]);
        let record = SignedReceipt {
            body,
            public_key: hex(&key.verifying_key().to_bytes()),
            signature: hex(&key.sign(old_body.as_bytes()).to_bytes()),
        };
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("zero-old-receipt-{}.json", hex(&random)));
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        let result = verify_receipt(&path, &record.public_key).unwrap();
        assert_eq!(result.original_bytes, 17);
        fs::remove_file(path).unwrap();
    }
}

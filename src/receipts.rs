use crate::recovery;
use crate::storage::StorageAssessment;
use crate::{AppResult, state_directory};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let key = recovery::receipt_key(state_dir)?;
    check_or_write_public_key(state_dir, &key)?;
    Ok(key)
}

pub fn initialize_signing_key(state_dir: &Path) -> AppResult<()> {
    fs::create_dir_all(state_dir)?;
    let key = recovery::initialize_receipt_key(state_dir)?;
    check_or_write_public_key(state_dir, &key)
}

fn check_or_write_public_key(state_dir: &Path, key: &SigningKey) -> AppResult<()> {
    let public_path = state_dir.join("receipt-public-key.hex");
    let public = hex(&key.verifying_key().to_bytes());
    if public_path.try_exists()? {
        if fs::read_to_string(public_path)?.trim() != public {
            return Err(
                "receipt public key does not match the current user's signing credential".into(),
            );
        }
    } else {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&public_path)
        {
            Ok(mut file) => {
                file.write_all(public.as_bytes())?;
                file.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if fs::read_to_string(public_path)?.trim() != public {
                    return Err(
                        "receipt public key does not match the current user's signing credential"
                            .into(),
                    );
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
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
    write_receipt_with_state(
        &state_directory()?,
        selected_path,
        original_bytes,
        storage,
        output,
    )
}

fn write_receipt_with_state(
    state_dir: &Path,
    selected_path: &Path,
    original_bytes: u64,
    storage: &StorageAssessment,
    output: &Path,
) -> AppResult<PathBuf> {
    let key = signing_key(state_dir)?;
    fs::create_dir_all(output)?;
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
    fn credential_backed_receipt_and_tampering_check() {
        let root = crate::tests::test_root("receipts");
        let state = root.join("state");
        let output = root.join("receipts");
        initialize_signing_key(&state).unwrap();
        let receipt = write_receipt_with_state(
            &state,
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
        fs::write(
            state.join("receipt-signing-key.dpapi"),
            b"untrusted legacy blob",
        )
        .unwrap();
        assert_eq!(
            signing_key(&state).unwrap().verifying_key().to_bytes(),
            unhex::<32>(trusted.trim()).unwrap()
        );
        fs::write(state.join("receipt-public-key.hex"), "00".repeat(32)).unwrap();
        assert!(signing_key(&state).is_err());
        fs::write(state.join("receipt-public-key.hex"), &trusted).unwrap();
        assert_eq!(
            verify_receipt(&receipt, &trusted).unwrap().original_bytes,
            17
        );
        let original = fs::read_to_string(&receipt).unwrap();
        fs::write(&receipt, original.replace("17", "18")).unwrap();
        assert!(verify_receipt(&receipt, &trusted).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_key_requires_explicit_review_before_initialization() {
        let root = crate::tests::test_root("legacy-receipt-key");
        fs::write(
            root.join("receipt-signing-key.dpapi"),
            b"synthetic legacy key",
        )
        .unwrap();
        fs::write(root.join("receipt-public-key.hex"), b"synthetic public key").unwrap();
        assert!(
            initialize_signing_key(&root)
                .unwrap_err()
                .to_string()
                .contains("legacy receipt/result signing state")
        );
        assert_eq!(
            fs::read(root.join("receipt-public-key.hex")).unwrap(),
            b"synthetic public key"
        );
        assert!(signing_key(&root).is_err());
        fs::remove_dir_all(root).unwrap();
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

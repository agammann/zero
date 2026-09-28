use crate::filters::FileFilters;
use crate::profiles;
use crate::receipts::{hex, signing_key, unhex, write_receipt};
use crate::{AppResult, FileIdentity, collect_selection, process_one_with_filter, state_directory};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const COMMAND_DOMAIN: &[u8] = b"zero-remote-command-v1\0";
const RESULT_DOMAIN: &[u8] = b"zero-remote-result-v1\0";

#[derive(Clone, Deserialize, Serialize)]
struct DeviceConfig {
    version: u8,
    device_id: String,
    queue: Vec<u16>,
    controller_public_key: String,
    allowed_profiles: Vec<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct CommandBody {
    version: u8,
    device_id: String,
    profile: String,
    nonce: String,
    issued_unix_seconds: u64,
}

#[derive(Deserialize, Serialize)]
struct SignedCommand {
    body: CommandBody,
    public_key: String,
    signature: String,
}

#[derive(Deserialize, Serialize)]
struct SnapshotFile {
    path: Vec<u16>,
    identity: FileIdentity,
}

#[derive(Deserialize, Serialize)]
struct Snapshot {
    version: u8,
    command: CommandBody,
    files: Vec<SnapshotFile>,
    receipt_directory: Option<Vec<u16>>,
    #[serde(default)]
    filters: FileFilters,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ResultBody {
    pub version: u8,
    pub device_id: String,
    pub profile: String,
    pub nonce: String,
    pub files_completed: usize,
    pub files_missing: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub files_skipped_filter: usize,
    pub completed_unix_seconds: u64,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Deserialize, Serialize)]
struct SignedResult {
    body: ResultBody,
    public_key: String,
    signature: String,
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn now() -> AppResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn signing_bytes<T: Serialize>(domain: &[u8], body: &T) -> AppResult<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(body)?);
    Ok(bytes)
}

fn read_limited<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> AppResult<T> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > limit {
        return Err(format!("remote record is too large: {}", path.display()).into());
    }
    Ok(serde_json::from_reader(file)?)
}

fn write_new<T: Serialize>(path: &Path, value: &T) -> AppResult<()> {
    fs::create_dir_all(path.parent().ok_or("record has no parent directory")?)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn config_path(state_dir: &Path) -> PathBuf {
    state_dir.join("remote-device.json")
}

fn load_config(state_dir: &Path) -> AppResult<DeviceConfig> {
    let config: DeviceConfig = read_limited(&config_path(state_dir), 64 * 1024)?;
    if config.version != 1
        || !safe_name(&config.device_id)
        || config.allowed_profiles.is_empty()
        || config.allowed_profiles.iter().any(|name| !safe_name(name))
        || config.queue.is_empty()
    {
        return Err("remote device configuration is invalid".into());
    }
    let _ = unhex::<32>(&config.controller_public_key)?;
    Ok(config)
}

pub fn export_public_key(path: &Path) -> AppResult<()> {
    let key = signing_key(&state_directory()?)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(hex(&key.verifying_key().to_bytes()).as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub fn enroll(
    device_id: &str,
    queue: &Path,
    controller_key_path: &Path,
    allowed: &[String],
) -> AppResult<()> {
    if !safe_name(device_id) || allowed.is_empty() || allowed.iter().any(|name| !safe_name(name)) {
        return Err("device ID and allowed profile names must use 1-48 letters, digits, hyphens, or underscores".into());
    }
    for profile in allowed {
        let _ = profiles::load(profile)?;
    }
    let controller_public_key = fs::read_to_string(controller_key_path)?.trim().to_owned();
    let _ = unhex::<32>(&controller_public_key)?;
    let queue = std::path::absolute(queue)?;
    fs::create_dir_all(queue.join(device_id).join("pending"))?;
    fs::create_dir_all(queue.join(device_id).join("results"))?;
    let config = DeviceConfig {
        version: 1,
        device_id: device_id.to_owned(),
        queue: queue.as_os_str().encode_wide().collect(),
        controller_public_key,
        allowed_profiles: allowed.to_vec(),
    };
    let state = state_directory()?;
    fs::create_dir_all(&state)?;
    write_new(&config_path(&state), &config)?;
    if let Err(error) = install_agent(device_id) {
        let _ = fs::remove_file(config_path(&state));
        return Err(error);
    }
    Ok(())
}

fn task_name(device_id: &str) -> String {
    format!("Zero-Agent-{device_id}")
}

fn install_agent(device_id: &str) -> AppResult<()> {
    let executable = std::env::current_exe()?;
    let action = format!("\"{}\" --quiet --agent", executable.display());
    let output = Command::new("schtasks.exe")
        .args([
            "/Create",
            "/F",
            "/SC",
            "MINUTE",
            "/MO",
            "1",
            "/RL",
            "LIMITED",
            "/TN",
            &task_name(device_id),
            "/TR",
            &action,
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Task Scheduler could not install the remote agent: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

pub fn remove_agent() -> AppResult<()> {
    let state = state_directory()?;
    let config = load_config(&state)?;
    let output = Command::new("schtasks.exe")
        .args(["/Delete", "/F", "/TN", &task_name(&config.device_id)])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Task Scheduler could not remove the remote agent: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    fs::remove_file(config_path(&state))?;
    Ok(())
}

pub fn send(queue: &Path, device_id: &str, profile: &str) -> AppResult<String> {
    if !safe_name(device_id) || !safe_name(profile) {
        return Err("invalid device ID or profile name".into());
    }
    let key = signing_key(&state_directory()?)?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)?;
    let nonce = hex(&random);
    let body = CommandBody {
        version: 1,
        device_id: device_id.to_owned(),
        profile: profile.to_owned(),
        nonce: nonce.clone(),
        issued_unix_seconds: now()?,
    };
    let signature = key.sign(&signing_bytes(COMMAND_DOMAIN, &body)?);
    let command = SignedCommand {
        body,
        public_key: hex(&key.verifying_key().to_bytes()),
        signature: hex(&signature.to_bytes()),
    };
    write_new(
        &queue
            .join(device_id)
            .join("pending")
            .join(format!("cmd-{nonce}.json")),
        &command,
    )?;
    Ok(nonce)
}

fn verify_command(command: &SignedCommand, config: &DeviceConfig) -> AppResult<()> {
    if command.body.version != 1
        || command.body.device_id != config.device_id
        || !config.allowed_profiles.contains(&command.body.profile)
        || command.public_key != config.controller_public_key
        || command.body.nonce.len() != 32
    {
        return Err("remote command is outside this device's enrollment".into());
    }
    let _ = unhex::<16>(&command.body.nonce)?;
    let public = VerifyingKey::from_bytes(&unhex::<32>(&command.public_key)?)?;
    let signature = Signature::from_bytes(&unhex::<64>(&command.signature)?);
    public.verify(&signing_bytes(COMMAND_DOMAIN, &command.body)?, &signature)?;
    Ok(())
}

fn snapshot(command: &CommandBody, queue: &Path) -> AppResult<Snapshot> {
    let profile = profiles::load(&command.profile)?;
    let paths: Vec<PathBuf> = profile
        .paths
        .into_iter()
        .filter(|path| path.exists())
        .collect();
    let (files, folders, _) = collect_selection(&paths, Some(&profile.filters), false)?;
    let queue_name = fs::canonicalize(queue)?.to_string_lossy().to_lowercase();
    if folders.iter().any(|folder| {
        let folder_name = fs::canonicalize(folder)
            .unwrap_or_else(|_| folder.clone())
            .to_string_lossy()
            .to_lowercase();
        queue_name == folder_name
            || queue_name.starts_with(&format!("{}\\", folder_name.trim_end_matches('\\')))
    }) {
        return Err("remote queue is inside a selected folder".into());
    }
    if let Some(directory) = &profile.receipt_directory {
        let receipt_name = std::path::absolute(directory)?
            .to_string_lossy()
            .to_lowercase();
        if folders.iter().any(|folder| {
            let folder_name = folder.to_string_lossy().to_lowercase();
            receipt_name == folder_name
                || receipt_name.starts_with(&format!("{}\\", folder_name.trim_end_matches('\\')))
        }) {
            return Err("receipt directory must be outside selected folders".into());
        }
    }
    let mut captured = Vec::with_capacity(files.len());
    for selected in files {
        captured.push(SnapshotFile {
            path: selected.path.as_os_str().encode_wide().collect(),
            identity: selected.identity,
        });
    }
    Ok(Snapshot {
        version: 2,
        command: command.clone(),
        files: captured,
        receipt_directory: profile
            .receipt_directory
            .map(|path| path.as_os_str().encode_wide().collect()),
        filters: profile.filters,
    })
}

fn process_snapshot(snapshot: &Snapshot) -> AppResult<(usize, usize, usize)> {
    if !(1..=2).contains(&snapshot.version)
        || (snapshot.version == 1 && snapshot.filters != FileFilters::default())
        || snapshot.files.len() > 100_000
    {
        return Err("remote snapshot format is unsupported".into());
    }
    snapshot.filters.validate()?;
    let mut completed = 0;
    let mut missing = 0;
    let mut skipped_filter = 0;
    for selected in &snapshot.files {
        let path = PathBuf::from(OsString::from_wide(&selected.path));
        if !path.try_exists()? {
            missing += 1;
            continue;
        }
        let bytes = process_one_with_filter(&path, selected.identity, Some(&snapshot.filters))?;
        if let Some(bytes) = bytes {
            if let Some(directory) = &snapshot.receipt_directory {
                write_receipt(&path, bytes, &PathBuf::from(OsString::from_wide(directory)))?;
            }
            completed += 1;
        } else {
            skipped_filter += 1;
        }
    }
    Ok((completed, missing, skipped_filter))
}

fn result_for(
    snapshot: &Snapshot,
    completed: usize,
    missing: usize,
    skipped_filter: usize,
) -> AppResult<SignedResult> {
    let key = signing_key(&state_directory()?)?;
    let body = ResultBody {
        version: 1,
        device_id: snapshot.command.device_id.clone(),
        profile: snapshot.command.profile.clone(),
        nonce: snapshot.command.nonce.clone(),
        files_completed: completed,
        files_missing: missing,
        files_skipped_filter: skipped_filter,
        completed_unix_seconds: now()?,
    };
    let signature = key.sign(&signing_bytes(RESULT_DOMAIN, &body)?);
    Ok(SignedResult {
        body,
        public_key: hex(&key.verifying_key().to_bytes()),
        signature: hex(&signature.to_bytes()),
    })
}

fn verify_signed_result(result: &SignedResult, trusted_key: &str) -> AppResult<()> {
    if result.body.version != 1 || result.public_key != trusted_key.trim() {
        return Err("remote result is not signed by the trusted device key".into());
    }
    let public = VerifyingKey::from_bytes(&unhex::<32>(&result.public_key)?)?;
    let signature = Signature::from_bytes(&unhex::<64>(&result.signature)?);
    public.verify(&signing_bytes(RESULT_DOMAIN, &result.body)?, &signature)?;
    Ok(())
}

pub fn poll_once() -> AppResult<usize> {
    let state = state_directory()?;
    fs::create_dir_all(&state)?;
    let _agent_lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(state.join("agent.lock"))
    {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(32) => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let config = load_config(&state)?;
    let queue = PathBuf::from(OsString::from_wide(&config.queue));
    let pending = queue.join(&config.device_id).join("pending");
    let results = queue.join(&config.device_id).join("results");
    fs::create_dir_all(&pending)?;
    fs::create_dir_all(&results)?;
    let mut commands = fs::read_dir(&pending)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    commands.sort();
    let mut processed = 0;
    for path in commands {
        let command: SignedCommand = read_limited(&path, 64 * 1024)?;
        verify_command(&command, &config)?;
        if path.file_name().and_then(|name| name.to_str())
            != Some(&format!("cmd-{}.json", command.body.nonce))
        {
            return Err("remote command filename does not match its signed nonce".into());
        }
        let working = state
            .join("remote-working")
            .join(format!("{}.json", command.body.nonce));
        let done = state
            .join("remote-done")
            .join(format!("{}.json", command.body.nonce));
        let signed_result = if done.try_exists()? {
            let result: SignedResult = read_limited(&done, 64 * 1024)?;
            let local_key = signing_key(&state)?;
            verify_signed_result(&result, &hex(&local_key.verifying_key().to_bytes()))?;
            if result.body.nonce != command.body.nonce
                || result.body.device_id != config.device_id
                || result.body.profile != command.body.profile
            {
                return Err("completed remote job does not match the command".into());
            }
            result
        } else {
            let captured: Snapshot = if working.try_exists()? {
                read_limited(&working, 16 * 1024 * 1024)?
            } else {
                let captured = snapshot(&command.body, &queue)?;
                if serde_json::to_vec(&captured)?.len() > 16 * 1024 * 1024 {
                    return Err("remote snapshot exceeds the recovery size limit".into());
                }
                write_new(&working, &captured)?;
                captured
            };
            if captured.command != command.body {
                return Err("remote recovery snapshot does not match the signed command".into());
            }
            let (completed, missing, skipped_filter) = process_snapshot(&captured)?;
            let result = result_for(&captured, completed, missing, skipped_filter)?;
            write_new(&done, &result)?;
            fs::remove_file(working)?;
            result
        };
        let result_path = results.join(format!("result-{}.json", command.body.nonce));
        if result_path.try_exists()? {
            let existing: SignedResult = read_limited(&result_path, 64 * 1024)?;
            if existing.body.nonce != signed_result.body.nonce
                || existing.public_key != signed_result.public_key
                || existing.signature != signed_result.signature
            {
                return Err("remote result path contains conflicting data".into());
            }
        } else {
            write_new(&result_path, &signed_result)?;
        }
        fs::remove_file(path)?;
        processed += 1;
    }
    Ok(processed)
}

pub fn verify_result(path: &Path, trusted_public_key_path: &Path) -> AppResult<ResultBody> {
    let trusted = fs::read_to_string(trusted_public_key_path)?;
    let result: SignedResult = read_limited(path, 64 * 1024)?;
    verify_signed_result(&result, &trusted)?;
    Ok(result.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_names_and_signatures_are_scoped() {
        assert!(safe_name("laptop_1"));
        assert!(!safe_name("../other"));
        let secret = [19u8; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let config = DeviceConfig {
            version: 1,
            device_id: "laptop_1".to_owned(),
            queue: vec![1],
            controller_public_key: hex(&key.verifying_key().to_bytes()),
            allowed_profiles: vec!["private".to_owned()],
        };
        let body = CommandBody {
            version: 1,
            device_id: "laptop_1".to_owned(),
            profile: "private".to_owned(),
            nonce: "aa".repeat(16),
            issued_unix_seconds: 1,
        };
        let signature = key.sign(&signing_bytes(COMMAND_DOMAIN, &body).unwrap());
        let mut command = SignedCommand {
            body,
            public_key: config.controller_public_key.clone(),
            signature: hex(&signature.to_bytes()),
        };
        verify_command(&command, &config).unwrap();
        command.body.profile = "other".to_owned();
        assert!(verify_command(&command, &config).is_err());
    }

    #[test]
    fn old_signed_results_still_verify() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let old_body = r#"{"version":1,"device_id":"target","profile":"clean","nonce":"job","files_completed":2,"files_missing":0,"completed_unix_seconds":42}"#;
        let mut signed_bytes = RESULT_DOMAIN.to_vec();
        signed_bytes.extend_from_slice(old_body.as_bytes());
        let signature = key.sign(&signed_bytes);
        let result = SignedResult {
            body: serde_json::from_str(old_body).unwrap(),
            public_key: hex(&key.verifying_key().to_bytes()),
            signature: hex(&signature.to_bytes()),
        };
        assert_eq!(result.body.files_skipped_filter, 0);
        verify_signed_result(&result, &result.public_key).unwrap();
    }
}

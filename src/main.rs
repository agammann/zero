#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(not(windows))]
compile_error!("Zero currently supports Windows only.");

mod profiles;
mod receipts;
mod remote;

use aes_gcm::{Aes256Gcm, Nonce, aead::AeadInOut, aead::KeyInit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ZEROFMT2";
const CHUNK_SIZE: usize = 1024 * 1024;
const TAG_SIZE: usize = 16;

type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() {
    let quiet = env::args_os().nth(1).is_some_and(|arg| arg == "--quiet");
    match run() {
        Ok(()) => {
            if quiet && let Ok(dir) = state_directory() {
                let _ = fs::remove_file(dir.join("last-error.txt"));
            }
        }
        Err(error) => {
            if quiet {
                if let Ok(dir) = state_directory() {
                    let _ = fs::create_dir_all(&dir);
                    let _ = fs::write(dir.join("last-error.txt"), error.to_string());
                }
            } else {
                show_dialog("Zero", &format!("Operation stopped:\n\n{error}"));
            }
            std::process::exit(1);
        }
    }
}

fn run() -> AppResult<()> {
    let mut args = env::args_os().skip(1).peekable();
    let quiet = args.peek().is_some_and(|arg| arg == "--quiet");
    if quiet {
        args.next();
    }
    if args.peek().is_some_and(|arg| arg == "--verify-receipt") {
        args.next();
        let path = PathBuf::from(args.next().ok_or("receipt path is required")?);
        let public_key_path =
            PathBuf::from(args.next().ok_or("trusted public key path is required")?);
        if args.next().is_some() {
            return Err("too many receipt verification arguments".into());
        }
        let key = fs::read_to_string(public_key_path)?;
        let body = receipts::verify_receipt(&path, &key)?;
        if !quiet {
            show_dialog(
                "Zero",
                &format!(
                    "Receipt signature is valid.\n\nSelected path: {}\nOriginal bytes: {}\nCompleted at Unix time: {}\n\nThis verifies the record's signature, not physical media erasure.",
                    body.selected_path, body.original_bytes, body.completed_unix_seconds
                ),
            );
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--export-key") {
        args.next();
        let path = PathBuf::from(args.next().ok_or("public key export path is required")?);
        if args.next().is_some() {
            return Err("too many key export arguments".into());
        }
        remote::export_public_key(&path)?;
        if !quiet {
            show_dialog(
                "Zero",
                &format!(
                    "Public key exported to {}. Keep this file's origin verifiable when transferring it to a device.",
                    path.display()
                ),
            );
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--enroll") {
        args.next();
        let device = args.next().ok_or("device ID is required")?;
        let queue = PathBuf::from(args.next().ok_or("shared queue directory is required")?);
        let controller_key = PathBuf::from(
            args.next()
                .ok_or("controller public key path is required")?,
        );
        let allowed: Vec<String> = args
            .map(|arg| {
                arg.into_string()
                    .map_err(|_| "profile names must be Unicode")
            })
            .collect::<Result<_, _>>()?;
        let device = device.to_str().ok_or("device ID must be Unicode")?;
        remote::enroll(device, &queue, &controller_key, &allowed)?;
        if !quiet {
            show_dialog(
                "Zero",
                &format!(
                    "Device {device} enrolled for {} saved profile(s). A one-minute Windows task now checks the shared queue for authenticated jobs.",
                    allowed.len()
                ),
            );
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--remove-agent") {
        args.next();
        if args.next().is_some() {
            return Err("too many agent removal arguments".into());
        }
        remote::remove_agent()?;
        if !quiet {
            show_dialog("Zero", "Remote agent schedule and enrollment removed.");
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--agent") {
        args.next();
        if args.next().is_some() {
            return Err("too many remote agent arguments".into());
        }
        recover_pending_jobs(&state_directory()?)?;
        let count = remote::poll_once()?;
        if !quiet {
            show_dialog(
                "Zero",
                &format!("Processed {count} authenticated remote job(s)."),
            );
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--send") {
        args.next();
        let queue = PathBuf::from(args.next().ok_or("shared queue directory is required")?);
        let device = args.next().ok_or("device ID is required")?;
        let profile = args.next().ok_or("profile name is required")?;
        if args.next().is_some() {
            return Err("too many remote send arguments".into());
        }
        let device = device.to_str().ok_or("device ID must be Unicode")?;
        let profile = profile.to_str().ok_or("profile name must be Unicode")?;
        let nonce = remote::send(&queue, device, profile)?;
        if !quiet {
            show_dialog(
                "Zero",
                &format!(
                    "Signed job queued for {device}.\n\nProfile: {profile}\nJob ID: {nonce}\n\nDelivery depends on the shared queue reaching the enrolled device."
                ),
            );
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--verify-result") {
        args.next();
        let result = PathBuf::from(args.next().ok_or("remote result path is required")?);
        let public_key = PathBuf::from(
            args.next()
                .ok_or("trusted device public key path is required")?,
        );
        if args.next().is_some() {
            return Err("too many result verification arguments".into());
        }
        let body = remote::verify_result(&result, &public_key)?;
        if !quiet {
            show_dialog(
                "Zero",
                &format!(
                    "Authenticated result for {}.\n\nJob ID: {}\nProfile: {}\nFiles completed: {}\nFiles missing on retry: {}\nCompleted at Unix time: {}\n\nThis verifies the signed app result, not physical media erasure.",
                    body.device_id,
                    body.nonce,
                    body.profile,
                    body.files_completed,
                    body.files_missing,
                    body.completed_unix_seconds
                ),
            );
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--create-profile") {
        args.next();
        let name = args.next().ok_or("profile name is required")?;
        let name = name.to_str().ok_or("profile name must be Unicode")?;
        let receipt_dir = if args.peek().is_some_and(|arg| arg == "--receipts") {
            args.next();
            Some(PathBuf::from(
                args.next().ok_or("receipt directory is required")?,
            ))
        } else {
            None
        };
        let selected: Vec<PathBuf> = args.map(PathBuf::from).collect();
        let _ = collect_selection(&selected)?;
        let path = profiles::create(name, &selected, receipt_dir.as_deref())?;
        if !quiet {
            show_dialog(
                "Zero",
                &format!(
                    "Profile {name} saved at {}.\n\nNothing was deleted. Schedule or run this profile when ready.",
                    path.display()
                ),
            );
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--schedule") {
        args.next();
        let name = args.next().ok_or("profile name is required")?;
        let cadence = args.next().ok_or("schedule cadence is required")?;
        let time = args.next().ok_or("schedule time is required")?;
        if args.next().is_some() {
            return Err("too many schedule arguments".into());
        }
        let name = name.to_str().ok_or("profile name must be Unicode")?;
        let cadence = cadence.to_str().ok_or("cadence must be Unicode")?;
        let time = time.to_str().ok_or("time must be Unicode")?;
        profiles::schedule(name, cadence, time)?;
        if !quiet {
            show_dialog(
                "Zero",
                &format!("Profile {name} scheduled: {cadence} at {time}."),
            );
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--unschedule") {
        args.next();
        let name = args.next().ok_or("profile name is required")?;
        if args.next().is_some() {
            return Err("too many unschedule arguments".into());
        }
        let name = name.to_str().ok_or("profile name must be Unicode")?;
        profiles::unschedule(name)?;
        if !quiet {
            show_dialog("Zero", &format!("Profile {name} is no longer scheduled."));
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--profiles") {
        args.next();
        if args.next().is_some() {
            return Err("too many profile-list arguments".into());
        }
        if !quiet {
            let names = profiles::list()?;
            show_dialog(
                "Zero",
                &format!(
                    "Saved profiles:\n\n{}",
                    if names.is_empty() {
                        "(none)".to_owned()
                    } else {
                        names.join("\n")
                    }
                ),
            );
        }
        return Ok(());
    }
    if args.peek().is_some_and(|arg| arg == "--volume") {
        return Err(
            "whole-volume selection is not supported; drag specific files or folders".into(),
        );
    }
    let mut from_profile = false;
    let (sources, receipt_dir) = if args.peek().is_some_and(|arg| arg == "--profile") {
        args.next();
        let name = args.next().ok_or("profile name is required")?;
        if args.next().is_some() {
            return Err("too many profile-run arguments".into());
        }
        let name = name.to_str().ok_or("profile name must be Unicode")?;
        from_profile = true;
        profiles::load(name)?
    } else {
        let receipt_dir = if args.peek().is_some_and(|arg| arg == "--receipts") {
            args.next();
            Some(PathBuf::from(
                args.next().ok_or("receipt directory is required")?,
            ))
        } else {
            None
        };
        (args.map(PathBuf::from).collect(), receipt_dir)
    };
    recover_pending_jobs(&state_directory()?)?;
    let sources: Vec<PathBuf> = if from_profile {
        sources.into_iter().filter(|path| path.exists()).collect()
    } else {
        sources
    };
    if sources.is_empty() {
        if !quiet {
            show_dialog(
                "Zero",
                "Drag files or folders onto this executable in Windows Explorer.\n\nEach selected file is encrypted on disk with AES-256-GCM, verified, and then its working key is cleared. The file is overwritten and deleted. Nothing is retained after success. There is no confirmation prompt.",
            );
        }
        return Ok(());
    }
    if sources.len() > 32 {
        return Err("select at most 32 files or folders per drop".into());
    }
    let (files, folders) = collect_selection(&sources)?;
    if let Some(dir) = &receipt_dir {
        let absolute = std::path::absolute(dir)?;
        let receipt_name = absolute.to_string_lossy().to_lowercase();
        if folders.iter().any(|folder| {
            receipt_name.starts_with(&format!("{}\\", folder.to_string_lossy().to_lowercase()))
                || receipt_name == folder.to_string_lossy().to_lowercase()
        }) {
            return Err("receipt directory must be outside selected folders".into());
        }
    }

    for (index, selected) in files.iter().enumerate() {
        let original_bytes = process_one_with_identity(&selected.path, selected.identity).map_err(|error| {
            format!(
                "{}: {error}\n\n{} earlier file(s) completed. This file may be partly encrypted or overwritten if the error occurred after staging.",
                selected.path.display(), index
            )
        })?;
        if let Some(dir) = &receipt_dir {
            receipts::write_receipt(&selected.path, original_bytes, dir)?;
        }
    }
    if !from_profile {
        for folder in folders.iter().rev() {
            fs::remove_dir(folder)?;
        }
    }
    if !quiet {
        show_dialog(
            "Zero",
            &format!(
                "Processed {} selected file(s).\n\nNo encrypted files or keys were retained. The selected originals were overwritten and deleted. Backups, snapshots, and old storage blocks may remain.",
                files.len()
            ),
        );
    }
    Ok(())
}

struct SelectedFile {
    path: PathBuf,
    identity: FileIdentity,
}

fn collect_selection(sources: &[PathBuf]) -> AppResult<(Vec<SelectedFile>, Vec<PathBuf>)> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
    const MAX_FILES: usize = 100_000;

    let mut files = Vec::new();
    let mut folders = Vec::new();
    let mut seen = HashSet::new();
    let state_dir = state_directory()?;
    fs::create_dir_all(&state_dir)?;
    let protected = [state_dir, env::current_exe()?]
        .into_iter()
        .map(|path| {
            fs::canonicalize(&path)
                .or_else(|_| std::path::absolute(&path))
                .map(|path| path.to_string_lossy().to_lowercase())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut pending: Vec<PathBuf> = sources
        .iter()
        .rev()
        .map(std::path::absolute)
        .collect::<Result<_, _>>()?;
    while let Some(path) = pending.pop() {
        for ancestor in path.ancestors() {
            let attributes = fs::symlink_metadata(ancestor)?.file_attributes();
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(format!("reparse points are refused: {}", ancestor.display()).into());
            }
        }
        let metadata = fs::symlink_metadata(&path)?;
        let attributes = metadata.file_attributes();
        if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE) != 0 {
            return Err(format!("unsupported path: {}", path.display()).into());
        }
        let canonical = fs::canonicalize(&path)?;
        let identity = canonical.to_string_lossy().to_lowercase();
        if protected.iter().any(|protected_path| {
            identity == *protected_path
                || (metadata.is_dir()
                    && protected_path
                        .starts_with(&format!("{}\\", identity.trim_end_matches('\\'))))
        }) {
            return Err(format!(
                "Zero's executable or state directory is inside the selection: {}",
                path.display()
            )
            .into());
        }
        if !seen.insert(identity) {
            continue;
        }
        if metadata.is_dir() {
            if canonical.parent().is_none() || attributes & FILE_ATTRIBUTE_SYSTEM != 0 {
                return Err(format!(
                    "system and volume-root folders are refused: {}",
                    path.display()
                )
                .into());
            }
            folders.push(path.clone());
            let mut children = fs::read_dir(&path)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<Result<Vec<_>, _>>()?;
            children.sort();
            pending.extend(children.into_iter().rev());
        } else if metadata.is_file() {
            let inspected = open_for_destroy(&path)?;
            let identity = file_identity(&inspected)?;
            drop(inspected);
            files.push(SelectedFile { path, identity });
            if files.len() > MAX_FILES {
                return Err("selection exceeds 100,000 files".into());
            }
        } else {
            return Err(format!(
                "only ordinary files and folders are supported: {}",
                path.display()
            )
            .into());
        }
    }
    folders.sort_by_key(|path| path.components().count());
    Ok((files, folders))
}

fn process_one_with_identity(source: &Path, expected: FileIdentity) -> AppResult<u64> {
    let mut file = open_for_destroy(source)?;
    if file_identity(&file)? != expected {
        return Err(format!("selected file changed: {}", source.display()).into());
    }
    let original_bytes = file.metadata()?.len();
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key)?;
    let (mut stage, stage_path) = create_encrypted_stage(source)?;
    encrypt_stream(&mut file, &mut stage, &key)?;
    stage.sync_all()?;
    verify_encrypted_stage(&mut stage, &mut file, &key)?;
    let journal = PendingJournal::create(source, &file, &stage_path, &stage, &state_directory()?)?;
    replace_source_with_ciphertext(&mut file, &mut stage)?;
    key.zeroize();
    drop(stage);
    if stage_path.try_exists()? {
        return Err("temporary encrypted file was not removed".into());
    }
    overwrite_and_delete(file, source)?;
    journal.complete()?;
    Ok(original_bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FileIdentity {
    volume: u32,
    index: u64,
    creation_time: u64,
}

#[derive(Deserialize, Serialize)]
struct PendingOperation {
    version: u8,
    source: Vec<u16>,
    source_identity: FileIdentity,
    stage: Vec<u16>,
    stage_identity: FileIdentity,
}

struct PendingJournal {
    path: PathBuf,
}

impl PendingJournal {
    fn create(
        source: &Path,
        source_file: &File,
        stage: &Path,
        stage_file: &File,
        state_dir: &Path,
    ) -> AppResult<Self> {
        fs::create_dir_all(state_dir)?;
        let operation = PendingOperation {
            version: 1,
            source: source.as_os_str().encode_wide().collect(),
            source_identity: file_identity(source_file)?,
            stage: stage.as_os_str().encode_wide().collect(),
            stage_identity: file_identity(stage_file)?,
        };
        let encoded = serde_json::to_vec(&operation)?;
        for _ in 0..8 {
            let mut id = [0u8; 16];
            getrandom::fill(&mut id)?;
            let name: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = state_dir.join(format!("pending-{name}.json"));
            let opened = OpenOptions::new().write(true).create_new(true).open(&path);
            match opened {
                Ok(mut file) => {
                    file.write_all(&encoded)?;
                    file.sync_all()?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("could not choose a unique recovery record name".into())
    }

    fn complete(self) -> AppResult<()> {
        fs::remove_file(self.path)?;
        Ok(())
    }
}

fn state_directory() -> AppResult<PathBuf> {
    let appdata = env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is unavailable")?;
    Ok(PathBuf::from(appdata).join("Zero"))
}

fn recover_pending_jobs(state_dir: &Path) -> AppResult<()> {
    if !state_dir.try_exists()? {
        return Ok(());
    }
    let mut records = fs::read_dir(state_dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    records.sort();
    for record_path in records {
        if record_path
            .extension()
            .is_none_or(|extension| extension != "json")
            || record_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| !name.starts_with("pending-"))
        {
            continue;
        }
        let record_file = File::open(&record_path)?;
        if record_file.metadata()?.len() > 64 * 1024 {
            return Err(format!("recovery record is too large: {}", record_path.display()).into());
        }
        let operation: PendingOperation = serde_json::from_reader(record_file)?;
        if operation.version != 1 || operation.source.is_empty() || operation.stage.is_empty() {
            return Err("recovery record has an unsupported format".into());
        }
        let source = PathBuf::from(std::ffi::OsString::from_wide(&operation.source));
        let stage = PathBuf::from(std::ffi::OsString::from_wide(&operation.stage));
        if source.try_exists()? {
            let file = open_for_destroy(&source)?;
            if file_identity(&file)? != operation.source_identity {
                return Err(format!(
                    "selected file changed before recovery: {}",
                    source.display()
                )
                .into());
            }
            overwrite_and_delete(file, &source)?;
        }
        if stage.try_exists()? {
            let file = open_for_destroy(&stage)?;
            if file_identity(&file)? != operation.stage_identity {
                return Err(format!(
                    "encrypted stage changed before recovery: {}",
                    stage.display()
                )
                .into());
            }
            drop(file);
            fs::remove_file(&stage)?;
        }
        fs::remove_file(&record_path)?;
    }
    Ok(())
}

fn create_encrypted_stage(source: &Path) -> AppResult<(File, PathBuf)> {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    let parent = source.parent().unwrap_or_else(|| Path::new("."));
    for _ in 0..8 {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id)?;
        let name: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = parent.join(format!(".zero-stage-{name}.tmp"));
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
            .share_mode(0)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(&path);
        match opened {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err("could not choose a unique temporary file name".into())
}

fn show_dialog(title: &str, message: &str) {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(
            window: *mut c_void,
            text: *const u16,
            caption: *const u16,
            kind: u32,
        ) -> i32;
    }
    let title: Vec<u16> = title.encode_utf16().chain([0]).collect();
    let message: Vec<u16> = message.encode_utf16().chain([0]).collect();
    // Both buffers are valid, NUL-terminated UTF-16 for the duration of this call.
    unsafe { MessageBoxW(std::ptr::null_mut(), message.as_ptr(), title.as_ptr(), 0x40) };
}

fn open_for_destroy(source: &Path) -> AppResult<File> {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const UNSUPPORTED_ATTRIBUTES: u32 = 0x0040_0000 // recall on data access
        | 0x0004_0000 // recall on open
        | 0x0000_4000 // EFS encryption
        | 0x0000_1000 // offline
        | 0x0000_0800 // compressed
        | 0x0000_0400 // reparse point
        | 0x0000_0200; // sparse

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(source)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & UNSUPPORTED_ATTRIBUTES != 0 {
        return Err("this file type is not supported for cleanup".into());
    }
    if hard_link_count(&file)? != 1 {
        return Err("files with another hard link are refused".into());
    }
    Ok(file)
}

#[repr(C)]
struct FileInfo {
    _attributes: u32,
    creation_time: [u32; 2],
    _access_time: [u32; 2],
    _write_time: [u32; 2],
    volume_serial: u32,
    _size_high: u32,
    _size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}

fn file_info(file: &File) -> AppResult<FileInfo> {
    use std::mem::MaybeUninit;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(handle: *mut c_void, info: *mut FileInfo) -> i32;
    }
    let mut info = MaybeUninit::<FileInfo>::uninit();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { info.assume_init() })
}

fn hard_link_count(file: &File) -> AppResult<u32> {
    Ok(file_info(file)?.links)
}

fn file_identity(file: &File) -> AppResult<FileIdentity> {
    let info = file_info(file)?;
    Ok(FileIdentity {
        volume: info.volume_serial,
        index: ((info.index_high as u64) << 32) | info.index_low as u64,
        creation_time: ((info.creation_time[1] as u64) << 32) | info.creation_time[0] as u64,
    })
}

fn encrypt_stream<W: Write>(input: &mut File, output: &mut W, key: &[u8; 32]) -> AppResult<()> {
    input.seek(SeekFrom::Start(0))?;
    let metadata = input.metadata()?;
    if !metadata.is_file() {
        return Err("source is not a regular file".into());
    }
    let chunks = metadata.len().div_ceil(CHUNK_SIZE as u64);
    if chunks > u32::MAX as u64 {
        return Err("source is too large for the encryption format".into());
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid AES-256 key")?;
    let mut prefix = [0u8; 8];
    getrandom::fill(&mut prefix)?;
    let mut header = [0u8; 28];
    header[..8].copy_from_slice(MAGIC);
    header[8..16].copy_from_slice(&prefix);
    header[16..24].copy_from_slice(&metadata.len().to_be_bytes());
    header[24..28].copy_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
    output.write_all(&header)?;

    let mut buffer = Zeroizing::new(Vec::<u8>::with_capacity(CHUNK_SIZE + TAG_SIZE));
    let mut remaining = metadata.len();
    for index in 0..chunks {
        let length = remaining.min(CHUNK_SIZE as u64) as usize;
        buffer.resize(length, 0);
        input.read_exact(&mut buffer[..length])?;
        let nonce: Nonce<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize> =
            nonce_for(&prefix, index as u32).into();
        let aad = frame_aad(&header, index as u32, false);
        cipher
            .encrypt_in_place(&nonce, &aad, &mut *buffer)
            .map_err(|_| "AES-256-GCM encryption failed")?;
        output.write_all(&(buffer.len() as u32).to_be_bytes())?;
        output.write_all(&buffer)?;
        buffer.as_mut_slice().zeroize();
        buffer.clear();
        remaining -= length as u64;
    }
    let mut extra = [0u8; 1];
    if input.read(&mut extra)? != 0 {
        return Err("source changed during encryption".into());
    }
    let final_nonce: Nonce<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize> =
        nonce_for(&prefix, chunks as u32).into();
    let final_aad = frame_aad(&header, chunks as u32, true);
    let mut final_frame = Zeroizing::new(Vec::with_capacity(TAG_SIZE));
    cipher
        .encrypt_in_place(&final_nonce, &final_aad, &mut *final_frame)
        .map_err(|_| "final AES-256-GCM authentication failed")?;
    output.write_all(&(final_frame.len() as u32).to_be_bytes())?;
    output.write_all(&final_frame)?;
    Ok(())
}

fn nonce_for(prefix: &[u8; 8], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn frame_aad(header: &[u8; 28], index: u32, final_frame: bool) -> [u8; 33] {
    let mut aad = [0u8; 33];
    aad[..28].copy_from_slice(header);
    aad[28..32].copy_from_slice(&index.to_be_bytes());
    aad[32] = u8::from(final_frame);
    aad
}

fn verify_encrypted_stage(stage: &mut File, source: &mut File, key: &[u8; 32]) -> AppResult<()> {
    stage.seek(SeekFrom::Start(0))?;
    source.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 28];
    stage.read_exact(&mut header)?;
    if &header[..8] != MAGIC || u32::from_be_bytes(header[24..28].try_into()?) != CHUNK_SIZE as u32
    {
        return Err("encrypted file header is invalid".into());
    }
    let prefix: [u8; 8] = header[8..16].try_into()?;
    let original_len = u64::from_be_bytes(header[16..24].try_into()?);
    if original_len != source.metadata()?.len() {
        return Err("source size changed during encryption".into());
    }
    let chunks = original_len.div_ceil(CHUNK_SIZE as u64);
    if chunks > u32::MAX as u64 {
        return Err("source is too large for the encryption format".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid AES-256 key")?;
    let mut remaining = original_len;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + TAG_SIZE));
    let mut expected = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    for index in 0..chunks {
        let length = remaining.min(CHUNK_SIZE as u64) as usize;
        let frame_len = u32::from_be_bytes(read_four(stage)?) as usize;
        if frame_len != length + TAG_SIZE {
            return Err("encrypted file frame length is invalid".into());
        }
        plaintext.resize(frame_len, 0);
        stage.read_exact(&mut plaintext)?;
        let nonce: Nonce<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize> =
            nonce_for(&prefix, index as u32).into();
        cipher
            .decrypt_in_place(
                &nonce,
                &frame_aad(&header, index as u32, false),
                &mut *plaintext,
            )
            .map_err(|_| "encrypted file authentication failed")?;
        source.read_exact(&mut expected[..length])?;
        if *plaintext != expected[..length] {
            return Err("encrypted file does not match the selected original".into());
        }
        plaintext.as_mut_slice().zeroize();
        plaintext.clear();
        expected[..length].zeroize();
        remaining -= length as u64;
    }
    let final_len = u32::from_be_bytes(read_four(stage)?) as usize;
    if final_len != TAG_SIZE {
        return Err("encrypted file final frame is invalid".into());
    }
    let mut final_frame = Zeroizing::new(vec![0u8; TAG_SIZE]);
    stage.read_exact(&mut final_frame)?;
    let final_nonce: Nonce<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize> =
        nonce_for(&prefix, chunks as u32).into();
    cipher
        .decrypt_in_place(
            &final_nonce,
            &frame_aad(&header, chunks as u32, true),
            &mut *final_frame,
        )
        .map_err(|_| "encrypted file final authentication failed")?;
    let mut extra = [0u8; 1];
    if stage.read(&mut extra)? != 0 || source.read(&mut extra)? != 0 {
        return Err("file changed during encrypted verification".into());
    }
    Ok(())
}

fn read_four(file: &mut File) -> AppResult<[u8; 4]> {
    let mut bytes = [0u8; 4];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn replace_source_with_ciphertext(source: &mut File, stage: &mut File) -> AppResult<()> {
    stage.seek(SeekFrom::Start(0))?;
    source.seek(SeekFrom::Start(0))?;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut staged_hash = Sha256::new();
    let mut copied = 0u64;
    loop {
        let count = stage.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        staged_hash.update(&buffer[..count]);
        source.write_all(&buffer[..count])?;
        copied += count as u64;
    }
    source.set_len(copied)?;
    source.sync_all()?;
    source.seek(SeekFrom::Start(0))?;
    let mut readback_hash = Sha256::new();
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        readback_hash.update(&buffer[..count]);
    }
    if source.metadata()?.len() != copied || staged_hash.finalize() != readback_hash.finalize() {
        return Err("encrypted readback did not match the on-disk stage".into());
    }
    Ok(())
}

fn overwrite_and_delete(mut file: File, source: &Path) -> AppResult<()> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetFileInformationByHandle(
            handle: *mut c_void,
            class: u32,
            info: *const u8,
            length: u32,
        ) -> i32;
    }

    let length = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let mut random = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut written_hash = Sha256::new();
    let mut remaining = length;
    while remaining > 0 {
        let size = remaining.min(CHUNK_SIZE as u64) as usize;
        getrandom::fill(&mut random[..size])?;
        written_hash.update(&random[..size]);
        file.write_all(&random[..size])?;
        remaining -= size as u64;
    }
    file.sync_all()?;
    random.zeroize();

    file.seek(SeekFrom::Start(0))?;
    let mut readback = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut read_hash = Sha256::new();
    remaining = length;
    while remaining > 0 {
        let size = remaining.min(CHUNK_SIZE as u64) as usize;
        file.read_exact(&mut readback[..size])?;
        read_hash.update(&readback[..size]);
        remaining -= size as u64;
    }
    if written_hash.finalize() != read_hash.finalize() {
        return Err("logical readback did not match the overwrite".into());
    }
    let disposition = 1u8;
    // This handle has DELETE access; Windows removes the file when it closes.
    let marked = unsafe { SetFileInformationByHandle(file.as_raw_handle(), 4, &disposition, 1) };
    if marked == 0 {
        return Err(io::Error::last_os_error().into());
    }
    drop(file);
    if source.try_exists()? {
        return Err("Windows did not remove the selected file".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(label: &str) -> PathBuf {
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).unwrap();
        let name: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = env::temp_dir().join(format!("zero-{label}-{name}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn aes_256_gcm_round_trip_for_multiple_chunks() {
        let root = test_root("crypto");
        let source = root.join("example.bin");
        let original = vec![0x41; CHUNK_SIZE + 37];
        fs::write(&source, &original).unwrap();
        let key = [7u8; 32];
        let mut encrypted = Vec::new();
        encrypt_stream(&mut File::open(&source).unwrap(), &mut encrypted, &key).unwrap();
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(decrypt_for_test(&encrypted, &key), original);
        assert!(!encrypted.windows(32).any(|window| window == [0x41; 32]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_file_still_has_an_authenticated_record() {
        let root = test_root("empty");
        let source = root.join("empty.bin");
        fs::write(&source, []).unwrap();
        let mut encrypted = Vec::new();
        let key = [9u8; 32];
        encrypt_stream(&mut File::open(&source).unwrap(), &mut encrypted, &key).unwrap();
        assert_eq!(encrypted.len(), 28 + 4 + TAG_SIZE);
        assert!(decrypt_for_test(&encrypted, &key).is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selected_file_contains_verified_ciphertext_before_key_disposal() {
        let root = test_root("stored-ciphertext");
        let source = root.join("selected.bin");
        let original = vec![0x6d; CHUNK_SIZE + 23];
        fs::write(&source, &original).unwrap();
        let mut file = open_for_destroy(&source).unwrap();
        let mut key = Zeroizing::new([4u8; 32]);
        let (mut stage, stage_path) = create_encrypted_stage(&source).unwrap();
        encrypt_stream(&mut file, &mut stage, &key).unwrap();
        stage.sync_all().unwrap();
        assert!(stage_path.exists());
        stage.seek(SeekFrom::Start(0)).unwrap();
        let mut staged = Vec::new();
        stage.read_to_end(&mut staged).unwrap();
        assert!(staged.starts_with(MAGIC));
        assert_eq!(decrypt_for_test(&staged, &key), original);
        assert!(!staged.windows(32).any(|window| window == [0x6d; 32]));
        verify_encrypted_stage(&mut stage, &mut file, &key).unwrap();
        replace_source_with_ciphertext(&mut file, &mut stage).unwrap();
        let mut stored = Vec::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_end(&mut stored).unwrap();
        assert!(stored.starts_with(MAGIC));
        assert_eq!(decrypt_for_test(&stored, &key), original);
        key.zeroize();
        drop(stage);
        assert!(!stage_path.exists());
        overwrite_and_delete(file, &source).unwrap();
        assert!(!source.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_stage_is_refused_before_original_is_modified() {
        let root = test_root("tamper");
        let source = root.join("selected.bin");
        let original = vec![0x35; 100];
        fs::write(&source, &original).unwrap();
        let mut file = open_for_destroy(&source).unwrap();
        let key = [0x44; 32];
        let (mut stage, stage_path) = create_encrypted_stage(&source).unwrap();
        encrypt_stream(&mut file, &mut stage, &key).unwrap();
        stage.seek(SeekFrom::Start(32)).unwrap();
        let mut byte = [0u8; 1];
        stage.read_exact(&mut byte).unwrap();
        stage.seek(SeekFrom::Start(32)).unwrap();
        stage.write_all(&[byte[0] ^ 1]).unwrap();
        stage.sync_all().unwrap();
        assert!(verify_encrypted_stage(&mut stage, &mut file, &key).is_err());
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut after = Vec::new();
        file.read_to_end(&mut after).unwrap();
        assert_eq!(after, original);
        drop(stage);
        assert!(!stage_path.exists());
        drop(file);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selected_file_is_removed_without_retained_files() {
        let root = test_root("destroy");
        let selected = root.join("selected.txt");
        let other = root.join("other.txt");
        fs::write(&selected, vec![0x52; CHUNK_SIZE + 17]).unwrap();
        fs::write(&other, b"keep this").unwrap();
        let identity = file_identity(&open_for_destroy(&selected).unwrap()).unwrap();
        process_one_with_identity(&selected, identity).unwrap();
        assert!(!selected.exists());
        assert_eq!(fs::read(&other).unwrap(), b"keep this");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_another_hard_link_to_a_selected_file() {
        let root = test_root("links");
        let selected = root.join("selected.txt");
        let other_link = root.join("other-link.txt");
        fs::write(&selected, b"shared content").unwrap();
        fs::hard_link(&selected, &other_link).unwrap();
        assert!(open_for_destroy(&selected).is_err());
        assert_eq!(fs::read(&other_link).unwrap(), b"shared content");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nested_folder_selection_stays_inside_selected_tree() {
        let root = test_root("folder");
        let selected = root.join("selected");
        let nested = selected.join("nested");
        let untouched = root.join("untouched.txt");
        fs::create_dir_all(&nested).unwrap();
        fs::write(selected.join("a.txt"), b"a").unwrap();
        fs::write(nested.join("b.txt"), b"b").unwrap();
        fs::write(&untouched, b"keep").unwrap();
        let (files, folders) = collect_selection(std::slice::from_ref(&selected)).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(folders.len(), 2);
        for file in files {
            process_one_with_identity(&file.path, file.identity).unwrap();
        }
        for folder in folders.iter().rev() {
            fs::remove_dir(folder).unwrap();
        }
        assert!(!selected.exists());
        assert_eq!(fs::read(untouched).unwrap(), b"keep");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_after_preflight_is_refused_before_processing() {
        let root = test_root("replacement");
        let selected = root.join("selected.txt");
        let original = root.join("moved-original.txt");
        fs::write(&selected, b"original selected file").unwrap();
        let (files, _) = collect_selection(std::slice::from_ref(&selected)).unwrap();
        fs::rename(&selected, &original).unwrap();
        fs::write(&selected, b"replacement file").unwrap();
        assert!(process_one_with_identity(&files[0].path, files[0].identity).is_err());
        assert_eq!(fs::read(&selected).unwrap(), b"replacement file");
        assert_eq!(fs::read(&original).unwrap(), b"original selected file");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_drive_root_alias_has_no_parent() {
        let root = env::current_exe()
            .unwrap()
            .ancestors()
            .last()
            .unwrap()
            .to_path_buf();
        let alias = root.join(".");
        let canonical = fs::canonicalize(alias).unwrap();
        assert!(canonical.parent().is_none());
    }

    #[test]
    fn recovery_finishes_a_selected_file_after_interruption() {
        let root = test_root("recovery");
        let state = root.join("state");
        let source = root.join("selected.bin");
        let stage_path = root.join("encrypted-stage.tmp");
        fs::write(&source, b"original plaintext").unwrap();
        fs::write(&stage_path, b"encrypted stage").unwrap();
        let mut file = open_for_destroy(&source).unwrap();
        let stage = open_for_destroy(&stage_path).unwrap();
        let journal = PendingJournal::create(&source, &file, &stage_path, &stage, &state).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"partially changed").unwrap();
        drop(file);
        drop(stage);
        assert!(journal.path.exists());
        recover_pending_jobs(&state).unwrap();
        assert!(!source.exists());
        assert!(!stage_path.exists());
        assert!(!journal.path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn decrypt_for_test(sealed: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let header: [u8; 28] = sealed[..28].try_into().unwrap();
        let prefix: [u8; 8] = header[8..16].try_into().unwrap();
        let total = u64::from_be_bytes(header[16..24].try_into().unwrap());
        let chunks = total.div_ceil(CHUNK_SIZE as u64);
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let mut offset = 28;
        let mut plaintext = Vec::new();
        for index in 0..=chunks {
            let frame_len =
                u32::from_be_bytes(sealed[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            let mut frame = sealed[offset..offset + frame_len].to_vec();
            offset += frame_len;
            let nonce: Nonce<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize> =
                nonce_for(&prefix, index as u32).into();
            let aad = frame_aad(&header, index as u32, index == chunks);
            cipher.decrypt_in_place(&nonce, &aad, &mut frame).unwrap();
            plaintext.extend_from_slice(&frame);
        }
        assert_eq!(offset, sealed.len());
        assert_eq!(plaintext.len() as u64, total);
        plaintext
    }
}

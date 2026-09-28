#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(not(windows))]
compile_error!("Zero currently supports Windows only.");

use aes_gcm::{Aes256Gcm, Nonce, aead::AeadInOut, aead::KeyInit};
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ZEROFMT2";
const CHUNK_SIZE: usize = 1024 * 1024;
const TAG_SIZE: usize = 16;

type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() {
    if let Err(error) = run() {
        show_dialog("Zero", &format!("Operation stopped:\n\n{error}"));
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let sources: Vec<PathBuf> = env::args_os().skip(1).map(PathBuf::from).collect();
    if sources.is_empty() {
        show_dialog(
            "Zero",
            "Drag up to 32 individual files onto this executable in Windows Explorer.\n\nEach selected file is encrypted on disk with AES-256-GCM, verified, and then its working key is cleared. The file is overwritten and deleted. Nothing is retained after success. There is no confirmation prompt.",
        );
        return Ok(());
    }
    if sources.len() > 32 {
        return Err("select at most 32 individual files per drop".into());
    }
    for source in &sources {
        let info = fs::symlink_metadata(source)?;
        if info.file_type().is_symlink() || !info.is_file() {
            return Err(format!(
                "only individual regular files may be selected: {}",
                source.display()
            )
            .into());
        }
    }

    for (index, source) in sources.iter().enumerate() {
        if let Err(error) = process_one(source) {
            return Err(format!(
                "{}: {error}\n\n{} earlier file(s) completed. This file may be partly encrypted or overwritten if the error occurred after staging.",
                source.display(),
                index
            )
            .into());
        }
    }
    show_dialog(
        "Zero",
        &format!(
            "Processed {} selected file(s).\n\nNo encrypted files or keys were retained. The selected originals were overwritten and deleted. Backups, snapshots, and old storage blocks may remain.",
            sources.len()
        ),
    );
    Ok(())
}

fn process_one(source: &Path) -> AppResult<()> {
    let mut file = open_for_destroy(source)?;
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key)?;
    let (mut stage, stage_path) = create_encrypted_stage(source)?;
    encrypt_stream(&mut file, &mut stage, &key)?;
    stage.sync_all()?;
    verify_encrypted_stage(&mut stage, &mut file, &key)?;
    replace_source_with_ciphertext(&mut file, &mut stage)?;
    key.zeroize();
    drop(stage);
    if stage_path.try_exists()? {
        return Err("temporary encrypted file was not removed".into());
    }
    overwrite_and_delete(file, source)
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

fn hard_link_count(file: &File) -> AppResult<u32> {
    use std::mem::MaybeUninit;

    #[repr(C)]
    struct FileInfo {
        _attributes: u32,
        _creation_time: [u32; 2],
        _access_time: [u32; 2],
        _write_time: [u32; 2],
        _volume_serial: u32,
        _size_high: u32,
        _size_low: u32,
        links: u32,
        _index_high: u32,
        _index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(handle: *mut c_void, info: *mut FileInfo) -> i32;
    }
    let mut info = MaybeUninit::<FileInfo>::uninit();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { info.assume_init() }.links)
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
        process_one(&selected).unwrap();
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

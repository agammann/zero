use crate::AppResult;
use std::fs;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetVolumePathNameW(path: *const u16, volume: *mut u16, length: u32) -> i32;
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn GetWindowsDirectoryW(buffer: *mut u16, length: u32) -> u32;
    fn GetVolumeInformationW(
        root: *const u16,
        name: *mut u16,
        name_length: u32,
        serial: *mut u32,
        maximum_component: *mut u32,
        flags: *mut u32,
        filesystem: *mut u16,
        filesystem_length: u32,
    ) -> i32;
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

fn volume_root(path: &Path) -> AppResult<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    // The input is NUL terminated, and the output has a full-size writable buffer.
    let ok = unsafe {
        GetVolumePathNameW(
            wide(path).as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or("volume path is too long")?;
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer[..end])))
}

fn windows_directory() -> AppResult<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    // The output buffer is valid for the supplied length.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length as usize],
    )))
}

fn volume_information(root: &Path) -> AppResult<(u32, String)> {
    let mut serial = 0u32;
    let mut filesystem_buffer = [0u16; 128];
    let root_wide = wide(root);
    // The supplied pointers reference writable output buffers for this call.
    let ok = unsafe {
        GetVolumeInformationW(
            root_wide.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            filesystem_buffer.as_mut_ptr(),
            filesystem_buffer.len() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let end = filesystem_buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or("filesystem name is too long")?;
    let filesystem = std::ffi::OsString::from_wide(&filesystem_buffer[..end])
        .to_string_lossy()
        .into_owned();
    Ok((serial, filesystem))
}

pub struct VolumeSelection {
    pub root: PathBuf,
    pub children: Vec<PathBuf>,
    pub kind: &'static str,
    pub filesystem: String,
    pub skipped_system_entries: usize,
}

pub fn inspect(selected: &Path, executable: &Path, state: &Path) -> AppResult<VolumeSelection> {
    let selected = std::path::absolute(selected)?;
    let metadata = fs::symlink_metadata(&selected)?;
    if !metadata.is_dir() {
        return Err("--volume requires an existing volume root directory".into());
    }
    let root = volume_root(&selected)?;
    if fs::canonicalize(&selected)? != fs::canonicalize(&root)? {
        return Err("--volume requires the exact volume root, such as E:\\".into());
    }
    let (serial, filesystem) = volume_information(&root)?;
    for protected in [
        windows_directory()?,
        executable.to_owned(),
        state.to_owned(),
    ] {
        let protected_root = volume_root(&protected)?;
        if protected_root
            .to_string_lossy()
            .eq_ignore_ascii_case(&root.to_string_lossy())
            || volume_information(&protected_root)?.0 == serial
        {
            return Err("the Windows, executable, or Zero state volume is protected".into());
        }
    }
    // A trailing separator is required by GetDriveTypeW and GetVolumeInformationW.
    let root_wide = wide(&root);
    // The pointer refers to a NUL-terminated buffer for this call.
    let kind = match unsafe { GetDriveTypeW(root_wide.as_ptr()) } {
        2 => "removable",
        3 => "fixed",
        _ => return Err("only local removable or fixed volumes are supported".into()),
    };
    let entries = fs::read_dir(&root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut children = Vec::new();
    let mut skipped_system_entries = 0;
    for entry in entries {
        if fs::symlink_metadata(&entry)?.file_attributes() & 0x0000_0004 != 0 {
            skipped_system_entries += 1;
        } else {
            children.push(entry);
        }
    }
    children.sort();
    Ok(VolumeSelection {
        root,
        children,
        kind,
        filesystem,
        skipped_system_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_within_system_volume_is_not_accepted_as_a_volume_root() {
        let selected = std::env::temp_dir();
        let result = inspect(
            &selected,
            &std::env::current_exe().unwrap(),
            &selected.join("state"),
        );
        assert!(result.is_err());
    }
}

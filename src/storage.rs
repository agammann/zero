use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageKind {
    Fixed,
    Removable,
    Network,
    RamDisk,
    Optical,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageAssessment {
    pub kind: StorageKind,
    pub file_system: Option<String>,
    pub shared_block_capable: Option<bool>,
}

impl StorageAssessment {
    pub fn describe(&self) -> String {
        let kind = match self.kind {
            StorageKind::Fixed => "fixed (HDD/SSD unknown)",
            StorageKind::Removable => "removable",
            StorageKind::Network => "network",
            StorageKind::RamDisk => "RAM disk",
            StorageKind::Optical => "optical",
            StorageKind::Unknown => "unknown",
        };
        let shared = match self.shared_block_capable {
            Some(true) => "reported",
            Some(false) => "not reported",
            None => "unknown",
        };
        format!(
            "{kind}; file system {}; shared-block support {shared}",
            self.file_system.as_deref().unwrap_or("unknown")
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageSummary {
    pub fixed: usize,
    pub removable: usize,
    pub network: usize,
    pub ram_disk: usize,
    pub optical: usize,
    pub unknown: usize,
    pub shared_block_capable: usize,
    pub file_system_unknown: usize,
    pub file_systems: Vec<String>,
    pub other_file_systems: bool,
}

impl StorageSummary {
    pub fn add(&mut self, assessment: &StorageAssessment) {
        match assessment.kind {
            StorageKind::Fixed => self.fixed += 1,
            StorageKind::Removable => self.removable += 1,
            StorageKind::Network => self.network += 1,
            StorageKind::RamDisk => self.ram_disk += 1,
            StorageKind::Optical => self.optical += 1,
            StorageKind::Unknown => self.unknown += 1,
        }
        if assessment.shared_block_capable == Some(true) {
            self.shared_block_capable += 1;
        }
        if let Some(name) = &assessment.file_system {
            if !self.file_systems.contains(name) {
                if self.file_systems.len() < 8 {
                    self.file_systems.push(name.clone());
                    self.file_systems.sort();
                } else {
                    self.other_file_systems = true;
                }
            }
        } else {
            self.file_system_unknown += 1;
        }
    }

    pub fn total(&self) -> usize {
        self.fixed + self.removable + self.network + self.ram_disk + self.optical + self.unknown
    }

    pub fn describe(&self) -> String {
        if self.total() == 0 {
            return "Storage context: no matching files.".to_owned();
        }
        let mut parts = Vec::new();
        for (count, label) in [
            (self.fixed, "fixed"),
            (self.removable, "removable"),
            (self.network, "network"),
            (self.ram_disk, "RAM disk"),
            (self.optical, "optical"),
            (self.unknown, "unknown"),
        ] {
            if count != 0 {
                parts.push(format!("{count} {label}"));
            }
        }
        let mut description = format!("Storage context: {} file(s).", parts.join(", "));
        if self.fixed != 0 {
            description.push_str(" Fixed does not distinguish HDD, SSD, or virtual media.");
        }
        if !self.file_systems.is_empty() {
            description.push_str(&format!("\nFile systems: {}", self.file_systems.join(", ")));
            if self.other_file_systems {
                description.push_str(", others");
            }
            description.push('.');
        }
        if self.file_system_unknown != 0 {
            description.push_str(&format!(
                "\nFile system unavailable for {} file(s).",
                self.file_system_unknown
            ));
        }
        if self.shared_block_capable != 0 {
            description.push_str(&format!(
                "\nShared-block support reported for {} file(s); this does not show whether their blocks are shared.",
                self.shared_block_capable
            ));
        }
        description
    }
}

/// Queries only the explicitly selected path and its already-open file handle.
/// A failed query is recorded as unknown; it never widens cleanup scope.
pub fn assess(path: &Path, file: &File) -> StorageAssessment {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetVolumePathNameW(path: *const u16, root: *mut u16, length: u32) -> i32;
        fn GetDriveTypeW(root: *const u16) -> u32;
        fn GetVolumeInformationByHandleW(
            file: *mut c_void,
            volume_name: *mut u16,
            volume_name_length: u32,
            serial: *mut u32,
            maximum_component: *mut u32,
            flags: *mut u32,
            file_system_name: *mut u16,
            file_system_name_length: u32,
        ) -> i32;
    }

    const FILE_SUPPORTS_BLOCK_REFCOUNTING: u32 = 0x0800_0000;
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut root = [0u16; 1024];
    let kind =
        if unsafe { GetVolumePathNameW(wide_path.as_ptr(), root.as_mut_ptr(), root.len() as u32) }
            != 0
        {
            match unsafe { GetDriveTypeW(root.as_ptr()) } {
                2 => StorageKind::Removable,
                3 => StorageKind::Fixed,
                4 => StorageKind::Network,
                5 => StorageKind::Optical,
                6 => StorageKind::RamDisk,
                _ => StorageKind::Unknown,
            }
        } else {
            StorageKind::Unknown
        };

    let mut file_system = [0u16; 261];
    let mut flags = 0u32;
    let queried = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            file_system.as_mut_ptr(),
            file_system.len() as u32,
        )
    } != 0;
    let (file_system, shared_block_capable) = if queried {
        let end = file_system
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(file_system.len());
        let name = String::from_utf16_lossy(&file_system[..end]);
        let name = if !name.is_empty()
            && name.len() <= 32
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            Some(name)
        } else {
            None
        };
        (name, Some(flags & FILE_SUPPORTS_BLOCK_REFCOUNTING != 0))
    } else {
        (None, None)
    };
    StorageAssessment {
        kind,
        file_system,
        shared_block_capable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn summary_reports_observations_without_claiming_physical_erasure() {
        let mut summary = StorageSummary::default();
        summary.add(&StorageAssessment {
            kind: StorageKind::Fixed,
            file_system: Some("NTFS".to_owned()),
            shared_block_capable: Some(false),
        });
        summary.add(&StorageAssessment {
            kind: StorageKind::Network,
            file_system: None,
            shared_block_capable: None,
        });
        assert_eq!(summary.total(), 2);
        assert_eq!(summary.file_system_unknown, 1);
        assert!(summary.describe().contains("1 fixed, 1 network"));
        assert!(summary.describe().contains("does not distinguish HDD, SSD"));
    }

    #[test]
    fn assessment_only_reads_a_selected_test_file() {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).unwrap();
        let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("zero-storage-{name}.txt"));
        fs::write(&path, b"unchanged").unwrap();
        let file = File::open(&path).unwrap();
        let assessment = assess(&path, &file);
        assert!(matches!(
            assessment.kind,
            StorageKind::Fixed | StorageKind::Removable | StorageKind::RamDisk
        ));
        assert!(assessment.file_system.is_some());
        assert_eq!(fs::read(&path).unwrap(), b"unchanged");
        drop(file);
        fs::remove_file(path).unwrap();
    }
}

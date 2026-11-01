use crate::filters::FileFilters;
use crate::receipts::{hex, unhex};
use crate::recovery;
use crate::{AppResult, state_directory};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

#[derive(Deserialize, Serialize)]
pub struct Profile {
    version: u8,
    paths: Vec<Vec<u16>>,
    receipt_directory: Option<Vec<u16>>,
    #[serde(default)]
    filters: FileFilters,
}

const PROFILE_DOMAIN: &[u8] = b"zero-saved-profile-v3\0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedProfile {
    version: u8,
    profile: Profile,
    signature: String,
}

pub struct LoadedProfile {
    pub paths: Vec<PathBuf>,
    pub receipt_directory: Option<PathBuf>,
    pub filters: FileFilters,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn profile_path(state: &Path, name: &str) -> AppResult<PathBuf> {
    if !valid_name(name) {
        return Err("profile name must use 1-48 letters, digits, hyphens, or underscores".into());
    }
    Ok(state.join("profiles").join(format!("{name}.json")))
}

pub fn create(
    name: &str,
    paths: &[PathBuf],
    receipts: Option<&Path>,
    filters: &FileFilters,
) -> AppResult<PathBuf> {
    if paths.is_empty() || paths.len() > 32 {
        return Err("a profile needs 1-32 explicitly selected paths".into());
    }
    filters.validate()?;
    let state = state_directory()?;
    let path = profile_path(&state, name)?;
    fs::create_dir_all(path.parent().ok_or("profile directory is unavailable")?)?;
    let profile = Profile {
        version: 2,
        paths: paths
            .iter()
            .map(|selected| {
                std::path::absolute(selected)
                    .map(|absolute| absolute.as_os_str().encode_wide().collect())
            })
            .collect::<Result<_, _>>()?,
        receipt_directory: receipts
            .map(|selected| {
                std::path::absolute(selected)
                    .map(|absolute| absolute.as_os_str().encode_wide().collect())
            })
            .transpose()?,
        filters: filters.clone(),
    };
    for encoded in &profile.paths {
        if encoded.len() > 16_384 {
            return Err("selected path is too long".into());
        }
    }
    let signature =
        recovery::sign_scoped(PROFILE_DOMAIN, &state, name, &serde_json::to_vec(&profile)?)?;
    let signed = SignedProfile {
        version: 3,
        profile,
        signature: hex(&signature),
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    serde_json::to_writer_pretty(&mut file, &signed)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(path)
}

pub fn load(name: &str) -> AppResult<LoadedProfile> {
    let state = state_directory()?;
    let path = profile_path(&state, name)?;
    read_profile(&path, &state, name)
}

fn read_profile(path: &Path, state: &Path, name: &str) -> AppResult<LoadedProfile> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > 1024 * 1024 {
        return Err("profile is too large".into());
    }
    let record: serde_json::Value = serde_json::from_reader(file)?;
    if matches!(
        record.get("version").and_then(serde_json::Value::as_u64),
        Some(1 | 2)
    ) {
        return Err("unsigned legacy profile requires operator review and re-creation".into());
    }
    let signed: SignedProfile = serde_json::from_value(record)?;
    if signed.version != 3 {
        return Err("profile format is unsupported".into());
    }
    recovery::verify_scoped(
        PROFILE_DOMAIN,
        state,
        name,
        &serde_json::to_vec(&signed.profile)?,
        &unhex::<64>(&signed.signature)?,
    )?;
    let profile = signed.profile;
    if !(1..=2).contains(&profile.version)
        || profile.paths.is_empty()
        || profile.paths.len() > 32
        || (profile.version == 1 && profile.filters != FileFilters::default())
    {
        return Err("profile format is unsupported".into());
    }
    profile.filters.validate()?;
    if profile.paths.iter().any(|encoded| encoded.len() > 16_384)
        || profile
            .receipt_directory
            .as_ref()
            .is_some_and(|encoded| encoded.len() > 16_384)
    {
        return Err("profile path is too long".into());
    }
    let paths = profile
        .paths
        .iter()
        .map(|encoded| PathBuf::from(OsString::from_wide(encoded)))
        .collect();
    let receipts = profile
        .receipt_directory
        .map(|encoded| PathBuf::from(OsString::from_wide(&encoded)));
    Ok(LoadedProfile {
        paths,
        receipt_directory: receipts,
        filters: profile.filters,
    })
}

pub fn list() -> AppResult<Vec<String>> {
    let dir = state_directory()?.join("profiles");
    if !dir.try_exists()? {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
            && let Some(name) = path.file_stem().and_then(|stem| stem.to_str())
            && valid_name(name)
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

pub fn schedule(name: &str, cadence: &str, time: &str) -> AppResult<()> {
    let _ = load(name)?;
    let task_name = crate::state::task_name(crate::state::TaskKind::Profile, name)?;
    let action = crate::state::task_action(&["--profile".as_ref(), name.as_ref()])?;
    crate::scheduler::register(
        &task_name,
        &action,
        crate::scheduler::Schedule::Profile { cadence, time },
    )
}

pub fn unschedule(name: &str) -> AppResult<()> {
    if !valid_name(name) {
        return Err("invalid profile name".into());
    }
    let result = crate::scheduler::command()?
        .args([
            "/Delete",
            "/F",
            "/TN",
            &crate::state::task_name(crate::state::TaskKind::Profile, name)?,
        ])
        .output()?;
    if !result.status.success() {
        return Err(format!(
            "Task Scheduler could not remove this schedule: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_cannot_escape_state_directory() {
        assert!(valid_name("work-photos_1"));
        assert!(!valid_name("../other"));
        assert!(!valid_name("name with space"));
        assert!(!valid_name(""));
    }

    #[test]
    fn old_profiles_load_without_filters() {
        let legacy = r#"{"version":1,"paths":[[67,58,92,120]],"receipt_directory":null}"#;
        let profile: Profile = serde_json::from_str(legacy).unwrap();
        assert_eq!(profile.version, 1);
        assert_eq!(profile.filters, FileFilters::default());
    }

    #[test]
    fn saved_profiles_require_current_user_signature() {
        let root = crate::tests::test_root("profile-auth");
        fs::create_dir(root.join("profiles")).unwrap();
        let path = root.join("profiles").join("benign.json");
        let selected = root.join("selected");
        let profile = Profile {
            version: 2,
            paths: vec![selected.as_os_str().encode_wide().collect()],
            receipt_directory: None,
            filters: FileFilters::default(),
        };
        let signed = SignedProfile {
            version: 3,
            signature: hex(&recovery::sign_scoped(
                PROFILE_DOMAIN,
                &root,
                "benign",
                &serde_json::to_vec(&profile).unwrap(),
            )
            .unwrap()),
            profile,
        };
        fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
        assert_eq!(
            read_profile(&path, &root, "benign").unwrap().paths,
            [selected]
        );
        assert!(read_profile(&path, &root, "other").is_err());
        let other_state = crate::tests::test_root("profile-replay");
        let replayed = other_state.join("benign.json");
        fs::copy(&path, &replayed).unwrap();
        assert!(read_profile(&replayed, &other_state, "benign").is_err());
        fs::remove_dir_all(other_state).unwrap();

        let mut altered = serde_json::to_value(&signed).unwrap();
        altered["profile"]["paths"] = serde_json::json!([[67, 58, 92, 111, 116, 104, 101, 114]]);
        fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
        assert!(
            read_profile(&path, &root, "benign")
                .err()
                .unwrap()
                .to_string()
                .contains("authentication failed")
        );

        fs::write(&path, serde_json::to_vec(&signed.profile).unwrap()).unwrap();
        assert!(
            read_profile(&path, &root, "benign")
                .err()
                .unwrap()
                .to_string()
                .contains("unsigned legacy profile")
        );
        fs::remove_dir_all(root).unwrap();
    }
}

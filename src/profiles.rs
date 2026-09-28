use crate::filters::FileFilters;
use crate::{AppResult, state_directory};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize, Serialize)]
pub struct Profile {
    version: u8,
    paths: Vec<Vec<u16>>,
    receipt_directory: Option<Vec<u16>>,
    #[serde(default)]
    filters: FileFilters,
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
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    serde_json::to_writer_pretty(&mut file, &profile)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(path)
}

pub fn load(name: &str) -> AppResult<LoadedProfile> {
    let path = profile_path(&state_directory()?, name)?;
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > 1024 * 1024 {
        return Err("profile is too large".into());
    }
    let profile: Profile = serde_json::from_reader(file)?;
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
    let parts = time.split(':').collect::<Vec<_>>();
    if parts.len() != 2
        || parts[0].len() != 2
        || parts[1].len() != 2
        || parts[0].parse::<u8>()? > 23
        || parts[1].parse::<u8>()? > 59
    {
        return Err("time must be HH:MM in local 24-hour time".into());
    }
    let task_name = format!("Zero-{name}");
    let executable = std::env::current_exe()?;
    let command_line = format!("\"{}\" --quiet --profile {name}", executable.display());
    let mut command = Command::new("schtasks.exe");
    command.args([
        "/Create",
        "/F",
        "/TN",
        &task_name,
        "/TR",
        &command_line,
        "/ST",
        time,
        "/RL",
        "LIMITED",
    ]);
    match cadence {
        "daily" => {
            command.args(["/SC", "DAILY"]);
        }
        "weekdays" => {
            command.args(["/SC", "WEEKLY", "/D", "MON,TUE,WED,THU,FRI"]);
        }
        value if value.starts_with("every-") => {
            let days = value.trim_start_matches("every-").parse::<u8>()?;
            if !(1..=30).contains(&days) {
                return Err("every-N cadence supports 1-30 days".into());
            }
            command.args(["/SC", "DAILY", "/MO", &days.to_string()]);
        }
        _ => return Err("cadence must be daily, weekdays, or every-N".into()),
    }
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!(
            "Task Scheduler rejected the schedule: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(())
}

pub fn unschedule(name: &str) -> AppResult<()> {
    if !valid_name(name) {
        return Err("invalid profile name".into());
    }
    let result = Command::new("schtasks.exe")
        .args(["/Delete", "/F", "/TN", &format!("Zero-{name}")])
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
}

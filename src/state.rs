use crate::{AppResult, FileIdentity, file_identity};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::iter::Peekable;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static STATE: OnceLock<State> = OnceLock::new();

struct State {
    directory: PathBuf,
    expected: Option<FileIdentity>,
    explicit_directory: bool,
}

#[derive(Clone, Copy)]
pub enum TaskKind {
    Profile,
    Agent,
}

impl State {
    fn parse(args: &mut Peekable<impl Iterator<Item = OsString>>) -> AppResult<Self> {
        let mut directory = None;
        let mut expected = None;
        while let Some(option) = args.peek().and_then(|arg| arg.to_str()) {
            match option {
                "--state-dir" => {
                    args.next();
                    if directory.is_some() {
                        return Err("state directory was specified twice".into());
                    }
                    let path = PathBuf::from(args.next().ok_or("state directory is required")?);
                    if !path.is_absolute() {
                        return Err("state directory must be an absolute path".into());
                    }
                    directory = Some(path);
                }
                "--state-id" => {
                    args.next();
                    if expected.is_some() {
                        return Err("state identity was specified twice".into());
                    }
                    let value = args.next().ok_or("scheduled state identity is required")?;
                    expected = Some(parse_identity(&value)?);
                }
                _ => break,
            }
        }
        if expected.is_some() && directory.is_none() {
            return Err("scheduled state identity requires --state-dir".into());
        }
        let explicit_directory = directory.is_some();
        let directory = match directory {
            Some(path) => path,
            None => default_directory()?,
        };
        Ok(Self {
            directory: std::path::absolute(directory)?,
            expected,
            explicit_directory,
        })
    }

    fn checked_directory(&self) -> AppResult<PathBuf> {
        if let Some(expected) = self.expected
            && directory_identity(&self.directory)? != expected
        {
            return Err(format!(
                "scheduled state directory changed: {}; refusing state access; review the location before scheduling again",
                self.directory.display()
            )
            .into());
        }
        Ok(self.directory.clone())
    }

    fn task_name(&self, kind: TaskKind, name: &str) -> AppResult<String> {
        if !self.explicit_directory {
            return Ok(match kind {
                TaskKind::Profile => format!("Zero-{name}"),
                TaskKind::Agent => format!("Zero-Agent-{name}"),
            });
        }
        let identity = directory_identity(&self.checked_directory()?)?;
        let kind = match kind {
            TaskKind::Profile => "Profile",
            TaskKind::Agent => "Agent",
        };
        Ok(format!(
            "Zero@{:08x}-{:016x}-{:016x}-{kind}-{name}",
            identity.volume, identity.index, identity.creation_time
        ))
    }
}

fn default_directory() -> AppResult<PathBuf> {
    let appdata = env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is unavailable")?;
    Ok(PathBuf::from(appdata).join("Zero"))
}

pub fn initialize(args: &mut Peekable<impl Iterator<Item = OsString>>) -> AppResult<()> {
    let state = State::parse(args)?;
    // Do not expose a state path to logging or any other consumer before this check succeeds.
    state.checked_directory()?;
    STATE
        .set(state)
        .map_err(|_| "state directory was already initialized".into())
}

pub fn directory() -> AppResult<PathBuf> {
    if let Some(state) = STATE.get() {
        return state.checked_directory();
    }
    // Unit tests call the existing file-operation helpers without entering the CLI.
    #[cfg(test)]
    return default_directory();
    #[cfg(not(test))]
    Err("state directory is not initialized".into())
}

fn directory_identity(path: &Path) -> AppResult<FileIdentity> {
    let file = OpenOptions::new()
        .read(true)
        .access_mode(0)
        .share_mode(7)
        .custom_flags(0x0220_0000) // BACKUP_SEMANTICS | OPEN_REPARSE_POINT; metadata only.
        .open(path)
        .map_err(|error| {
            format!(
                "could not inspect state directory {}: {error}",
                path.display()
            )
        })?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err("scheduled state must be an ordinary directory".into());
    }
    file_identity(&file)
}

fn parse_identity(value: &OsStr) -> AppResult<FileIdentity> {
    let value = value.to_str().ok_or("invalid scheduled state identity")?;
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().zip([8, 16, 16]).any(|(part, size)| {
            part.len() != size || !part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err("invalid scheduled state identity".into());
    }
    Ok(FileIdentity {
        volume: u32::from_str_radix(parts[0], 16)?,
        index: u64::from_str_radix(parts[1], 16)?,
        creation_time: u64::from_str_radix(parts[2], 16)?,
    })
}

fn quote_argument(value: &OsStr) -> Vec<u16> {
    let mut quoted = vec![b'"' as u16];
    let mut slashes = 0;
    for unit in value.encode_wide() {
        if unit == b'\\' as u16 {
            slashes += 1;
        } else {
            quoted.extend(std::iter::repeat_n(b'\\' as u16, slashes));
            if unit == b'"' as u16 {
                quoted.extend(std::iter::repeat_n(b'\\' as u16, slashes + 1));
            }
            quoted.push(unit);
            slashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    quoted.push(b'"' as u16);
    quoted
}

fn action(
    executable: &Path,
    directory: &Path,
    args: &[&OsStr],
) -> AppResult<crate::scheduler::Action> {
    let identity = directory_identity(directory)?;
    let encoded = format!(
        "{:08x}:{:016x}:{:016x}",
        identity.volume, identity.index, identity.creation_time
    );
    let arguments = [
        OsStr::new("--quiet"),
        OsStr::new("--state-dir"),
        directory.as_os_str(),
        OsStr::new("--state-id"),
        OsStr::new(&encoded),
    ];
    let mut command = Vec::new();
    for argument in arguments.into_iter().chain(args.iter().copied()) {
        if !command.is_empty() {
            command.push(b' ' as u16);
        }
        command.extend(quote_argument(argument));
    }
    Ok(crate::scheduler::Action {
        executable: executable.to_path_buf(),
        arguments: OsString::from_wide(&command),
    })
}

pub fn task_action(args: &[&OsStr]) -> AppResult<crate::scheduler::Action> {
    action(&env::current_exe()?, &directory()?, args)
}

pub fn task_name(kind: TaskKind, name: &str) -> AppResult<String> {
    STATE
        .get()
        .ok_or("state directory is not initialized")?
        .task_name(kind, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn parse(command: &[&str]) -> AppResult<State> {
        State::parse(&mut command.iter().map(OsString::from).peekable())
    }

    fn windows_arguments(command: &OsStr) -> Vec<OsString> {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn CommandLineToArgvW(command: *const u16, count: *mut i32) -> *mut *mut u16;
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        }
        let wide = command.encode_wide().chain(Some(0)).collect::<Vec<_>>();
        let mut count = 0;
        let argv = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
        assert!(!argv.is_null());
        let result = (0..count as usize)
            .map(|index| {
                let argument = unsafe { *argv.add(index) };
                let mut length = 0;
                while unsafe { *argument.add(length) } != 0 {
                    length += 1;
                }
                OsString::from_wide(unsafe { std::slice::from_raw_parts(argument, length) })
            })
            .collect();
        unsafe { LocalFree(argv.cast()) };
        result
    }

    #[test]
    fn default_state_and_leading_options_preserve_command_arguments() {
        let mut args = ["--state-dir", r"Z:\Chosen State", "--profile", "Saved"]
            .into_iter()
            .map(OsString::from)
            .peekable();
        let state = State::parse(&mut args).unwrap();
        assert_eq!(state.directory, Path::new(r"Z:\Chosen State"));
        assert!(state.explicit_directory);
        assert_eq!(args.collect::<Vec<_>>(), ["--profile", "Saved"]);
        assert_eq!(
            parse(&["--profiles"]).unwrap().directory,
            std::path::absolute(default_directory().unwrap()).unwrap()
        );
        for invalid in [
            vec!["--state-dir", "relative"],
            vec!["--state-dir"],
            vec!["--state-dir", r"Z:\one", "--state-dir", r"Z:\two"],
            vec!["--state-id", "00000000:0000000000000000:0000000000000000"],
            vec!["--state-dir", r"Z:\one", "--state-id", "invalid"],
        ] {
            assert!(parse(&invalid).is_err());
        }
    }

    #[test]
    fn bound_state_refuses_replaced_or_missing_directory_without_writes() {
        let root = crate::tests::test_root("state-binding");
        let path = root.join("state");
        fs::create_dir(&path).unwrap();
        let state = State {
            directory: path.clone(),
            expected: Some(directory_identity(&path).unwrap()),
            explicit_directory: true,
        };
        assert_eq!(state.checked_directory().unwrap(), path);
        fs::rename(&path, root.join("original")).unwrap();
        assert!(state.checked_directory().is_err());
        assert!(!path.exists());
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep.txt"), b"untouched").unwrap();
        assert!(
            state
                .checked_directory()
                .unwrap_err()
                .to_string()
                .contains("scheduled state directory changed")
        );
        assert_eq!(fs::read(path.join("keep.txt")).unwrap(), b"untouched");
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn task_action_round_trips_with_windows_parser_and_binds_both_modes() {
        let root = crate::tests::test_root("state-action");
        let directory = root.join("state with spaces");
        fs::create_dir(&directory).unwrap();
        for mode in [
            vec![OsStr::new("--profile"), OsStr::new("Saved")],
            vec![OsStr::new("--agent")],
        ] {
            let command =
                action(Path::new(r"Z:\Program Files\Zero.exe"), &directory, &mode).unwrap();
            let mut joined = OsString::from_wide(&quote_argument(command.executable.as_os_str()));
            joined.push(" ");
            joined.push(&command.arguments);
            let decoded = windows_arguments(&joined);
            assert_eq!(decoded[0], r"Z:\Program Files\Zero.exe");
            assert_eq!(decoded[1], "--quiet");
            let mut args = decoded.into_iter().skip(2).peekable();
            let state = State::parse(&mut args).unwrap();
            assert_eq!(state.checked_directory().unwrap(), directory);
            assert_eq!(
                state.expected,
                Some(directory_identity(&directory).unwrap())
            );
            assert_eq!(args.collect::<Vec<_>>(), mode);
        }
        let unusual = OsString::from_wide(&[
            b'Z' as u16,
            b':' as u16,
            b'\\' as u16,
            0xd800,
            b'"' as u16,
            b'\\' as u16,
        ]);
        let mut encoded = OsString::from("Zero.exe ");
        encoded.push(OsString::from_wide(&quote_argument(&unusual)));
        assert_eq!(windows_arguments(&encoded)[1], unusual);
        let mut encoded = OsString::from("Zero.exe ");
        encoded.push(OsString::from_wide(&quote_argument(OsStr::new(r"Z:\"))));
        assert_eq!(windows_arguments(&encoded)[1], r"Z:\");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_stores_namespace_both_task_kinds_without_changing_defaults() {
        let root = crate::tests::test_root("task-names");
        let first = root.join("first");
        let second = root.join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let selected = |directory| State {
            directory,
            expected: None,
            explicit_directory: true,
        };
        let one = selected(first.clone());
        let alias = selected(first.join("."));
        let two = selected(second);
        for kind in [TaskKind::Profile, TaskKind::Agent] {
            let name = one.task_name(kind, "Shared").unwrap();
            assert!(name.starts_with("Zero@"));
            assert_eq!(name, alias.task_name(kind, "Shared").unwrap());
            assert_ne!(name, two.task_name(kind, "Shared").unwrap());
        }
        assert_ne!(
            one.task_name(TaskKind::Profile, "Shared").unwrap(),
            one.task_name(TaskKind::Agent, "Shared").unwrap()
        );
        assert_eq!(
            one.task_name(TaskKind::Profile, &"x".repeat(48))
                .unwrap()
                .len(),
            104
        );
        let default = State {
            directory: root.join("missing"),
            expected: None,
            explicit_directory: false,
        };
        assert_eq!(
            default
                .task_name(TaskKind::Profile, "Agent-Shared")
                .unwrap(),
            "Zero-Agent-Shared"
        );
        assert_eq!(
            default.task_name(TaskKind::Agent, "Shared").unwrap(),
            "Zero-Agent-Shared"
        );
        assert_ne!(
            one.task_name(TaskKind::Agent, "Shared").unwrap(),
            "Zero-Agent-Shared"
        );
        assert!(!default.directory.exists());
        let old_name = one.task_name(TaskKind::Profile, "Shared").unwrap();
        fs::rename(&first, root.join("moved")).unwrap();
        assert!(one.task_name(TaskKind::Profile, "Shared").is_err());
        assert!(!first.exists());
        fs::create_dir(&first).unwrap();
        assert_ne!(
            old_name,
            one.task_name(TaskKind::Profile, "Shared").unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
}

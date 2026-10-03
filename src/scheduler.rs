use crate::{AppResult, state};
use std::ffi::{OsStr, OsString, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Action {
    pub executable: PathBuf,
    pub arguments: OsString,
}

pub enum Schedule<'a> {
    Profile { cadence: &'a str, time: &'a str },
    Agent,
}

#[repr(C)]
#[derive(Default)]
struct LocalTime {
    year: u16,
    month: u16,
    weekday: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLocalTime(time: *mut LocalTime);
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        information: *mut c_void,
        size: u32,
        needed: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
}

fn current_sid() -> AppResult<String> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // TOKEN_USER starts with a SID pointer. This aligned buffer exceeds the maximum SID size.
    let mut information = [0usize; 128];
    let mut needed = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            1,
            information.as_mut_ptr().cast(),
            std::mem::size_of_val(&information) as u32,
            &mut needed,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(error.into());
    }
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(information[0] as *mut c_void, &mut text) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let length = (0..192).find(|&index| unsafe { *text.add(index) } == 0);
    let result = length
        .ok_or_else(|| "current user SID is too long".into())
        .and_then(|length| {
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
                .map_err(Into::into)
        });
    unsafe { LocalFree(text.cast()) };
    result
}

fn schtasks() -> AppResult<PathBuf> {
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err("could not locate the Windows system directory".into());
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length as usize])).join("schtasks.exe"))
}

fn text(value: &OsStr) -> AppResult<String> {
    let value = String::from_utf16(&value.encode_wide().collect::<Vec<_>>())
        .map_err(|_| "scheduled paths and arguments must be valid Unicode")?;
    if value.chars().any(|ch| {
        !matches!(ch, '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
    }) {
        return Err("scheduled paths and arguments contain an invalid XML character".into());
    }
    Ok(value)
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('\r', "&#13;")
}

fn trigger(schedule: Schedule<'_>, now: &LocalTime) -> AppResult<String> {
    let date = format!("{:04}-{:02}-{:02}", now.year, now.month, now.day);
    match schedule {
        Schedule::Agent => Ok(format!(
            "<TimeTrigger><StartBoundary>{date}T{:02}:{:02}:{:02}</StartBoundary><Repetition><Interval>PT1M</Interval></Repetition></TimeTrigger>",
            now.hour, now.minute, now.second
        )),
        Schedule::Profile { cadence, time } => {
            let parts = time.split(':').collect::<Vec<_>>();
            if parts.len() != 2
                || parts
                    .iter()
                    .any(|part| part.len() != 2 || !part.bytes().all(|b| b.is_ascii_digit()))
                || parts[0].parse::<u8>()? > 23
                || parts[1].parse::<u8>()? > 59
            {
                return Err("time must be HH:MM in local 24-hour time".into());
            }
            let calendar = match cadence {
                "daily" => "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>".to_owned(),
                "weekdays" => "<ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><Monday/><Tuesday/><Wednesday/><Thursday/><Friday/></DaysOfWeek></ScheduleByWeek>".to_owned(),
                value if value.starts_with("every-") => {
                    let days = value.trim_start_matches("every-").parse::<u8>()?;
                    if !(1..=30).contains(&days) {
                        return Err("every-N cadence supports 1-30 days".into());
                    }
                    format!("<ScheduleByDay><DaysInterval>{days}</DaysInterval></ScheduleByDay>")
                }
                _ => return Err("cadence must be daily, weekdays, or every-N".into()),
            };
            Ok(format!(
                "<CalendarTrigger><StartBoundary>{date}T{time}:00</StartBoundary>{calendar}</CalendarTrigger>"
            ))
        }
    }
}

fn document(action: &Action, sid: &str, trigger: &str) -> AppResult<String> {
    let executable = text(action.executable.as_os_str())?;
    let arguments = text(&action.arguments)?;
    // Task Scheduler's Command schema is pathType (260); CreateProcessW includes the NUL.
    if !action.executable.is_absolute() || executable.encode_utf16().count() > 260 {
        return Err(
            "scheduled executable must be an absolute path of at most 260 UTF-16 units".into(),
        );
    }
    if executable.encode_utf16().count() + arguments.encode_utf16().count() + 4 > 32767 {
        return Err("scheduled action exceeds the Windows process command-line limit".into());
    }
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers>{trigger}</Triggers>
<Principals><Principal id="Author"><UserId>{}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><Enabled>false</Enabled><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings></Settings>
<Actions Context="Author"><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions>
</Task>"#,
        escape(sid),
        escape(&executable),
        escape(&arguments)
    ))
}

// Read only simple fields in schtasks' XML export, not arbitrary XML input. Ambiguous
// or unsupported exports fail closed while the newly imported task is disabled.
fn element<'a>(xml: &'a str, name: &str) -> AppResult<Option<&'a str>> {
    let prefix = format!("<{name}");
    let mut found = xml.match_indices(&prefix).filter(|(index, _)| {
        xml.as_bytes()
            .get(index + prefix.len())
            .is_some_and(|b| *b == b'>' || *b == b'/' || b.is_ascii_whitespace())
    });
    let Some((start, _)) = found.next() else {
        return Ok(None);
    };
    if found.next().is_some() {
        return Err("ambiguous task XML field".into());
    }
    let body = start + xml[start..].find('>').ok_or("invalid task XML")? + 1;
    if xml[..body - 1].ends_with('/') {
        return Ok(Some(""));
    }
    let closing = format!("</{name}>");
    let end = body + xml[body..].find(&closing).ok_or("invalid task XML")?;
    Ok(Some(&xml[body..end]))
}

fn required<'a>(xml: &'a str, name: &str) -> AppResult<&'a str> {
    element(xml, name)?.ok_or_else(|| format!("task XML is missing {name}").into())
}

fn unescape(value: &str) -> AppResult<String> {
    if value.contains('<') {
        return Err("unexpected nested task XML field".into());
    }
    let mut out = String::new();
    let mut rest = value;
    while let Some(index) = rest.find('&') {
        out.push_str(&rest[..index]);
        rest = &rest[index + 1..];
        let end = rest.find(';').ok_or("invalid task XML entity")?;
        let entity = &rest[..end];
        let ch = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let number = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16)?
                } else if let Some(decimal) = entity.strip_prefix('#') {
                    decimal.parse()?
                } else {
                    return Err("unsupported task XML entity".into());
                };
                char::from_u32(number).ok_or("invalid task XML character")?
            }
        };
        out.push(ch);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn enabled(xml: &str) -> AppResult<bool> {
    match element(required(xml, "Settings")?, "Enabled")?
        .unwrap_or("true")
        .trim()
    {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err("invalid task enabled state".into()),
    }
}

fn verify(xml: &str, action: &Action, sid: &str, expected_enabled: bool) -> AppResult<()> {
    if xml.contains("<!") || xml.len() > 1024 * 1024 {
        return Err("unsupported task XML export".into());
    }
    let actions = required(xml, "Actions")?;
    let exec = required(actions, "Exec")?;
    if ["ComHandler", "SendEmail", "ShowMessage"]
        .iter()
        .any(|name| actions.contains(&format!("<{name}")))
        || unescape(required(exec, "Command")?)? != text(action.executable.as_os_str())?
        || unescape(required(exec, "Arguments")?)? != text(&action.arguments)?
        || element(exec, "WorkingDirectory")?.is_some_and(|value| !value.is_empty())
    {
        return Err("Task Scheduler did not retain the exact executable and arguments".into());
    }
    let principal = required(required(xml, "Principals")?, "Principal")?;
    if unescape(required(principal, "UserId")?)? != sid
        || required(principal, "LogonType")?.trim() != "InteractiveToken"
        || element(principal, "RunLevel")?
            .unwrap_or("LeastPrivilege")
            .trim()
            != "LeastPrivilege"
        || element(principal, "GroupId")?.is_some()
        || enabled(xml)? != expected_enabled
    {
        return Err(
            "Task Scheduler did not retain the requested user, permissions or enabled state".into(),
        );
    }
    Ok(())
}

fn decode_xml(bytes: &[u8]) -> AppResult<String> {
    if bytes.len() > 1024 * 1024 {
        return Err("task XML export is too large".into());
    }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[b'<', 0]) {
        let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
        if !bytes.len().is_multiple_of(2) {
            return Err("invalid UTF-16 task XML".into());
        }
        Ok(String::from_utf16(
            &bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )?)
    } else {
        Ok(String::from_utf8(
            bytes
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(bytes)
                .to_vec(),
        )?)
    }
}

fn query(program: &Path, name: &str) -> AppResult<String> {
    let output = Command::new(program)
        .args(["/Query", "/TN", name, "/XML"])
        .output()?;
    if !output.status.success() {
        return Err("could not read back the registered task".into());
    }
    decode_xml(&output.stdout)
}

struct TemporaryXml {
    path: PathBuf,
    file: Option<File>,
    removed: bool,
}

impl TemporaryXml {
    fn create(xml: &str) -> AppResult<Self> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)?;
        let name = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let path = state::directory()?.join(format!("schedule-{name}.xml"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(1)
            .open(&path)?;
        let mut temporary = Self {
            path,
            file: Some(file),
            removed: false,
        };
        let file = temporary.file.as_mut().ok_or("task XML is unavailable")?;
        file.write_all(&[0xff, 0xfe])?;
        for unit in xml.encode_utf16() {
            file.write_all(&unit.to_le_bytes())?;
        }
        file.sync_all()?;
        drop(temporary.file.take());
        Ok(temporary)
    }

    fn remove(&mut self) -> AppResult<()> {
        fs::remove_file(&self.path).map_err(|error| {
            format!(
                "could not remove temporary scheduler XML {}: {error}",
                self.path.display()
            )
        })?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for TemporaryXml {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.removed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn register(name: &str, action: &Action, schedule: Schedule<'_>) -> AppResult<()> {
    let mut now = LocalTime::default();
    unsafe { GetLocalTime(&mut now) };
    let sid = current_sid()?;
    let xml = document(action, &sid, &trigger(schedule, &now)?)?;
    let mut temporary = TemporaryXml::create(&xml)?;
    let program = schtasks()?;
    let result = Command::new(&program)
        .args(["/Create", "/F", "/TN", name, "/XML"])
        .arg(&temporary.path)
        .output()?;
    if !result.status.success() {
        return Err(format!(
            "Task Scheduler rejected the disabled task: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    temporary
        .remove()
        .map_err(|error| format!("{error}; task {name} has not been enabled"))?;
    drop(temporary);
    let activate = || -> AppResult<()> {
        verify(&query(&program, name)?, action, &sid, false)?;
        let result = Command::new(&program)
            .args(["/Change", "/TN", name, "/ENABLE"])
            .output()?;
        if !result.status.success() {
            return Err("Task Scheduler could not enable the verified task".into());
        }
        verify(&query(&program, name)?, action, &sid, true)
    };
    if let Err(error) = activate() {
        // Keep the named task for inspection; never delete a potentially changed task.
        let disabled = Command::new(&program)
            .args(["/Change", "/TN", name, "/DISABLE"])
            .output()
            .is_ok_and(|output| output.status.success())
            && query(&program, name)
                .and_then(|xml| enabled(&xml))
                .is_ok_and(|enabled| !enabled);
        let status = if disabled {
            "disabled task retained for inspection"
        } else {
            "could not confirm task disabled; inspect Task Scheduler immediately"
        };
        return Err(format!("{error}; {name}: {status}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn action() -> Action {
        Action {
            executable: PathBuf::from(r"Z:\Tools & Apps\Zero雪.exe"),
            arguments: OsString::from(format!(
                "\"--quiet\" \"--state-dir\" \"Z:\\{} & 雪\\\" \"--agent\"",
                "long state ".repeat(32)
            )),
        }
    }

    #[test]
    fn long_actions_survive_xml_and_truncation_is_rejected() {
        let action = action();
        let xml = document(&action, "S-1-5-21-1001", "").unwrap();
        assert!(action.arguments.encode_wide().count() > 255);
        verify(&xml, &action, "S-1-5-21-1001", false).unwrap();
        // Independent Windows XML parser: verifies decoded values rather than the writer's spelling.
        let powershell = schtasks()
            .unwrap()
            .parent()
            .unwrap()
            .join(r"WindowsPowerShell\v1.0\powershell.exe");
        let mut parser = Command::new(powershell)
            .args(["-NoProfile", "-NonInteractive", "-Command", "[Console]::InputEncoding=[Text.Encoding]::UTF8; [Console]::OutputEncoding=[Text.Encoding]::UTF8; [xml]$doc=[Console]::In.ReadToEnd(); @($doc.Task.Actions.Exec.Command,$doc.Task.Actions.Exec.Arguments) | ConvertTo-Json -Compress"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        parser
            .stdin
            .take()
            .unwrap()
            .write_all(xml.as_bytes())
            .unwrap();
        let parsed = parser.wait_with_output().unwrap();
        assert!(
            parsed.status.success(),
            "{}",
            String::from_utf8_lossy(&parsed.stderr)
        );
        let decoded: Vec<String> = serde_json::from_slice(
            parsed
                .stdout
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&parsed.stdout),
        )
        .unwrap();
        assert_eq!(
            decoded,
            [
                text(action.executable.as_os_str()).unwrap(),
                text(&action.arguments).unwrap()
            ]
        );
        assert!(verify(&xml, &action, "S-1-5-21-1001", true).is_err());
        for changed in [
            xml.replace("--agent", "--age"),
            xml.replace("Zero雪.exe", "Other.exe"),
            xml.replace("</Exec>", "</Exec><Exec><Command>other</Command></Exec>"),
            xml.replace("LeastPrivilege", "HighestAvailable"),
            xml.replace("S-1-5-21-1001", "S-1-5-18"),
            xml.replace("<Arguments>", "<Arguments/><Arguments>"),
            xml.replace(
                "</Exec>",
                "<WorkingDirectory>Z:\\other</WorkingDirectory></Exec>",
            ),
        ] {
            assert!(verify(&changed, &action, "S-1-5-21-1001", false).is_err());
        }
        let utf16 = [0xff, 0xfe]
            .into_iter()
            .chain(xml.encode_utf16().flat_map(u16::to_le_bytes))
            .collect::<Vec<_>>();
        assert_eq!(decode_xml(&utf16).unwrap(), xml);
        assert_eq!(decode_xml(xml.as_bytes()).unwrap(), xml);
        assert_eq!(
            unescape("a&#x26;b&#13;&#10;&quot;&apos;").unwrap(),
            "a&b\r\n\"'"
        );
        assert!(text(&OsString::from_wide(&[0xd800])).is_err());
        assert!(text(OsStr::new("bad\0path")).is_err());
    }

    #[test]
    fn existing_cadences_use_local_calendar_and_indefinite_minute_repetition() {
        let now = LocalTime {
            year: 2026,
            month: 10,
            day: 2,
            hour: 23,
            minute: 59,
            second: 42,
            ..Default::default()
        };
        for (cadence, days) in [("daily", "1"), ("every-3", "3"), ("every-30", "30")] {
            let xml = trigger(
                Schedule::Profile {
                    cadence,
                    time: "08:05",
                },
                &now,
            )
            .unwrap();
            assert_eq!(
                required(&xml, "StartBoundary").unwrap(),
                "2026-10-02T08:05:00"
            );
            assert_eq!(required(&xml, "DaysInterval").unwrap(), days);
        }
        let weekdays = trigger(
            Schedule::Profile {
                cadence: "weekdays",
                time: "08:05",
            },
            &now,
        )
        .unwrap();
        assert_eq!(required(&weekdays, "WeeksInterval").unwrap(), "1");
        assert_eq!(
            required(&weekdays, "DaysOfWeek").unwrap(),
            "<Monday/><Tuesday/><Wednesday/><Thursday/><Friday/>"
        );
        let agent = trigger(Schedule::Agent, &now).unwrap();
        assert_eq!(
            required(&agent, "StartBoundary").unwrap(),
            "2026-10-02T23:59:42"
        );
        assert_eq!(required(&agent, "Interval").unwrap(), "PT1M");
        assert!(element(&agent, "Duration").unwrap().is_none());
        for (cadence, time) in [
            ("every-0", "01:00"),
            ("every-31", "01:00"),
            ("daily", "24:00"),
            ("daily", "01:60"),
            ("daily", "1:00"),
            ("daily", "+1:00"),
        ] {
            assert!(trigger(Schedule::Profile { cadence, time }, &now).is_err());
        }
    }
}

# Zero

Zero is a free, open-source Windows app that processes and removes the files and folders you explicitly select. It works locally without an account, subscription, or API key.

[Download Zero for Windows](https://github.com/agammann/zero/releases/latest) · [Read the storage model](STORAGE_AND_KEY_MODEL.md) · [Build from source](#build-and-test)

Drag up to 32 files or folders onto `Zero.exe`; it starts immediately without a confirmation prompt. A folder drop includes its nested ordinary files and removes the selected folders when they are empty. Zero does not retain a vault. Volume roots are refused; Zero has no whole-device operation.

For each file, Zero writes an AES-256-GCM encrypted stage on the same volume, authenticates that stage, replaces the selected file's current logical contents with the verified ciphertext, clears its working key, overwrites the file once with random bytes, checks the logical readback, and deletes it. It rejects reparse points, files with other hard links, named data streams, and unsupported file attributes. The whole selection is inspected before the first file is changed, with a limit of 100,000 files.

**Zero is destructive.** A processed file cannot be restored through Zero. If a batch fails, earlier files stay processed. Backups, snapshots, cloud copies, old blocks, and device-reserved storage may still hold data. Read [the storage and key model](STORAGE_AND_KEY_MODEL.md) before using Zero for sensitive files. Zero has no independent security audit or forensic certification; the Windows executable is unsigned.

## Storage context

During inspection, Zero makes read-only Windows queries for each selected file's drive category, file-system name, and whether the file system reports shared-block support. The profile preview shows a summary before any file is processed; the completion dialog summarizes processed files. New optional signed receipts record the observed context for each processed file, and signed remote results include aggregate counts. Ordinary local drops write no persistent assessment by default.

"Fixed" is a Windows drive category; it does not tell Zero whether the underlying media is an HDD, SSD, or virtual device. A file system reporting shared-block support does not prove that a particular file's blocks are shared. A query failure is shown as unknown. These observations do not detect old blocks, snapshots, backups, cloud replicas, or device-reserved storage, and they do not establish physical-media erasure. Zero does not open a physical drive or issue a device sanitization command. The actual selected-file cleanup sequence is the same on all reported storage categories.

## Quick use

1. Open the [latest release](https://github.com/agammann/zero/releases/latest). Download `Zero.exe`, or extract the Windows ZIP to keep the executable and its documentation together. No installer is needed.
2. Double-click `Zero.exe` without selecting files to read its short usage dialog. Create a folder containing disposable copies for your first run.
3. Preview that folder with the command below. Then drag it onto `Zero.exe` to process it. A successful direct drop removes the selected files and their empty folders; other files are left alone.

To inspect a selection without changing it, run `./Zero.exe --preview "D:\Disposable\example.txt"` in PowerShell. The preview lists up to 15 selected files and shows the observed storage context. It does not create a vault or perform recovery. Dropping files onto the executable still starts processing immediately.

The advanced commands below are run from PowerShell. Put `--quiet` first to suppress result dialogs; failures return exit code 1 and are normally written to `last-error.txt` in the selected state directory, which defaults to `%LOCALAPPDATA%\Zero`.

| Task | Command |
| --- | --- |
| Inspect files without changing them | `.\Zero.exe --preview "D:\Disposable"` |
| Run an existing saved selection | `.\Zero.exe --profile DownloadsClean` |
| List saved selections | `.\Zero.exe --profiles` |
| Verify a signed receipt | `.\Zero.exe --verify-receipt "D:\Receipts\receipt.json" "D:\trusted-public-key.hex"` |

Preview commands use a visible dialog and do not accept `--quiet`. Profile runs keep their selected folders for reuse. Direct drops remove empty selected folders. If a batch stops, read the error before retrying: earlier files may already be gone, and an interrupted file operation may be completed on a later processing run.

## Saved and scheduled selections

Create a named profile without changing the selected files, then run or schedule it:

```powershell
.\Zero.exe --create-profile DownloadsClean "D:\Drop Folder"
.\Zero.exe --preview-profile DownloadsClean
.\Zero.exe --profile DownloadsClean
.\Zero.exe --schedule DownloadsClean daily 23:30
.\Zero.exe --unschedule DownloadsClean
```

Scheduling uses Windows Task Scheduler under the current user. Stay signed in to that Windows account and keep the computer awake and connected to AC power. These tasks do not start on battery power and stop if the computer switches to battery. Cadences are `daily`, `weekdays`, or `every-N` for 1–30 days, followed by local `HH:MM` time. A profile keeps its selected folders in place so a later scheduled run can process newly added files. Files absent when the task runs are skipped. Task failures can be inspected in `last-error.txt` and Task Scheduler. A scheduled run has no confirmation prompt.

### Choosing a shared state location

`--state-dir` requires version 0.6.2 or newer. Version 0.6.1 does not support it; do not pass this option to that version.

Use the leading `--state-dir` option to choose an absolute directory for profiles, signing keys, recovery records, remote enrollment and job history. Put it after `--quiet`, if used, and before the command. Use the same location for subsequent commands:

```powershell
.\Zero.exe --state-dir "D:\Zero State" --create-profile DownloadsClean "D:\Drop Folder"
.\Zero.exe --state-dir "D:\Zero State" --preview-profile DownloadsClean
.\Zero.exe --state-dir "D:\Zero State" --schedule DownloadsClean daily 23:30
.\Zero.exe --state-dir "D:\Zero State" --unschedule DownloadsClean
```

Some packaged Windows hosts redirect AppData. A caller and Task Scheduler can then see different directories under the same path and Windows account. Choose a deliberate local state directory outside that redirected location, and keep it outside every selected folder. This option does not copy or migrate existing profiles, keys or job history; a different directory is a separate state store. Continue using the original location for its existing records and trust identity.

New profile and remote-agent tasks retain the chosen state path and its Windows directory identity. They refuse a missing or replaced directory before recovery, key access or processing. This refusal returns exit code 1 without writing `last-error.txt` into an unverified directory; inspect Task Scheduler and the state location before scheduling again. Earlier tasks need to be recreated to gain this check. Task registration stores the executable and arguments separately and checks their exact stored values before enabling the task, then checks again. An unsuccessful check retains a disabled task for inspection; if disabling cannot be confirmed, the error says so. The executable path is limited to 260 UTF-16 units. The executable, quoting, separator, arguments and terminating null must fit Windows' 32,767-unit process command-line limit.

Tasks created with `--state-dir` use names beginning `Zero@` that include the directory identity and distinguish profile tasks from remote agents. Two explicit stores can therefore use the same profile or device name. Commands without this option keep the legacy `Zero-<profile>` and `Zero-Agent-<device>` names. Use the same default or explicit command form when removing a task. If an explicit store is removed or replaced, inspect and remove its old exact task in Task Scheduler; Zero does not fall back to deleting another store's or a legacy task.

The state check does not bind selected files, receipt destinations or the shared queue across different filesystem views. Use paths those contexts can access consistently; preview the selection from the intended execution environment. It does not change the normal same-run file-identity checks or recurring-profile behavior.

Filters are optional when creating a saved profile. This example includes `.log` and `.tmp` files last modified at least 30 days ago, except names starting with `keep`:

```powershell
.\Zero.exe --create-profile OldLogs --include-ext .log,.tmp --older-than-days 30 --exclude-name "keep*" "D:\Drop Folder"
.\Zero.exe --preview-profile OldLogs
.\Zero.exe --profile OldLogs
```

`--include-ext` accepts a comma-separated list and may be repeated; matching is case-insensitive. `--exclude-name` may be repeated and matches the file name, not its parent path; `*` matches any sequence and `?` matches one character. `--older-than-days` uses the file's last-modified time and full 24-hour days. Omit any option to leave that rule off. The preview reads the current selection, shows up to 15 matching paths and counts skipped files, and does not encrypt or delete anything. It can be run again before scheduling. Profiles created by earlier versions stay unfiltered. Direct drag-and-drop remains literal; filters apply only to saved profiles and are checked again immediately before each file is processed. A scheduled or remote run may see a different matching set from the preview if files have changed.

## Optional signed receipts

Receipts are off by default. To write a signed JSON record for each successfully processed file, pass a directory outside the selected folders:

```powershell
.\Zero.exe --receipts "D:\Zero Receipts" "D:\Disposable\example.txt"
.\Zero.exe --create-profile WithReceipts --receipts "D:\Zero Receipts" "D:\Drop Folder"
.\Zero.exe --export-key "D:\Zero Receipts\trusted-public-key.hex"
.\Zero.exe --verify-receipt "D:\Zero Receipts\zero-REPLACE.json" "D:\Zero Receipts\trusted-public-key.hex"
```

The receipt signing key is a separate, persistent Ed25519 key protected for the current Windows user with DPAPI. The per-file AES key is still cleared after use. Transfer and trust the public key independently of the receipt. New receipts include the observed storage context. A valid signature attests that this app signed the listed actions and observations; it cannot prove physical erasure, historical-copy removal, or that the signing computer was uncompromised.

## Authenticated remote jobs

Zero can use a shared directory as a job queue. This may be a user-managed sync folder or SMB share; Zero provides no hosted relay. The controller signs a request for a device and one pre-enrolled profile. The target's one-minute Windows task verifies the controller signature and local allowlist, applies the target's saved-profile filters, records the exact selected file identities for restart, processes them, and signs a result. A completed job ID is recorded locally so replaying the same request does not process newly added files.

On the controller:

```powershell
.\Zero.exe --export-key "D:\controller-public.hex"
```

On the target, first create a local profile. Transfer the controller public key to it through a trusted channel, then enroll only the intended profile:

```powershell
.\Zero.exe --create-profile RemoteClean "D:\Drop Folder"
.\Zero.exe --enroll LaptopA "D:\Shared Zero Queue" "D:\controller-public.hex" RemoteClean
.\Zero.exe --export-key "D:\target-public.hex"
```

Back on the controller, trust the target public key through a separate channel, then queue and verify a job:

```powershell
.\Zero.exe --send "D:\Shared Zero Queue" LaptopA RemoteClean
.\Zero.exe --verify-result "D:\Shared Zero Queue\LaptopA\results\result-JOBID.json" "D:\target-public.hex"
```

Run `--agent` manually to poll once, or `--remove-agent` on the target to remove its scheduled poller and enrollment. The queue must reach the target for delivery. Anyone who can control the queue can delay or delete jobs and results, but cannot authorize a different profile without the enrolled controller signing key. The target profile and its files are controlled by the target Windows user. A signed result reports the app's actions, files missing on retry, files skipped because they no longer match filters, and observed storage context for files completed during that attempt; it is not a physical erasure certificate. See [remote job design](REMOTE_JOBS.md).

## Build and test

Install a current stable [Rust toolchain for Windows](https://rust-lang.org/learn/get-started/). The standard MSVC toolchain also needs the C++ build tools and Windows SDK offered during Rust setup. Open PowerShell in the repository directory and run:

```powershell
.\build-windows.ps1
```

The script tests and builds `Zero.exe`. `Cargo.lock` pins dependencies. The source includes tests for AES-256-GCM staging, ciphertext readback, folder selection, profile filters, storage-context reporting, interruption recovery, receipt signatures, and remote authorization. See [third-party notices](THIRD_PARTY_NOTICES.md) for bundled Rust dependencies.

To run the same source checks used in CI:

```powershell
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

After building, `.\package-release.ps1` creates Windows and source ZIPs in `dist` and checks that the packaged executable matches `Zero.exe`. The Windows release workflow also runs the tests and checks before publishing a tagged release. These checks cover the app's logical file operations; they do not measure residual data on physical media.

### Scheduler verification: 2026-10-02

A Windows 11 run in a signed-in session on AC power checked version 0.6.2 with fresh local state and disposable files:

- Registered and read back daily, weekday and every-three-day profile schedules, plus the one-minute agent. Executable paths containing spaces and combined profile command lines of 266 and 268 UTF-16 units retained their full arguments.
- Started one profile task through Task Scheduler and verified its signed receipt. The agent then ran on its minute trigger, processed one signed request and produced a result that passed signature verification.
- Two explicit state stores used the same profile name without replacing or removing each other's task. The second store's task was never started. An unrelated sentinel file stayed unchanged, and all test tasks were removed.
- Missing or mismatched bound state, a malformed state identity and a relative state option were refused. The 31 unit tests, formatting, Clippy and an offline release build also passed. The 20-file source archive was extracted and compiled offline.

This verifies one profile execution and one naturally triggered agent request. It does not establish recurrence across days or reboots, operation while signed out or on battery, cross-machine queue delivery, or physical-media erasure.

Zero is available under the [MIT License](LICENSE).

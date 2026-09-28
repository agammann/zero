# Zero

Zero is a free, open-source Windows app for the files and folders you explicitly select. Drag up to 32 files or folders onto `Zero.exe`; it starts immediately without a confirmation prompt. A folder drop includes its nested ordinary files and removes the selected folders when they are empty. Zero does not retain a vault.

For each file, Zero writes an AES-256-GCM encrypted stage on the same volume, authenticates that stage, replaces the selected file's current logical contents with the verified ciphertext, clears its working key, overwrites the file once with random bytes, checks the logical readback, and deletes it. It rejects reparse points, files with other hard links, and unsupported file attributes. The whole selection is inspected before the first file is changed, with a limit of 100,000 files.

**Zero is destructive.** A processed file cannot be restored through Zero. If a batch fails, earlier files stay processed. Backups, snapshots, cloud copies, old blocks, and device-reserved storage may still hold data. Read [the storage and key model](STORAGE_AND_KEY_MODEL.md) before using Zero for sensitive files. Zero has no independent security audit or forensic certification; the Windows executable is unsigned.

## Quick use

1. Download `Zero.exe` from a release, or [build it](#build-and-test).
2. Put disposable files in a test folder and drag that folder onto `Zero.exe` to see the behavior.
3. Drag only files or folders you intend to remove. There is no confirmation prompt.

The advanced commands below are run from PowerShell. Put `--quiet` first to suppress result dialogs; failures are written to `%LOCALAPPDATA%\Zero\last-error.txt` and return exit code 1.

## Saved and scheduled selections

Create a named profile without changing the selected files, then run or schedule it:

```powershell
.\Zero.exe --create-profile DownloadsClean "D:\Drop Folder"
.\Zero.exe --profile DownloadsClean
.\Zero.exe --schedule DownloadsClean daily 23:30
.\Zero.exe --unschedule DownloadsClean
```

Scheduling uses Windows Task Scheduler under the current user. Cadences are `daily`, `weekdays`, or `every-N` for 1–30 days, followed by local `HH:MM` time. A profile keeps its selected folders in place so a later scheduled run can process newly added files. Files absent when the task runs are skipped. Task failures can be inspected in `last-error.txt` and Task Scheduler. A scheduled run has no confirmation prompt.

## Optional signed receipts

Receipts are off by default. To write a signed JSON record for each successfully processed file, pass a directory outside the selected folders:

```powershell
.\Zero.exe --receipts "D:\Zero Receipts" "D:\Disposable\example.txt"
.\Zero.exe --create-profile WithReceipts --receipts "D:\Zero Receipts" "D:\Drop Folder"
.\Zero.exe --export-key "D:\Zero Receipts\trusted-public-key.hex"
.\Zero.exe --verify-receipt "D:\Zero Receipts\zero-REPLACE.json" "D:\Zero Receipts\trusted-public-key.hex"
```

The receipt signing key is a separate, persistent Ed25519 key protected for the current Windows user with DPAPI. The per-file AES key is still cleared after use. Transfer and trust the public key independently of the receipt. A valid signature attests that this app signed the listed actions; it cannot prove physical erasure, historical-copy removal, or that the signing computer was uncompromised.

## Explicit volume cleanup

`--volume` accepts one exact local volume root, such as `E:\`. It inspects the root's contents and performs the same file-level process on supported files. Root entries marked as Windows system files are skipped and counted in the result. It leaves the root itself in place. Zero refuses the Windows, executable, and app-state volumes and refuses network and unsupported drive types. An ordinary folder is not accepted as a volume root.

```powershell
.\Zero.exe --volume "E:\"
```

This command removes selected files on that volume. It does **not** sanitize unused space, partition metadata, spare cells, remapped blocks, drive firmware storage, or historical copies. Windows may report an external SSD as a fixed drive; the displayed drive type does not identify HDD versus SSD. This path has been tested for rejecting the system volume; a full run on a separate physical volume has not yet been verified.

## Authenticated remote jobs

Zero can use a shared directory as a job queue. This may be a user-managed sync folder or SMB share; Zero provides no hosted relay. The controller signs a request for a device and one pre-enrolled profile. The target's one-minute Windows task verifies the controller signature and local allowlist, records the exact selected file identities for restart, processes them, and signs a result. A completed job ID is recorded locally so replaying the same request does not process newly added files.

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

Run `--agent` manually to poll once, or `--remove-agent` on the target to remove its scheduled poller and enrollment. The queue must reach the target for delivery. Anyone who can control the queue can delay or delete jobs and results, but cannot authorize a different profile without the enrolled controller signing key. The target profile and its files are controlled by the target Windows user. A signed result reports the app's actions and files missing on retry; it is not a physical erasure certificate. See [remote job design](REMOTE_JOBS.md).

## Build and test

Install a current Rust toolchain for Windows and run:

```powershell
.\build-windows.ps1
```

The script tests and builds `Zero.exe`. `Cargo.lock` pins dependencies. The source includes tests for AES-256-GCM staging, ciphertext readback, folder selection, interruption recovery, receipt signatures, remote authorization, and protected-volume refusal. See [third-party notices](THIRD_PARTY_NOTICES.md) for bundled Rust dependencies.

Zero is available under the [MIT License](LICENSE).

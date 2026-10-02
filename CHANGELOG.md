# Changelog

## 0.6.1

- Reject non-ASCII text in hexadecimal keys, signatures, and job IDs with a normal error instead of panicking at a UTF-8 character boundary. File processing and receipt formats are unchanged.
- Package release archives correctly when the packaging script is invoked from another working directory.
- Add direct download and first-run guidance, a command reference, and Windows build prerequisites.

## 0.6.0

- Refuse selected files that contain named Windows data streams before any encryption or overwrite. The app cannot overwrite those streams through its current file handle, so processing them would give a misleading result.
- Add `--preview` for a read-only check of explicitly selected files and folders. It uses the same preflight rules and storage summary as saved-profile previews, without adding a confirmation step to drag-and-drop runs.
- Show failures with an error dialog and identify a processed file if optional receipt creation fails after its removal.
- Clear one-byte plaintext change-detection buffers on exit. The AES-256-GCM, logical readback, key clearing, and selected-file-only sequence remains the same.

## 0.5.0

- Add read-only storage-context assessment for each explicitly selected file. Preview and local completion dialogs report the observed drive category, file system, and shared-block capability.
- Include the storage assessment in new signed receipts and aggregate storage context in new signed remote results. Verification of earlier receipts and results remains supported.
- Keep file and folder scope. Zero does not query physical drive type, issue device sanitization commands, wipe free space, or remove backups and snapshots.

## 0.4.0

- Add optional extension, modified-age, and filename-exclusion filters to saved profiles. Existing profiles remain unfiltered.
- Add a read-only profile preview showing matching files and skip counts before a profile is run or scheduled.
- Apply profile filters to local, scheduled, and authenticated remote jobs, with a second check immediately before each file is processed.
- Keep direct file and folder drops literal and leave volume roots unsupported.

## 0.3.1

- Remove whole-volume selection. The `--volume` command now stops without processing selected files.
- Refuse volume-root folder aliases after resolving their canonical path.
- Keep explicit file and folder selection, saved profiles, scheduling, receipts, and remote profile jobs.

## 0.3.0

- Add recursive folder drops, saved profiles, and Windows Task Scheduler jobs.
- Add an explicit local volume-root command with Windows, executable, and app-state volume protection. It performs file-level cleanup and skips root system entries.
- Add interruption recovery records and file-identity checks before every destructive file operation.
- Add optional Ed25519-signed receipts with a user-scoped DPAPI-protected signing key.
- Add authenticated remote profile jobs through a user-managed shared directory, signed results, local snapshots, and replay protection.
- Add storage, remote-job, and third-party dependency documentation.

The volume path has passed rejection tests for the system volume and ordinary folders. A full run on a separate physical volume has not been verified. Zero does not claim physical-media sanitization, historical-copy removal, or certified erasure.

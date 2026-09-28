# Changelog

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

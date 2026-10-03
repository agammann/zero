# Zero remote jobs

Remote jobs are authenticated requests to run a target device's pre-existing local profile. Zero uses a directory owned by the user as transport. The directory can be synchronized or shared, but Zero does not supply a cloud account, relay, or delivery guarantee.

## Enrollment and trust

The controller creates a persistent Ed25519 signing key protected by Windows DPAPI for its user. It exports only a public key for the target. On enrollment, the target saves that public key, one device ID, the queue path, and an allowlist of profile names. The target installs a one-minute Windows Task Scheduler poller. The profile paths remain on the target; the controller cannot specify arbitrary target paths in a command. Keep the controller's Windows account and DPAPI state protected.

The target also signs results with its own separately generated Ed25519 key. The controller must obtain and trust that target public key through a channel other than the result itself. `--verify-result` uses the explicitly supplied trusted key; reading a key from an untrusted queue would defeat this check.

The same local signing-key store is used by optional receipts and remote messages. This key is not an AES file key and cannot recover deleted data. Losing it prevents verification under the old public key; compromise of the Windows user can allow forged future receipts and jobs.

The default state store is `%LOCALAPPDATA%\Zero`. A leading `--state-dir "D:\Zero State"` selects a separate store for every command, including enrollment, key export, polling and removal. Use the same chosen directory throughout; Zero does not migrate keys or completion history. Newly installed pollers retain its path and directory identity and stop before recovery or state access if the identity changes. See [state location and packaged Windows hosts](README.md#choosing-a-shared-state-location).

Explicit stores also have separate `Zero@…-Agent-<device>` task names. Enroll and remove with the same explicit state option; default-state commands retain the legacy task names. If the original explicit directory no longer exists or has been replaced, remove its old exact task through Task Scheduler after inspection. Zero does not search other stores or delete a legacy task as a fallback.

## Command and result flow

1. `--send` writes a signed JSON command to `DEVICE/pending/cmd-NONCE.json`. The signature covers format version, device ID, profile name, random job ID, and issue time.
2. The target poller requires an exact device ID, enrolled controller public key, valid signature, allowed profile, and matching command filename. Invalid or malformed queue entries stop that poll with an error; they are not executed.
3. Before processing, the target applies the local profile's optional filters and writes a local snapshot under `%LOCALAPPDATA%\Zero\remote-working` with the selected paths, Windows file identities, and filter rules. Later retries use this snapshot, so newly added files are not included in the old job.
4. Each selected file is checked against its captured identity and filter rules again before the normal AES-256-GCM, key-clearing, overwrite, and delete path. Zero observes the selected file's storage context at that point. Missing paths are recorded as missing on retry; files no longer matching filters are skipped. If a file at a selected path has a new identity, the job stops.
5. After finishing the snapshot, the target signs a result with aggregate storage context for files completed during that attempt, stores a local completion marker under `remote-done`, and writes the result to `DEVICE/results/result-NONCE.json`. It removes the pending command. The local completion marker prevents an old job ID from processing new files if the command is replayed.

Command and result signatures authenticate message content and key possession. They do not prove that the drive physically erased old blocks. The queue operator can delay, drop, reorder, or withhold messages. The target must be online, running its scheduled task, and able to access the queue. A local administrator or a compromised target account can alter profiles, files, or app state.

## Recovery and operation

Scheduled errors are normally written to `last-error.txt` in the target's chosen state directory. A failed startup state-identity check writes no file there; Task Scheduler records exit code 1. A successful quiet run clears this error file. A signed result reports `files_completed`, `files_missing`, `files_skipped_filter`, and, for new results, `storage`; a missing path may have been processed before an interruption or removed by something else. The storage field reports Windows observations, not physical erasure. Examine the target before interpreting a partial result.

The queue and local state contain path names, profile names, timestamps, and job IDs. Treat them as sensitive metadata. Restrict the shared directory and Windows profile permissions. Deleting the target's local `remote-done` history can weaken replay protection. The target's `--remove-agent` command removes the scheduled poller and enrollment; it does not erase existing queue messages, receipts, or completed-job records.

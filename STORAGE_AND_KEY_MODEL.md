# Zero: storage and key model

This document describes version 0.6.2's implemented file-level sequence. It is not a certification that every historical copy is gone.

State paths below use the default `%LOCALAPPDATA%\Zero`; a leading `--state-dir` instead selects one explicit store for profiles, keys, recovery and remote-job records. Newly registered tasks retain and check that directory's Windows identity before state access. No records or keys are automatically migrated. This does not establish that other saved paths resolve identically across Windows filesystem views.

## Per-file sequence

1. Inspect all selected paths before changing the first file and record each selected file identity. For a saved profile, include only files matching its optional extension, modified-age, and filename-exclusion rules. Refuse reparse points, unsupported attributes, files with other hard links, named data streams, and selections containing Zero's executable or state directory. Query the selected path and its open file handle for Windows drive category, file-system name, and shared-block capability without opening a physical drive. Open each file with exclusive read, write, and delete access when processing it, then require the opened handle to match the identity captured during inspection. Recheck profile filters and observe the storage context again immediately before processing.
2. Obtain a fresh 256-bit AES key and nonce prefix from the operating-system random source. Keep the working key in process memory. No file-specific key file, account, or remote key service is used.
3. Create a uniquely named stage in the source directory using `FILE_FLAG_DELETE_ON_CLOSE`. Encrypt source chunks with AES-256-GCM. Write the header, ciphertext, lengths, and authentication tags; no plaintext is written to the stage. Chunk and final-frame authentication bind the stream to its header and order.
4. Flush the stage. Read and authenticate every frame and compare recovered bytes against the selected original. Recovered plaintext remains in temporary process memory.
5. Write a recovery record under `%LOCALAPPDATA%\Zero` containing only the original and stage paths and file identities. Copy the verified encrypted stage over the selected file through the same exclusive handle. Flush, read back, and compare a SHA-256 digest of the current logical file with the staged ciphertext.
6. Zeroize the working AES key. The AES-GCM dependency is built with its `zeroize` feature to clear cipher state on drop. Close the stage handle and check that the stage path is gone.
7. Overwrite the encrypted source once with fresh random bytes, flush, check the logical readback, mark the same handle for deletion, and close it. Check that the selected path is absent, then remove the recovery record.

After success, no encrypted file or per-file AES key is intentionally retained. The recovery record contains paths and file identities but no key or ciphertext. Optional receipts use a separate persistent Ed25519 signing key protected by Windows DPAPI for the current user; that signing key cannot decrypt files. New signed receipts include the observed storage context, and new signed remote results include aggregate context for files completed during that attempt. No storage assessment is retained by default for ordinary local runs.

## Interruption and errors

- An ordinary error before the recovery record leaves the source's current logical bytes unchanged; closing the stage removes it.
- Once a recovery record exists, the next Zero run attempts to finish by overwriting and deleting the exact same file identity. This avoids leaving a partly encrypted original after an interruption. It does not reconstruct or resume the AES operation.
- Recovery of an already-started operation finishes independently of current profile filters, because that selected file may already contain partial ciphertext.
- If a file identity changes, a file is inaccessible, storage fails, or a recovery record is corrupt, Zero stops and keeps that record for inspection. It does not silently process a replacement path.
- A sudden power loss, filesystem damage, or storage/controller behavior can defeat cleanup. Windows delete-on-close is a process-lifetime behavior, not a power-loss guarantee.
- A multi-file batch stops at the first error. Earlier files remain processed. For scheduled or remote jobs, the snapshot and local records support retry; a remote result distinguishes files processed during the latest attempt, paths missing on retry, and files skipped because their filters no longer match.

## What storage checks prove

Zero checks bytes returned by Windows for the current logical file and stage. This confirms that the active handle presented ciphertext and later random data at the points checked. It does not prove that the physical media contains no prior plaintext. SSD wear leveling, remapped sectors, copy-on-write filesystems, application temporary files, backups, snapshots, and cloud replicas are outside this path.

The storage assessment is a bounded observation, not another sanitization method. Windows drive category `fixed` includes HDDs, SSDs, and other media. The file-system query can fail, including on network storage; Zero reports unknown rather than inferring a result. A shared-block capability flag says the file system can share blocks, not that this particular file has shared blocks. Zero does not inspect physical drive type, historical allocations, backup catalogs, shadow copies, or remote replicas. Query results do not change which explicitly selected files are processed.

The selected original may have existed as plaintext before Zero opened it. Encrypting its current contents is not retroactive encryption of old copies. A selected folder chooses its nested ordinary files for the same per-file path. Zero refuses volume roots and does not issue a device firmware sanitize command or overwrite all free space.

Zero does not lock every key schedule or temporary plaintext buffer against paging. `Zeroizing` clears the working key and the cipher library is built to clear state, but the operating system, cryptographic library, and hardware can keep copies beyond the app's control. Key disposal is best effort.

Zero refuses files with named data streams because its file-level overwrite targets only the default data stream. Stream enumeration uses the selected file handle during both preflight and processing. If Windows cannot enumerate streams, Zero stops on that file rather than claiming to have handled it.

## References

- [NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final) explains media sanitization methods and verification limits.
- [Windows `FILE_FLAG_DELETE_ON_CLOSE`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) defines the stage handle's deletion behavior.
- [Windows Data Protection API](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) protects the optional signing key for the current Windows user.
- [Windows `GetDriveTypeW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew), [`GetVolumePathNameW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamew), and [`GetVolumeInformationByHandleW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew) define the read-only storage-context queries.
- [Windows `FILE_STREAM_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_stream_info) defines the handle-based stream enumeration used to refuse named streams.

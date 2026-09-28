# Zero

Zero is a free, local Windows app for removing files you explicitly select. Drag up to 32 individual files onto `Zero.exe`. It runs immediately without a confirmation prompt. It does not scan folders, contact a server, or retain a vault.

For each file, Zero writes an AES-256-GCM encrypted stage in the same directory. It flushes that stage and authenticates it against the selected original. It then replaces the original file's current logical contents with the verified ciphertext, flushes and checks the readback, clears its working key, overwrites the encrypted file once with random bytes, and deletes it. The stage is opened with Windows delete-on-close and is removed when its handle closes. No encrypted file or key is retained after a successful run.

**This is destructive and has no recovery command.** A batch stops at the first error; files already processed stay processed. If an error or interruption occurs while replacing or overwriting a file, it may be partly modified. Try it on disposable files before using it on anything important.

## What the key can protect

The new stage and the selected file's *current logical contents* are ciphertext before Zero clears the key. This is a material change from version 0.1.0, which discarded the ciphertext before it reached storage.

If the file was stored as plaintext before you selected it, an older plaintext copy may still exist in a backup, snapshot, cloud sync service, temporary file, filesystem journal, remapped block, or SSD cell. Encrypting the current file cannot retroactively encrypt those copies. A successful readback only checks bytes returned by Windows through the active file handle. Zero does not claim certified media sanitization or guaranteed erasure of every copy.

Read [the storage and key model](STORAGE_AND_KEY_MODEL.md) for the exact sequence, failure behavior, and limits.

## Supported files

Zero accepts individual ordinary files. It refuses directories, symlinks and other reparse points, files with another hard link, and compressed, sparse, offline, or EFS files. Select at most 32 files in one drop. Use on local Windows storage; network and synced locations may retain other copies.

## Build and test

Install a current Rust toolchain for Windows, then run:

```powershell
.\build-windows.ps1
```

The script runs the tests and builds `Zero.exe` beside the script. `Cargo.lock` pins dependency versions. The tests check AES-256-GCM round trips, on-disk ciphertext before key disposal, automatic stage cleanup, selected-file removal, and hard-link refusal. This release has not had an independent security audit or forensic recovery assessment. The Windows executable is unsigned.

## License

Zero is available under the [MIT License](LICENSE). Third-party Rust crates retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).

# One-Way Vault

One-Way Vault is a free, local Windows app for explicitly selected files. It runs AES-256-GCM with a fresh random 256-bit key for each file, discards the ciphertext without saving it, clears its working key buffer, then overwrites and deletes the selected original. It creates no vault file and no key file.

## Use it

Place `Destroy selected files.exe` in a writable folder. In Windows Explorer, drag up to 32 **individual files** onto its icon. The app starts immediately, with no confirmation prompt, and shows a completion or error dialog. Double-clicking the executable shows brief instructions.

The app does not scan folders or process unselected files. It refuses linked files and files with another hard link so that an unselected path cannot be changed through the same underlying file. It has no network code; if you select a file in a synced folder or network share, copies elsewhere may remain.

**There is no recovery command.** A batch stops at the first error; earlier files stay processed. If an error occurs during overwrite or deletion, the current original may be partly overwritten.

## What cleanup can and cannot prove

After AES-256-GCM runs, the app overwrites the selected file once with random data, flushes it, checks the logical readback, and asks Windows to delete that same open file handle. No encrypted output is retained. This is **best-effort file-level cleanup**, not certified media sanitization.

It cannot reach backups, snapshots, cloud copies, temporary files, previous filesystem blocks, or SSD cells that the controller no longer exposes. Logical readback proves only what Windows currently returns for that file. Rust, its cryptography library, and Windows cannot guarantee that every possible in-memory copy of the key was cleared. The process exits when the selected files finish.

If complete removal of every plaintext copy matters, assess the storage system and its backups separately. A success dialog does not prove that every copy is gone.

## Build and test

Install a current Rust toolchain for Windows and run:

```powershell
.\build-windows.ps1
```

The script runs the Rust tests and builds `Destroy selected files.exe` beside itself. `Cargo.lock` pins dependency versions. The encryption test captures a ciphertext stream using a test-only key and verifies that AES-256-GCM decrypts it correctly. The app itself sends that stream to a sink and saves no ciphertext.

## License

One-Way Vault is available under the [MIT License](LICENSE). Third-party Rust crates retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).

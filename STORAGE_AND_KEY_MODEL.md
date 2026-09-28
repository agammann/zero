# Zero: storage and key model

This document describes version 0.2.0. It is a description of the implemented file path, not a certification that all historical copies are gone.

## Per-file sequence

1. Open the explicitly selected source with exclusive read, write, and delete access. Reject unsupported file types and files with more than one hard link.
2. Obtain a fresh 256-bit key and nonce prefix from the operating-system random source. Keep the working key in process memory. No key file, account, or remote key service is used.
3. Create a uniquely named file in the source directory with `FILE_FLAG_DELETE_ON_CLOSE`. Encrypt source chunks with AES-256-GCM and write only the header, ciphertext, lengths, and authentication tags to this stage. The format binds each chunk and the final frame to the header and chunk index as authenticated data. Plaintext is held only in temporary process buffers during this step.
4. Flush the stage. Read and authenticate every stage frame with the key, comparing the recovered bytes against the selected source. No recovered plaintext is written to the stage.
5. Copy the verified encrypted stage over the selected file through the same exclusive source handle. Flush it, read it back, and compare a SHA-256 digest of the current logical file against the staged ciphertext.
6. Zeroize the working key. The AES-GCM dependency is built with its `zeroize` feature, which clears its cipher state on drop. Close the stage handle; Windows then deletes the stage. Check that its path is gone.
7. Overwrite the encrypted source once with fresh random bytes, flush and compare logical readback, then mark that same file handle for deletion and close it. Check that the selected path is gone.

After successful completion, Zero retains neither ciphertext nor a key. No folder traversal, propagation, or background job is performed.

## Failure behavior

- A failure before step 5 leaves the original logical file unchanged; the stage is deleted when its handle closes.
- A failure or power loss during step 5 can leave the original partly plaintext and partly ciphertext. Zero does not resume or recover it.
- A failure after step 5 can leave encrypted bytes or random overwrite bytes at the selected path. A failure during cleanup may leave a partly overwritten file.
- Windows delete-on-close handles ordinary process termination, but the application cannot promise cleanup after storage failure, filesystem corruption, or every power-loss scenario.

## Boundaries of the claim

The source file may have existed as plaintext before Zero opened it. Filesystems, SSD controllers, backup tools, sync services, and applications may have stored other plaintext copies outside the current logical file. Zero cannot find or erase all of them. A logical readback is not a forensic test of physical media.

Zero does not lock every key schedule or temporary buffer against paging. It zeroizes its working key and enables cipher-state zeroization, but Rust, the cryptography library, the operating system, and hardware can hold copies beyond its control. Key destruction is therefore best effort, not a guarantee that no key material can ever be recovered.

The stage is encrypted when written. The selected original was already on storage before the app ran; only its current logical contents become ciphertext in step 5. This distinction matters when assessing any claim of cryptographic erasure.

## Implementation references

- [NIST SP 800-88 Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf) describes the preconditions and limits of cryptographic erase and selective sanitization.
- [Windows `FILE_FLAG_DELETE_ON_CLOSE`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) defines the stage file's delete-on-close behavior.
- [Windows `SetFileInformationByHandle`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle) defines how the selected file handle is marked for deletion.

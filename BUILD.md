# Build Zero

Zero 1.0.0 supports Windows 11 x64. The published executable uses Rust 1.98.1 with the standard MSVC target. Install Rust through [rustup](https://rust-lang.org/tools/install/) and the Visual Studio C++ build tools and Windows SDK. In PowerShell:

```powershell
rustup toolchain install 1.98.1 --profile minimal --component rustfmt,clippy
rustup override set 1.98.1
.\build-windows.ps1
```

If Windows PowerShell blocks a downloaded script, inspect the extracted source first, then run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build-windows.ps1`. This applies only to that build process; it does not change the system execution policy.

The build runs formatting, all unit tests, Clippy and a locked release compilation. Its output is `build\Zero.exe`; `build\BUILD.json` records the source files, executable digest, compiler and checks. A failed check keeps the previous successful output. A successful rebuild keeps the previous output under `build-history`. Build logs are retained. The tests use disposable files and temporary state. The Windows GNU target can also be used with its corresponding linker; it is the locally tested alternative, while release CI uses MSVC.

The source ZIP contains the same source and a `RELEASE.json` inventory. Extract it completely before building. Git is optional for building the ZIP. After editing the source, a local build records the edited bytes without claiming the original release identity. To contribute, clone the repository, make a focused change, run the build and disposable core checks, and open a pull request. Existing state formats remain compatible with 0.6.2.

```powershell
.\scripts\verify-core.ps1 -Executable .\build\Zero.exe
```

This creates a new temporary fixture directory, processes only its disposable selected files, and retains the results. It never selects your saved profiles or folders. Unit tests cover multi-chunk authenticated staging, ciphertext readback, identity changes, recovery, filters, storage observations, signatures and scheduler XML.

For a new release, update the version in `Cargo.toml` and `Cargo.lock`, add its changelog section, commit a clean Git tree, build, then run:

```powershell
.\package-release.ps1
.\scripts\check-release.ps1 -Directory .\release-artifacts -ExtractTo .\fresh-consumer
```

Packaging refuses a changed source, mismatched binary or an existing output directory. It creates a matching Windows ZIP, source ZIP, standalone `Zero.exe`, their three checksum files and `SHA256SUMS`. The checker validates unique archive paths, complete file inventories, source blobs, executable identity and checksums before extracting to a fresh directory. The release workflow pins its actions and Rust version, publishes only a checked main commit, verifies every uploaded asset, and leaves existing published versions unchanged.

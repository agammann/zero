$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $PSScriptRoot 'target' }
    $builtExe = Join-Path $targetRoot 'release\zero.exe'

    cargo test --locked
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    cargo build --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    Copy-Item -LiteralPath $builtExe -Destination (Join-Path $PSScriptRoot 'Zero.exe') -Force

    Write-Host 'Built Zero.exe beside this script.'
} finally {
    Pop-Location
}

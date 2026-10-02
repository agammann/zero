$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$repo = $PSScriptRoot
$output = Join-Path $repo 'dist'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$metadata = cargo metadata --no-deps --format-version 1 --manifest-path (Join-Path $repo 'Cargo.toml') | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Could not read package version.' }
$version = $metadata.packages[0].version

function New-ZeroArchive {
    param([string]$Destination, [string[]]$RelativePaths)
    $stream = [System.IO.File]::Open($Destination, [System.IO.FileMode]::Create)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($relative in $RelativePaths) {
                $source = Join-Path $repo $relative
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing package file: $relative" }
                $entry = $archive.CreateEntry(($relative -replace '\\','/'), [System.IO.Compression.CompressionLevel]::Optimal)
                $entryStream = $entry.Open()
                try {
                    $sourceStream = [System.IO.File]::OpenRead($source)
                    try { $sourceStream.CopyTo($entryStream) } finally { $sourceStream.Dispose() }
                } finally { $entryStream.Dispose() }
            }
        } finally { $archive.Dispose() }
    } finally { $stream.Dispose() }
}

$docs = @('README.md', 'CHANGELOG.md', 'STORAGE_AND_KEY_MODEL.md', 'REMOTE_JOBS.md', 'THIRD_PARTY_NOTICES.md', 'LICENSE')
$sourceFiles = @('Cargo.toml', 'Cargo.lock', 'build-windows.ps1', 'package-release.ps1', '.github\workflows\windows.yml', '.github\workflows\release.yml') + $docs + @('src\main.rs', 'src\filters.rs', 'src\profiles.rs', 'src\receipts.rs', 'src\remote.rs', 'src\storage.rs')
$windowsFiles = @('Zero.exe') + $docs
New-ZeroArchive -Destination (Join-Path $output "Zero-$version-Source.zip") -RelativePaths $sourceFiles
New-ZeroArchive -Destination (Join-Path $output "Zero-$version-Windows.zip") -RelativePaths $windowsFiles

$expectedHash = (Get-FileHash -LiteralPath (Join-Path $repo 'Zero.exe') -Algorithm SHA256).Hash
$archive = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $output "Zero-$version-Windows.zip"))
try {
    $binary = $archive.GetEntry('Zero.exe')
    if ($null -eq $binary) { throw 'Windows archive lacks Zero.exe' }
    $extracted = Join-Path $output 'Zero-archive-check.exe'
    $source = $binary.Open()
    try {
        $destination = [System.IO.File]::Open($extracted, [System.IO.FileMode]::Create)
        try { $source.CopyTo($destination) } finally { $destination.Dispose() }
    } finally { $source.Dispose() }
    $actualHash = (Get-FileHash -LiteralPath $extracted -Algorithm SHA256).Hash
    Remove-Item -LiteralPath $extracted -Force
    if ($actualHash -ne $expectedHash) { throw 'Packaged executable hash mismatch' }
} finally { $archive.Dispose() }
Write-Host "Packaged Zero $version; Zero.exe SHA256=$expectedHash"

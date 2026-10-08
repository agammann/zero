param([string]$OutputDirectory="")
$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot "scripts/build-release.ps1") -OutputDirectory $OutputDirectory

param([string]$BuildDirectory="", [string]$OutputDirectory="")
$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot "scripts/package-release.ps1") -BuildDirectory $BuildDirectory -OutputDirectory $OutputDirectory

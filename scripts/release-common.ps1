$ErrorActionPreference = 'Stop'
function Write-ZeroJson([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 12) + "`n"), (New-Object Text.UTF8Encoding($false)))
}
function Get-ZeroHash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Get-ZeroBlob([byte[]]$Bytes) {
    $header = [Text.Encoding]::UTF8.GetBytes('blob ' + $Bytes.Length + [char]0)
    $buffer = New-Object byte[] ($header.Length + $Bytes.Length)
    [Array]::Copy($header, 0, $buffer, 0, $header.Length)
    [Array]::Copy($Bytes, 0, $buffer, $header.Length, $Bytes.Length)
    $sha = [Security.Cryptography.SHA1]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($buffer))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}
function Assert-ZeroPaths($Entries) {
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Entries) {
        $path = [string]$entry.path
        if (!$path -or $path.Contains('\') -or $path -match '(^/|:|(^|/)\.\.?(/|$)|//)' -or !$seen.Add($path)) { throw "Invalid or duplicate package path: $path" }
    }
    if (!$seen.Count) { throw 'Empty package inventory.' }
}
function Get-ZeroVersion([string]$Root) {
    $version = [regex]::Match([IO.File]::ReadAllText((Join-Path $Root 'Cargo.toml')), '(?m)^version = "(\d+\.\d+\.\d+)"\r?$').Groups[1].Value
    if (!$version) { throw 'Missing stable Cargo package version.' }
    $version
}
function Get-ZeroSource([string]$Root) {
    $commit = $null; $tree = $null; $inventory = @()
    if (Test-Path -LiteralPath (Join-Path $Root '.git')) {
        $commit = (& git -C $Root rev-parse HEAD).Trim(); if ($LASTEXITCODE -ne 0) { throw 'Cannot identify source commit.' }
        $tree = (& git -C $Root rev-parse 'HEAD^{tree}').Trim(); if ($LASTEXITCODE -ne 0) { throw 'Cannot identify source tree.' }
        $inventory = @(& git -C $Root ls-tree -r HEAD | ForEach-Object {
            if ($_ -notmatch '^(100644|100755) blob ([0-9a-f]{40})\t(.+)$') { throw 'Only regular source files are supported.' }
            [ordered]@{path=$Matches[3]; mode=$Matches[1]; blob=$Matches[2]}
        }); if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate source.' }
        $dirty = & git -C $Root status --porcelain --untracked-files=normal
        if ($LASTEXITCODE -ne 0) { throw 'Cannot check source state.' }
        if ($dirty) { $commit = $null; $tree = $null }
    } else {
        $release = Get-Content -LiteralPath (Join-Path $Root 'RELEASE.json') -Raw | ConvertFrom-Json
        if ($release.name -ne 'zero' -or $release.version -ne (Get-ZeroVersion $Root)) { throw 'Source release metadata differs.' }
        $commit = $release.commit; $tree = $release.tree; $inventory = @($release.sourceFiles)
    }
    Assert-ZeroPaths $inventory
    $files = @($inventory | ForEach-Object {
        $path = Join-Path $Root $_.path
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Source must be a regular file: $($_.path)" }
        $blob = Get-ZeroBlob ([IO.File]::ReadAllBytes($path))
        if ($blob -ne $_.blob) { $commit = $null; $tree = $null }
        [ordered]@{path=$_.path;mode=$_.mode;blob=$blob;sha256=(Get-ZeroHash $path)}
    })
    [ordered]@{commit=$commit;tree=$tree;files=$files}
}
function Invoke-ZeroProcess([string]$Executable, [string[]]$Arguments, [string]$Directory, [int]$Seconds=900) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable; $info.WorkingDirectory = $Directory
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $encoded = @($Arguments | ForEach-Object {
        '"' + [regex]::Replace([regex]::Replace($_, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
    })
    $info.Arguments = $encoded -join ' '
    $process = [Diagnostics.Process]::Start($info)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit($Seconds * 1000)) { $process.Kill(); $process.WaitForExit(); throw 'Owned process exceeded its time limit.' }
        [ordered]@{exitCode=$process.ExitCode;stdout=$stdout.Result;stderr=$stderr.Result}
    } finally { $process.Dispose() }
}

param([string]$OutputDirectory='')
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $root 'scripts/release-common.ps1')
if (!$OutputDirectory) { $OutputDirectory = Join-Path $root 'build' }
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output -eq $root -or $root.StartsWith($output.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Build output must not contain the source directory.' }
if (Test-Path -LiteralPath $output) {
    $existing=Get-Item -LiteralPath $output -Force
    if (!$existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Existing build output must be an ordinary Zero build directory.' }
    $previous=Get-Content -LiteralPath (Join-Path $output 'BUILD.json') -Raw | ConvertFrom-Json
    if ($previous.name -ne 'zero' -or (Get-ZeroHash (Join-Path $output 'Zero.exe')) -ne $previous.executableSha256) { throw 'Refusing to replace an unrecognized build output.' }
}
$cargo = (Get-Command cargo -ErrorAction Stop).Source
$rustc = (Get-Command rustc -ErrorAction Stop).Source
$source = Get-ZeroSource $root
$version = Get-ZeroVersion $root
$stage = Join-Path $root ('build-staging/' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
$priorTemp=$env:TEMP; $priorTmp=$env:TMP; $priorAppData=$env:LOCALAPPDATA
try {
    $env:TEMP = Join-Path $stage 'tmp'; $env:TMP = $env:TEMP
    $env:LOCALAPPDATA = Join-Path $stage 'appdata'
    New-Item -ItemType Directory -Path $env:TEMP,$env:LOCALAPPDATA | Out-Null
    $steps = @()
    foreach ($spec in @(
        @{name='format';arguments=@('fmt','--all','--','--check')},
        @{name='tests';arguments=@('test','--locked')},
        @{name='lint';arguments=@('clippy','--locked','--all-targets','--','-D','warnings')},
        @{name='build';arguments=@('build','--release','--locked')}
    )) {
        $result = Invoke-ZeroProcess $cargo $spec.arguments $root
        [IO.File]::WriteAllText((Join-Path $stage ($spec.name+'.log')), $result.stdout+$result.stderr)
        if ($result.exitCode -ne 0) { throw "The $($spec.name) check failed. Logs retained in $stage" }
        $steps += [ordered]@{name=$spec.name;exitCode=$result.exitCode}
        Write-Host "PASS: $($spec.name)"
    }
    $target = if ($env:CARGO_TARGET_DIR) {
        if ([IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) { [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR) }
        else { [IO.Path]::GetFullPath((Join-Path $root $env:CARGO_TARGET_DIR)) }
    } else { Join-Path $root 'target' }
    Copy-Item -LiteralPath (Join-Path $target 'release/zero.exe') -Destination (Join-Path $stage 'Zero.exe')
    $actualVersion = Invoke-ZeroProcess (Join-Path $stage 'Zero.exe') @('--quiet','--version') $root 15
    if ($actualVersion.exitCode -ne 0 -or $actualVersion.stdout.Trim() -ne "Zero $version") { throw 'Executable version differs from the source.' }
    $after = Get-ZeroSource $root
    if (($after | ConvertTo-Json -Depth 8 -Compress) -ne ($source | ConvertTo-Json -Depth 8 -Compress)) { throw 'Source changed during the build.' }
    $compiler = Invoke-ZeroProcess $rustc @('--version','--verbose') $root 15
    if ($compiler.exitCode -ne 0) { throw 'Cannot record Rust compiler.' }
    $receipt = [ordered]@{name='zero';version=$version;commit=$source.commit;tree=$source.tree;sourceFiles=$source.files;executableSha256=(Get-ZeroHash (Join-Path $stage 'Zero.exe'));compiler=$compiler.stdout.Trim();builtAt=[DateTimeOffset]::UtcNow.ToString('o');checks=$steps}
    Write-ZeroJson (Join-Path $stage 'BUILD.json') $receipt
    if (Test-Path -LiteralPath $output) {
        $history = Join-Path $root 'build-history'
        New-Item -ItemType Directory -Path $history -Force | Out-Null
        Move-Item -LiteralPath $output -Destination (Join-Path $history ([Guid]::NewGuid().ToString('N')))
    }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($output)) | Out-Null
    Move-Item -LiteralPath $stage -Destination $output
    Write-Host "Built Zero $version in $output. Previous successful output is preserved in build-history."
} finally { $env:TEMP=$priorTemp; $env:TMP=$priorTmp; $env:LOCALAPPDATA=$priorAppData }

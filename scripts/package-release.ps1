param([string]$BuildDirectory='', [string]$OutputDirectory='')
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $root 'scripts/release-common.ps1')
if (!$BuildDirectory) { $BuildDirectory=Join-Path $root 'build' }
if (!$OutputDirectory) { $OutputDirectory=Join-Path $root 'release-artifacts' }
$buildRoot=[IO.Path]::GetFullPath($BuildDirectory); $output=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Release output exists; preserve it and choose a fresh directory.' }
$source=Get-ZeroSource $root; $version=Get-ZeroVersion $root
if (!$source.commit -or !$source.tree) { throw 'Release packaging requires a clean committed Git source tree.' }
$build=Get-Content -LiteralPath (Join-Path $buildRoot 'BUILD.json') -Raw | ConvertFrom-Json
if ($build.version -ne $version -or $build.commit -ne $source.commit -or $build.tree -ne $source.tree -or ($env:GITHUB_SHA -and $env:GITHUB_SHA -ne $source.commit)) { throw 'The checked build belongs to another source revision.' }
if (($build.sourceFiles | ConvertTo-Json -Depth 8 -Compress) -ne ($source.files | ConvertTo-Json -Depth 8 -Compress)) { throw 'Build inputs have changed.' }
$exe=Join-Path $buildRoot 'Zero.exe'
if ((Get-ZeroHash $exe) -ne $build.executableSha256) { throw 'Executable differs from the checked build.' }
$stage=Join-Path $root ('release-staging/'+[Guid]::NewGuid().ToString('N'))
$windows=Join-Path $stage "Zero-$version"
New-Item -ItemType Directory -Path $windows | Out-Null
Copy-Item -LiteralPath $exe,(Join-Path $buildRoot 'BUILD.json') -Destination $windows
$docs=@('README.md','BUILD.md','VERIFIED.md','CHANGELOG.md','STORAGE_AND_KEY_MODEL.md','REMOTE_JOBS.md','THIRD_PARTY_NOTICES.md','LICENSE')
foreach ($name in $docs) { Copy-Item -LiteralPath (Join-Path $root $name) -Destination $windows }
$payloads=@(Get-ChildItem -LiteralPath $windows -File | Sort-Object Name | ForEach-Object { [ordered]@{path=$_.Name;sha256=(Get-ZeroHash $_.FullName)} })
$release=[ordered]@{name='zero';version=$version;commit=$source.commit;tree=$source.tree;sourceFiles=$source.files;executableSha256=$build.executableSha256;windowsFiles=$payloads}
Write-ZeroJson (Join-Path $windows 'RELEASE.json') $release
New-Item -ItemType Directory -Path $output | Out-Null
$sourceName="Zero-$version-Source.zip"; $windowsName="Zero-$version-Windows.zip"
& git -C $root -c core.autocrlf=false archive --format=zip "--prefix=Zero-$version-Source/" "--output=$(Join-Path $output $sourceName)" HEAD
if ($LASTEXITCODE -ne 0) { throw 'Source archive failed.' }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.Compression.ZipFile]::Open((Join-Path $output $sourceName),[IO.Compression.ZipArchiveMode]::Update)
try {
    $entry=$archive.CreateEntry("Zero-$version-Source/RELEASE.json"); $stream=$entry.Open()
    try { $bytes=[IO.File]::ReadAllBytes((Join-Path $windows 'RELEASE.json')); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
} finally { $archive.Dispose() }
$archive=[IO.Compression.ZipFile]::Open((Join-Path $output $windowsName),[IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in @(Get-ChildItem -LiteralPath $windows -File | Sort-Object Name)) {
        $entry=$archive.CreateEntry("Zero-$version/"+$file.Name,[IO.Compression.CompressionLevel]::Optimal)
        $stream=$entry.Open()
        try { $bytes=[IO.File]::ReadAllBytes($file.FullName); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    }
} finally { $archive.Dispose() }
Copy-Item -LiteralPath $exe -Destination (Join-Path $output 'Zero.exe')
$combined=''; $utf8=New-Object Text.UTF8Encoding($false)
foreach ($name in @($sourceName,$windowsName,'Zero.exe')) {
    $line=(Get-ZeroHash (Join-Path $output $name))+'  '+$name+"`n"
    [IO.File]::WriteAllText((Join-Path $output ($name+'.sha256')),$line,$utf8); $combined+=$line
}
[IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS'),$combined,$utf8)
& (Join-Path $root 'scripts/check-release.ps1') -Directory $output
Write-Host "Packaged Zero $version from $($source.commit)."

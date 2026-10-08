param([Parameter(Mandatory=$true)][string]$Directory, [string]$ExtractTo='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'release-common.ps1')
$Directory=[IO.Path]::GetFullPath($Directory)
$sourceArchives=@(Get-ChildItem -LiteralPath $Directory -File -Filter 'Zero-*-Source.zip')
if ($sourceArchives.Count -ne 1 -or $sourceArchives[0].Name -notmatch '^Zero-(\d+\.\d+\.\d+)-Source\.zip$') { throw 'Expected one versioned source archive.' }
$version=$Matches[1]; $sourceName="Zero-$version-Source.zip"; $windowsName="Zero-$version-Windows.zip"
$files=@($sourceName,$windowsName,'Zero.exe'); $expected=@('SHA256SUMS')+@($files | ForEach-Object { $_; $_+'.sha256' })
if ((((Get-ChildItem -LiteralPath $Directory -Force).Name | Sort-Object) -join "`n") -cne (($expected | Sort-Object) -join "`n")) { throw 'Release asset inventory differs.' }
$combined=''
foreach ($name in $files) {
    $item=Get-Item -LiteralPath (Join-Path $Directory $name) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Release assets must be regular files.' }
    $line=(Get-ZeroHash $item.FullName)+'  '+$name+"`n"
    if ([IO.File]::ReadAllText((Join-Path $Directory ($name+'.sha256'))) -cne $line) { throw "Checksum differs: $name" }
    $combined+=$line
}
if ([IO.File]::ReadAllText((Join-Path $Directory 'SHA256SUMS')) -cne $combined) { throw 'Combined checksums differ.' }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Read-Archive([string]$Name,[string]$Prefix) {
    $archive=[IO.Compression.ZipFile]::OpenRead((Join-Path $Directory $Name))
    try {
        $entries=@($archive.Entries | Where-Object { !$_.FullName.EndsWith('/') })
        if ($entries.Count -gt 1000 -or ($entries | Measure-Object Length -Sum).Sum -gt 20000000) { throw 'Unexpected archive size.' }
        $map=New-Object 'System.Collections.Generic.Dictionary[string,byte[]]' ([StringComparer]::Ordinal)
        $paths=@()
        foreach ($entry in $entries) {
            if (!$entry.FullName.StartsWith($Prefix,[StringComparison]::Ordinal)) { throw 'Unexpected archive root.' }
            $relative=$entry.FullName.Substring($Prefix.Length)
            $paths+=@{path=$relative}
            if ($entry.Length -gt 10000000) { throw 'Unexpected archive entry size.' }
            $stream=$entry.Open(); $memory=New-Object IO.MemoryStream
            try { $stream.CopyTo($memory); $map.Add($relative,$memory.ToArray()) } finally { $stream.Dispose();$memory.Dispose() }
        }
        Assert-ZeroPaths $paths
        return ,$map
    } finally { $archive.Dispose() }
}
function Digest([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}
$source=Read-Archive $sourceName "Zero-$version-Source/"; $windows=Read-Archive $windowsName "Zero-$version/"
$sourceJson=[Text.Encoding]::UTF8.GetString($source['RELEASE.json']); $windowsJson=[Text.Encoding]::UTF8.GetString($windows['RELEASE.json'])
if ($sourceJson -cne $windowsJson) { throw 'Source and Windows release receipts differ.' }
$release=$sourceJson | ConvertFrom-Json
if ($release.name -ne 'zero' -or $release.version -ne $version -or $release.commit -notmatch '^[0-9a-f]{40}$' -or $release.tree -notmatch '^[0-9a-f]{40}$') { throw 'Invalid release identity.' }
Assert-ZeroPaths $release.sourceFiles; Assert-ZeroPaths $release.windowsFiles
if ((($source.Keys | Sort-Object) -join "`n") -cne ((@($release.sourceFiles.path)+@('RELEASE.json') | Sort-Object) -join "`n")) { throw 'Source archive file set differs.' }
if ((($windows.Keys | Sort-Object) -join "`n") -cne ((@($release.windowsFiles.path)+@('RELEASE.json') | Sort-Object) -join "`n")) { throw 'Windows archive file set differs.' }
foreach ($entry in $release.sourceFiles) {
    if ((Digest $source[$entry.path]) -ne $entry.sha256 -or (Get-ZeroBlob $source[$entry.path]) -ne $entry.blob -or $entry.mode -notin @('100644','100755')) { throw "Source bytes differ: $($entry.path)" }
}
foreach ($entry in $release.windowsFiles) { if ((Digest $windows[$entry.path]) -ne $entry.sha256) { throw "Windows bytes differ: $($entry.path)" } }
if ((Digest $windows['Zero.exe']) -ne $release.executableSha256 -or (Get-ZeroHash (Join-Path $Directory 'Zero.exe')) -ne $release.executableSha256) { throw 'Executable editions differ.' }
$build=[Text.Encoding]::UTF8.GetString($windows['BUILD.json']) | ConvertFrom-Json
if ($build.name -ne 'zero' -or $build.version -ne $version -or $build.commit -ne $release.commit -or $build.tree -ne $release.tree -or $build.executableSha256 -ne $release.executableSha256 -or ($build.sourceFiles | ConvertTo-Json -Depth 8 -Compress) -cne ($release.sourceFiles | ConvertTo-Json -Depth 8 -Compress)) { throw 'Build and release source identity differ.' }
if ($ExtractTo) {
    $destination=[IO.Path]::GetFullPath($ExtractTo)
    if (Test-Path -LiteralPath $destination) { throw 'Extraction destination exists; choose a fresh directory.' }
    New-Item -ItemType Directory -Path $destination | Out-Null
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $Directory $sourceName),(Join-Path $destination 'source'))
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $Directory $windowsName),(Join-Path $destination 'windows'))
}
Write-Host "Verified Zero ${version}: exact source and Windows inventories, checksums and build identity."

param([Parameter(Mandatory=$true)][string]$Executable, [string]$OutputDirectory='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'release-common.ps1')
$exe=[IO.Path]::GetFullPath($Executable)
if (!$OutputDirectory) { $OutputDirectory=Join-Path $env:TEMP ('zero-verification-'+[Guid]::NewGuid().ToString('N')) }
$root=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $root) { throw 'Fixture destination exists; choose a fresh directory.' }
New-Item -ItemType Directory -Path $root | Out-Null
$state=Join-Path $root 'state'; $info=Join-Path $root 'information'; $files=Join-Path $root 'files'; $receipts=Join-Path $root 'receipts'
New-Item -ItemType Directory -Path $state,$info,$files,$receipts | Out-Null
$checks=New-Object 'System.Collections.Generic.List[object]'
function Check([bool]$Condition,[string]$Name) { if (!$Condition) { throw "Failed: $Name" }; $checks.Add(@{name=$Name;passed=$true}) }
function Run([string[]]$Arguments,[string]$Store=$state,[int]$Expected=0) {
    $result=Invoke-ZeroProcess $exe (@('--quiet','--state-dir',$Store)+$Arguments) $root 40
    if ($result.exitCode -ne $Expected) { throw "Unexpected exit $($result.exitCode) for $($Arguments -join ' '); fixture retained at $root" }
    $result
}
$report=[ordered]@{name='zero';executableSha256=(Get-ZeroHash $exe);fixtureRoot=$root;checks=@();status='running'}
try {
    $v=Invoke-ZeroProcess $exe @('--quiet','--version') $root 10
    Check ($v.exitCode -eq 0 -and $v.stdout -match '^Zero \d+\.\d+\.\d+\s*$') 'version command'
    $h=Invoke-ZeroProcess $exe @('--quiet','--help') $root 10
    Check ($h.exitCode -eq 0 -and $h.stdout.Contains('--preview')) 'help command'
    [IO.File]::WriteAllText((Join-Path $info 'pending-keep.json'),'{corrupt recovery fixture}')
    $original=Get-ZeroHash (Join-Path $info 'pending-keep.json')
    $null=Run @() $info
    $null=Run @('--unsupported-option') $info 1
    Check ((Get-ZeroHash (Join-Path $info 'pending-keep.json')) -eq $original) 'empty selection and unknown option preserve recovery record'
    $recoveryFile=Join-Path $info 'untouched.bin'; [IO.File]::WriteAllText($recoveryFile,'replacement stays untouched')
    $recoveryHash=Get-ZeroHash $recoveryFile
    $null=Run @($recoveryFile) $info 1
    Check ((Get-ZeroHash $recoveryFile) -eq $recoveryHash -and (Get-ZeroHash (Join-Path $info 'pending-keep.json')) -eq $original) 'corrupt recovery stops processing and preserves file and record'
    $sibling=Join-Path $root 'keep.txt'; [IO.File]::WriteAllText($sibling,'unselected sentinel')
    $sentinel=Get-ZeroHash $sibling
    $selected=Join-Path $files 'selected.bin'; [IO.File]::WriteAllBytes($selected,(New-Object byte[] 2097197))
    $null=Run @('--receipts',$receipts,$selected)
    Check (!(Test-Path -LiteralPath $selected) -and (Get-ZeroHash $sibling) -eq $sentinel) 'selected file removed and sibling preserved'
    $public=Join-Path $root 'trusted-public.hex'; $null=Run @('--export-key',$public)
    $receipt=@(Get-ChildItem -LiteralPath $receipts -File -Filter '*.json')
    Check ($receipt.Count -eq 1) 'one receipt for one selected file'
    $null=Run @('--verify-receipt',$receipt[0].FullName,$public)
    Check $true 'receipt verifies with separately exported trusted public key'
    $tampered=Join-Path $root 'tampered.json'; $body=Get-Content -LiteralPath $receipt[0].FullName -Raw | ConvertFrom-Json
    $body.body.selected_path='changed'; Write-ZeroJson $tampered $body
    $null=Run @('--verify-receipt',$tampered,$public) $state 1
    Check ((Get-ZeroHash $sibling) -eq $sentinel) 'tampered receipt refused without processing files'
    $drop=Join-Path $root 'profile-drop'; New-Item -ItemType Directory -Path $drop | Out-Null
    foreach ($name in @('remove.tmp','keep.tmp','keep.txt')) { [IO.File]::WriteAllText((Join-Path $drop $name),'disposable profile fixture') }
    $profile='OwnedFixture'; $null=Run @('--create-profile',$profile,'--include-ext','.tmp','--exclude-name','keep*',$drop)
    $profilePath=Join-Path $state "profiles/$profile.json"; $profileHash=Get-ZeroHash $profilePath
    $null=Run @('--create-profile',$profile,$drop) $state 1
    Check ((Get-ZeroHash $profilePath) -eq $profileHash) 'duplicate profile cannot replace an existing selection'
    $null=Run @('--profile',$profile)
    Check ((Test-Path -LiteralPath $drop -PathType Container) -and !(Test-Path -LiteralPath (Join-Path $drop 'remove.tmp')) -and (Test-Path -LiteralPath (Join-Path $drop 'keep.tmp')) -and (Test-Path -LiteralPath (Join-Path $drop 'keep.txt'))) 'profile retains folder and excluded files'
    [IO.File]::WriteAllText((Join-Path $state 'profiles/Corrupt.json'),'{invalid profile}')
    $corrupt=Get-ZeroHash (Join-Path $state 'profiles/Corrupt.json'); $before=Get-ZeroHash (Join-Path $drop 'keep.tmp')
    $null=Run @('--profile','Corrupt') $state 1
    Check ((Get-ZeroHash (Join-Path $state 'profiles/Corrupt.json')) -eq $corrupt -and (Get-ZeroHash (Join-Path $drop 'keep.tmp')) -eq $before) 'corrupt profile preserved without processing replacement files'
    $null=Run @('--volume',$files) $state 1
    Check ((Get-ZeroHash $sibling) -eq $sentinel) 'whole-volume command refused'
    $report.status='passed'
} catch { $report.status='failed'; $report.error=$_.Exception.Message; throw }
finally { $report.checks=$checks.ToArray(); Write-ZeroJson (Join-Path $root 'result.json') $report }
Write-Host "Passed $($checks.Count) disposable Zero core checks. Fixtures retained at $root."

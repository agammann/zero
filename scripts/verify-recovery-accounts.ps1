param(
    [Parameter(Mandatory)][string]$TestExecutable,
    [Parameter(Mandatory)][string]$ProductExecutable
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Refuse to create users or credentials on a developer's machine or self-hosted runner.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Account tests run only in disposable GitHub-hosted Windows runners.'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Disposable runner administrator access is required to create test accounts.'
}
$tempRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
$runRoot = Join-Path $tempRoot ('zero-recovery-accounts-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $runRoot) { throw 'Fixture root already exists.' }
$fixture = Join-Path $runRoot 'fixture'
$accounts = [Collections.Generic.List[object]]::new()
$evidence = [Collections.Generic.List[object]]::new()
$cleanupErrors = [Collections.Generic.List[string]]::new()
$activeProcess = $null

function Invoke-AccountFixture($Account, [string]$Mode) {
    $stdout = Join-Path $runRoot "$Mode.stdout.txt"
    $stderr = Join-Path $runRoot "$Mode.stderr.txt"
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        ('"' + (Join-Path $runRoot 'actor.ps1') + '"'), '-TestExecutable',
        ('"' + (Join-Path $runRoot 'fixture-tests.exe') + '"'), '-Fixture', ('"' + $fixture + '"'),
        '-Mode', $Mode, '-ExpectedSid', $Account.Sid)
    $script:activeProcess = Start-Process -FilePath "$env:SystemRoot/System32/WindowsPowerShell/v1.0/powershell.exe" `
        -ArgumentList $arguments -Credential $Account.Credential -LoadUserProfile -WindowStyle Hidden `
        -WorkingDirectory $runRoot -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    if (-not $script:activeProcess.WaitForExit(120000)) {
        $script:activeProcess.Kill($true)
        $script:activeProcess.WaitForExit()
        throw "Account fixture $Mode timed out."
    }
    $script:activeProcess.Refresh()
    $code = $script:activeProcess.ExitCode
    $script:activeProcess = $null
    $output = Get-Content -LiteralPath $stdout -Raw
    Write-Host $output
    Write-Host (Get-Content -LiteralPath $stderr -Raw)
    if ($code -ne 0) { throw "Account fixture $Mode exited $code." }
    # libtest may print its test-name prefix before the first captured line.
    $matches = [regex]::Matches($output, 'ZERO_ACCOUNT_EVIDENCE=(\{[^\r\n]+\})')
    if ($matches.Count -ne 1) { throw "Account fixture $Mode must produce exactly one success record." }
    $result = $matches[0].Groups[1].Value | ConvertFrom-Json
    if ($result.sid -ne $Account.Sid -or $result.mode -ne $Mode) { throw 'Actor identity/mode mismatch.' }
    $evidence.Add($result)
}

function Get-FixtureSnapshot {
    $paths = @((Join-Path $fixture 'selected.bin'), (Join-Path $fixture 'encrypted-stage.tmp'))
    $records = @(Get-ChildItem -LiteralPath (Join-Path $fixture 'state') -File)
    if ($records.Count -ne 1 -or $records[0].Name -notlike 'pending-*.json') { throw 'Expected exactly one signed recovery record.' }
    $paths += $records[0].FullName
    return (($paths | ForEach-Object {
        [ordered]@{path=$_; length=(Get-Item -LiteralPath $_).Length; sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
    }) | ConvertTo-Json -Compress)
}

function Get-AuthoritySnapshot {
    $owner = Join-Path $fixture 'authority/owner'
    $files = @(Get-ChildItem -LiteralPath $owner -File -Recurse | Where-Object Name -ne 'last-error.txt' | Sort-Object FullName)
    if ($files.Count -ne 6) { throw 'Expected six protected owner files.' }
    return (($files | ForEach-Object {
        [ordered]@{path=$_.FullName; length=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    }) | ConvertTo-Json -Compress)
}

try {
    New-Item -ItemType Directory -Path $fixture | Out-Null
    Copy-Item -LiteralPath (Resolve-Path -LiteralPath $TestExecutable).Path -Destination (Join-Path $runRoot 'fixture-tests.exe')
    Copy-Item -LiteralPath (Resolve-Path -LiteralPath $ProductExecutable).Path -Destination (Join-Path $runRoot 'fixture-product.exe')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'verify-recovery-account-actor.ps1') -Destination (Join-Path $runRoot 'actor.ps1')
    $usersGroup = (Get-LocalGroup -SID 'S-1-5-32-545').Name
    foreach ($role in @('a','b')) {
        $name = 'zero' + $role + [Guid]::NewGuid().ToString('N').Substring(0, 12)
        if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { throw 'Generated account name already exists.' }
        $password = ConvertTo-SecureString ([Guid]::NewGuid().ToString('N') + 'aA1!') -AsPlainText -Force
        $user = New-LocalUser -Name $name -Password $password -Description 'Disposable Zero CI recovery fixture'
        $account = [pscustomobject]@{Name=$name; Sid=$user.SID.Value; Credential=[PSCredential]::new("$env:COMPUTERNAME\$name", $password)}
        $accounts.Add($account)
        Add-LocalGroupMember -Group $usersGroup -Member $user
        # Executable and actor script are read-only to actors; only generated fixtures are writable.
        & icacls.exe $runRoot /grant ('*' + $account.Sid + ':(OI)(CI)RX') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot grant fixture traversal/read access.' }
        & icacls.exe $fixture /grant ('*' + $account.Sid + ':(OI)(CI)M') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot grant synthetic fixture modify access.' }
    }
    if ($accounts[0].Sid -eq $accounts[1].Sid) { throw 'Test accounts must have distinct SIDs.' }
    Invoke-AccountFixture $accounts[0] 'create'
    Invoke-AccountFixture $accounts[0] 'state-create'
    $before = Get-FixtureSnapshot
    $authorityBefore = Get-AuthoritySnapshot
    Invoke-AccountFixture $accounts[1] 'reject-missing'
    if ((Get-FixtureSnapshot) -cne $before) { throw 'Missing-credential refusal changed a fixture or record.' }
    Invoke-AccountFixture $accounts[1] 'state-reject-missing'
    if ((Get-AuthoritySnapshot) -cne $authorityBefore) { throw 'Missing-credential refusal changed owner state or selected files.' }
    Invoke-AccountFixture $accounts[1] 'seed-own-key'
    Invoke-AccountFixture $accounts[1] 'state-other-key'
    Invoke-AccountFixture $accounts[1] 'reject-foreign'
    if ((Get-FixtureSnapshot) -cne $before) { throw 'Foreign-credential refusal changed a fixture or record.' }
    Invoke-AccountFixture $accounts[1] 'state-reject-foreign'
    if ((Get-AuthoritySnapshot) -cne $authorityBefore) { throw 'Foreign-credential refusal changed owner state or selected files.' }
    Invoke-AccountFixture $accounts[0] 'recover'
    if (Test-Path -LiteralPath (Join-Path $fixture 'selected.bin')) { throw 'Owner recovery left the selected file.' }
    if (Test-Path -LiteralPath (Join-Path $fixture 'encrypted-stage.tmp')) { throw 'Owner recovery left the staged file.' }
    if (@(Get-ChildItem -LiteralPath (Join-Path $fixture 'state') -File).Count -ne 0) { throw 'Owner recovery left its pending record.' }
    Invoke-AccountFixture $accounts[0] 'state-owner'
    if (($evidence | Select-Object -ExpandProperty pid -Unique).Count -ne 10) { throw 'Each test phase must run in a separate process.' }
    Write-Host 'PASS: distinct unprivileged SIDs, real modify access, both authentication refusals preserve bytes/identities, and separate-process owner recovery succeeds.'
    Write-Host 'PASS: profile/enrollment/snapshot account isolation, actual receipt-backed CLI refusals, independent receipt/result keys, and owner credential reuse.'
    $evidence | ConvertTo-Json -Depth 4 | Write-Host
} finally {
    if ($null -ne $activeProcess -and -not $activeProcess.HasExited) {
        $activeProcess.Kill($true)
        $activeProcess.WaitForExit()
    }
    foreach ($account in $accounts) {
        try {
            # Remove only the newly created account's profile, including its test credential store.
            $profiles = @(Get-CimInstance Win32_UserProfile -Filter "SID='$($account.Sid)'")
            foreach ($profile in $profiles) {
                $profilePath = [IO.Path]::GetFullPath($profile.LocalPath)
                $expectedParent = [IO.Path]::GetDirectoryName([Environment]::GetFolderPath('UserProfile'))
                if ([IO.Path]::GetDirectoryName($profilePath) -ne $expectedParent -or
                    [IO.Path]::GetFileName($profilePath) -notlike "$($account.Name)*" -or $profile.Special -or $profile.Loaded) {
                    throw 'Refusing to remove an unexpected or loaded test profile.'
                }
                Remove-CimInstance -InputObject $profile
            }
            Remove-LocalUser -SID $account.Sid
            if (Get-LocalUser -SID $account.Sid -ErrorAction SilentlyContinue) { throw 'Test account cleanup did not complete.' }
        } catch { $cleanupErrors.Add("$($account.Name): $_") }
    }
    if (Test-Path -LiteralPath $runRoot) {
        try {
            $resolved = (Resolve-Path -LiteralPath $runRoot).Path
            if ([IO.Path]::GetDirectoryName($resolved) -ne $tempRoot -or
                [IO.Path]::GetFileName($resolved) -notlike 'zero-recovery-accounts-*') {
                throw 'Refusing cleanup outside the exact generated runner fixture root.'
            }
            if ((Get-Item -LiteralPath $resolved -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Refusing cleanup through a reparse point at the fixture root.'
            }
            if (@(Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
                throw 'Refusing recursive cleanup through a reparse point.'
            }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        } catch { $cleanupErrors.Add("Fixture cleanup: $_") }
    }
    if ($cleanupErrors.Count) { throw ($cleanupErrors -join "`n") }
    Write-Host 'PASS: exact temporary accounts, profiles, credentials, and fixture directory cleaned up.'
}

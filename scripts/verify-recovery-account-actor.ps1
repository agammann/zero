param(
    [Parameter(Mandatory)][string]$TestExecutable,
    [Parameter(Mandatory)][string]$Fixture,
    [Parameter(Mandatory)][string]$Mode,
    [Parameter(Mandatory)][string]$ExpectedSid
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Account tests run only in disposable GitHub-hosted runners.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne $ExpectedSid) { throw 'Unexpected actor SID.' }
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The fixture actor must be an unprivileged account.'
}
$env:ZERO_ACCOUNT_FIXTURE = $Fixture
$env:ZERO_ACCOUNT_MODE = $Mode
$env:ZERO_ACCOUNT_EXPECTED_SID = $ExpectedSid
& $TestExecutable --ignored --exact recovery_account_tests::recovery_cross_account_driver --nocapture
if ($LASTEXITCODE -ne 0) { throw "Account fixture mode $Mode failed: $LASTEXITCODE" }

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
# The product crate uses the Windows GUI subsystem, including its test binary.
# Windows PowerShell's call operator does not reliably wait/set LASTEXITCODE for it.
$process = [Diagnostics.Process]::new()
$process.StartInfo = [Diagnostics.ProcessStartInfo]::new()
$process.StartInfo.FileName = $TestExecutable
$process.StartInfo.Arguments = '--ignored --exact recovery_account_tests::recovery_cross_account_driver --nocapture'
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
try {
    if (-not $process.Start()) { throw 'Could not start the exact fixture executable.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(60000)) {
        $process.Kill()
        $process.WaitForExit()
        throw "Account fixture mode $Mode timed out."
    }
    [Console]::Out.Write($stdout.GetAwaiter().GetResult())
    [Console]::Error.Write($stderr.GetAwaiter().GetResult())
    if ($process.ExitCode -ne 0) { throw "Account fixture mode $Mode failed: $($process.ExitCode)" }
} finally { $process.Dispose() }

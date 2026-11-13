param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Never run this native credential/task fixture on an operator's workstation.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne 'agammann/zero') {
    throw 'This fixture requires a disposable GitHub-hosted Windows runner.'
}
. (Join-Path $PSScriptRoot 'release-common.ps1')
$exe = (Resolve-Path -LiteralPath $Executable).Path
$temporary = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')
$output = Join-Path $temporary 'zero-interactive-results'
$root = Join-Path $temporary ('zero-interactive-fixture-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $root) { throw 'Fixture directory must be new.' }
New-Item -ItemType Directory -Path $output -Force | Out-Null
New-Item -ItemType Directory -Path $root | Out-Null

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class ZeroInteractiveNative {
    [StructLayout(LayoutKind.Sequential)] public struct Session { public int Id; public IntPtr Station; public int State; }
    [DllImport("wtsapi32.dll", SetLastError=true)] static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("wtsapi32.dll", SetLastError=true)] static extern bool WTSQuerySessionInformationW(IntPtr server, int id, int kind, out IntPtr value, out int bytes);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr value);
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CommandLineToArgvW(string text, out int count);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredReadW(string target, int type, int flags, out IntPtr value);
    [DllImport("advapi32.dll")] static extern void CredFree(IntPtr value);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredDeleteW(string target, int type, int flags);
    const string Target = "Zero/recovery-record-signing-key/v1";
    public static Session[] Sessions() {
        IntPtr data; int count;
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out data, out count)) throw new Win32Exception();
        try { var result = new Session[count]; for (int i=0; i<count; i++) result[i] = Marshal.PtrToStructure<Session>(IntPtr.Add(data, i*Marshal.SizeOf<Session>())); return result; }
        finally { WTSFreeMemory(data); }
    }
    public static string SessionText(int id, int kind) {
        IntPtr data; int bytes;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, id, kind, out data, out bytes)) throw new Win32Exception();
        try { return Marshal.PtrToStringUni(data) ?? ""; } finally { WTSFreeMemory(data); }
    }
    public static string[] Arguments(string text) {
        int count; var data=CommandLineToArgvW("fixture.exe " + text, out count);
        if (data==IntPtr.Zero) throw new Win32Exception();
        try { var result=new string[count-1]; for(int i=1;i<count;i++) result[i-1]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(data,i*IntPtr.Size)); return result; }
        finally { LocalFree(data); }
    }
    public static bool HasCredential() {
        IntPtr data;
        if (CredReadW(Target,1,0,out data)) { CredFree(data); return true; }
        int error=Marshal.GetLastWin32Error(); if(error==1168) return false; throw new Win32Exception(error);
    }
    public static void DeleteFixtureCredential() {
        if(!CredDeleteW(Target,1,0) && Marshal.GetLastWin32Error()!=1168) throw new Win32Exception();
    }
}
'@

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
$report = [ordered]@{status='running';commit=$env:GITHUB_SHA;runnerImage=$env:ImageOS;identity=$identity.Name;sid=$sid;processSession=(Get-Process -Id $PID).SessionId;executableSha256=(Get-ZeroHash $exe);sessions=@();checks=@();cleanup=@{taskRemoved=$false;credentialRemoved=$false;fixtureRemoved=$false}}
$checks = [Collections.Generic.List[string]]::new()
$task = $null
$credentialWasAbsent = $false
$registered = $false
function Check([bool]$Condition,[string]$Name) { if (!$Condition) { throw $Name }; $checks.Add($Name) }
function Run-Zero([string[]]$Arguments) {
    $result = Invoke-ZeroProcess $exe (@('--quiet','--state-dir',$state)+$Arguments) $root 30
    if ($result.exitCode -ne 0) { throw "Zero failed ($($result.exitCode)): $($result.stderr)" }
}
try {
    $sessions = @([ZeroInteractiveNative]::Sessions() | ForEach-Object {
        $user = ''; $domain = ''
        if ($_.Id -gt 0 -and $_.State -in @(0,1,4)) {
            $user = [ZeroInteractiveNative]::SessionText($_.Id,5)
            $domain = [ZeroInteractiveNative]::SessionText($_.Id,7)
        }
        $ownerSid = ''
        if ($user) { $ownerSid = ([Security.Principal.NTAccount]::new($domain,$user)).Translate([Security.Principal.SecurityIdentifier]).Value }
        [pscustomobject]@{id=$_.Id;state=$_.State;user=$user;domain=$domain;sid=$ownerSid}
    })
    $report.sessions = $sessions
    $interactive = @($sessions | Where-Object {$_.id -gt 0 -and $_.state -in @(0,4) -and $_.sid -eq $sid})
    if (!$interactive.Count) {
        $report.status = 'unsupported-runner-session'
        throw 'No pre-existing interactive session for this identity. Registration or a noninteractive fallback cannot establish InteractiveToken execution.'
    }
    $report.interactiveSessionIds = @($interactive.id)
    Check (![ZeroInteractiveNative]::HasCredential()) 'Disposable runner initially has no Zero recovery credential'
    $credentialWasAbsent = $true
    $state = Join-Path $root 'state'
    $receipts = Join-Path $root 'receipts'
    New-Item -ItemType Directory -Path $state,$receipts | Out-Null
    $selected = Join-Path $root 'selected-synthetic.bin'
    $sentinel = Join-Path $root 'unselected-synthetic.bin'
    [IO.File]::WriteAllBytes($selected,[Security.Cryptography.RandomNumberGenerator]::GetBytes(1048593))
    [IO.File]::WriteAllBytes($sentinel,[Security.Cryptography.RandomNumberGenerator]::GetBytes(257))
    $sentinelHash = Get-ZeroHash $sentinel
    $profile = 'Interactive-' + [Guid]::NewGuid().ToString('N')
    Run-Zero @('--create-profile',$profile,'--receipts',$receipts,$selected)
    $before = @(Get-ScheduledTask | Where-Object {$_.TaskName -like "Zero@*-Profile-$profile"})
    Check ($before.Count -eq 0) 'No task with the generated fixture profile exists'
    $registered = $true
    Run-Zero @('--schedule',$profile,'daily',(Get-Date).AddHours(1).ToString('HH:mm'))
    $tasks = @(Get-ScheduledTask | Where-Object {$_.TaskName -like "Zero@*-Profile-$profile"})
    Check ($tasks.Count -eq 1) 'Zero registered exactly one fixture task'
    $task = $tasks[0]
    $xmlText = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
    [IO.File]::WriteAllText((Join-Path $output 'registered-task.xml'),$xmlText)
    [xml]$xml = $xmlText
    $principal = $xml.Task.Principals.Principal
    $action = $xml.Task.Actions.Exec
    # Export-ScheduledTask can omit the default RunLevel; validate its effective CIM value too.
    $runLevelNode = $principal.SelectSingleNode('*[local-name()="RunLevel"]')
    $xmlRunLevel = if ($runLevelNode) { $runLevelNode.InnerText } else { '(default)' }
    Check (@($xml.Task.Principals.Principal).Count -eq 1 -and $principal.UserId -eq $sid -and $principal.LogonType -eq 'InteractiveToken' -and $xmlRunLevel -in @('(default)','LeastPrivilege') -and $task.Principal.RunLevel -eq 'Limited') 'Registered principal is this SID with InteractiveToken and LeastPrivilege'
    Check (@($xml.Task.Actions.Exec).Count -eq 1 -and $action.Command -eq $exe) 'Registered action executes the unchanged Zero binary'
    $arguments = [ZeroInteractiveNative]::Arguments($action.Arguments)
    Check ($arguments.Count -eq 7 -and $arguments[0] -eq '--quiet' -and $arguments[1] -eq '--state-dir' -and $arguments[2] -eq $state -and $arguments[3] -eq '--state-id' -and $arguments[4] -match '^[0-9a-f]{8}:[0-9a-f]{16}:[0-9a-f]{16}$' -and $arguments[5] -eq '--profile' -and $arguments[6] -eq $profile) 'Registered action retains exact isolated state and profile arguments'
    $report.task = @{name=$task.TaskName;path=$task.TaskPath;principalSid=$principal.UserId;logonType=$principal.LogonType;xmlRunLevel=$xmlRunLevel;effectiveRunLevel=[string]$task.Principal.RunLevel;command=$action.Command;arguments=$arguments}
    Check (Test-Path -LiteralPath $selected) 'Registration alone did not process the selected file'
    $prior = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
    Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 250
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
        $current = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
        if ($info.LastRunTime -gt $prior.LastRunTime -and $current.State -in @('Ready','Disabled') -and $info.LastTaskResult -eq 0 -and !(Test-Path -LiteralPath $selected) -and @(Get-ChildItem -LiteralPath $receipts -File -Filter '*.json').Count -eq 1) { break }
    } while ((Get-Date) -lt $deadline)
    $report.completion = @{lastRunTime=$info.LastRunTime.ToString('o');lastTaskResult=$info.LastTaskResult;state=[string]$current.State}
    Check ($info.LastRunTime -gt $prior.LastRunTime -and $info.LastTaskResult -eq 0 -and $current.State -ne 'Running') 'Actual scheduled task ran and completed successfully'
    Check (!(Test-Path -LiteralPath $selected) -and (Get-ZeroHash $sentinel) -eq $sentinelHash) 'Scheduled process removed only the selected synthetic file'
    Check ([ZeroInteractiveNative]::HasCredential()) 'Scheduled process used the current-user recovery credential store'
    $records = @(Get-ChildItem -LiteralPath $receipts -File -Filter '*.json')
    Check ($records.Count -eq 1) 'Scheduled process produced one receipt'
    $public = Join-Path $root 'trusted-public.hex'
    Run-Zero @('--export-key',$public)
    Run-Zero @('--verify-receipt',$records[0].FullName,$public)
    $receipt = Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json
    Check ($receipt.body.selected_path -eq $selected -and $receipt.body.original_bytes -eq 1048593) 'Verified receipt identifies the selected synthetic file and byte count'
    $report.outcomes = @{selectedRemoved=$true;sentinelSha256=$sentinelHash;sentinelUnchanged=$true;receiptVerified=$true;originalBytes=$receipt.body.original_bytes}
    Copy-Item -LiteralPath $records[0].FullName -Destination (Join-Path $output 'synthetic-receipt.json')
    $report.status = 'passed'
} catch {
    if ($report.status -eq 'running') { $report.status = 'failed' }
    $report.error = $_.Exception.Message
    throw
} finally {
    try {
        if ($registered) {
            $owned = if ($task) { @(Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue) } else { @(Get-ScheduledTask | Where-Object {$_.TaskName -like "Zero@*-Profile-$profile"}) }
            foreach ($entry in $owned) {
                if ($entry.Actions.Count -ne 1 -or $entry.Actions[0].Execute -ne $exe -or !$entry.Actions[0].Arguments.Contains($root)) { throw 'Refusing cleanup of an unexpected task action.' }
                Stop-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath -Confirm:$false
            }
            $report.cleanup.taskRemoved = @(Get-ScheduledTask | Where-Object {$_.TaskName -like "Zero@*-Profile-$profile"}).Count -eq 0
        }
        if ($credentialWasAbsent) { [ZeroInteractiveNative]::DeleteFixtureCredential(); $report.cleanup.credentialRemoved = ![ZeroInteractiveNative]::HasCredential() }
        $resolved = [IO.Path]::GetFullPath($root)
        if (!$resolved.StartsWith($temporary + '\',[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolved) -notmatch '^zero-interactive-fixture-[0-9a-f]{32}$') { throw 'Refusing cleanup outside the exact disposable fixture.' }
        $reparse = @((Get-Item -LiteralPath $resolved -Force); (Get-ChildItem -LiteralPath $resolved -Recurse -Force)) | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }
        if ($reparse) { throw 'Refusing recursive cleanup through a reparse point.' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
        $report.cleanup.fixtureRemoved = !(Test-Path -LiteralPath $resolved)
    } catch { $report.cleanup.error = $_.Exception.Message; $report.status = 'failed'; throw }
    finally {
        $report.checks = $checks.ToArray()
        Write-ZeroJson (Join-Path $output 'result.json') $report
        $report | ConvertTo-Json -Depth 8 | Write-Host
    }
}

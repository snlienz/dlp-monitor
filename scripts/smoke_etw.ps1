<#
.SYNOPSIS
  End-to-end check of the ETW pipeline. Run from an elevated PowerShell after building:
    cmake --build --preset debug
    powershell -ExecutionPolicy Bypass -File scripts\smoke_etw.ps1

  Runs DlpAgent in console mode, writes sensitive and clean files into C:\DlpTest (a
  monitored path in the default policy, so no USB stick is needed), starts a process,
  then kills the agent to simulate a crash and checks that a restart reclaims the
  orphaned ETW session.
#>
param([string]$Config = 'Debug')

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) PowerShell.'
}

$repo = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $repo "build\src\agent\$Config\DlpAgent.exe"
$policy = Join-Path $repo 'policy\default_policy.json'
$out = Join-Path $env:TEMP 'dlp-smoke'
New-Item -ItemType Directory -Force $out, 'C:\DlpTest' | Out-Null
Remove-Item "$out\*" -Force -ErrorAction SilentlyContinue

function Start-Agent([string]$log) {
    Start-Process -FilePath $exe -ArgumentList '--console', '--verbose', '--policy', "`"$policy`"" `
        -RedirectStandardError $log -RedirectStandardOutput "$log.out" -PassThru -WindowStyle Hidden
}

Write-Host '1. starting agent'
$agent = Start-Agent "$out\run1.log"
Start-Sleep 4

Write-Host '2. generating activity'
Set-Content C:\DlpTest\card.txt 'invoice A123456789, card 4111 1111 1111 1111' -Encoding UTF8
Copy-Item C:\DlpTest\card.txt C:\DlpTest\card-copy.txt -Force
Set-Content C:\DlpTest\utf16.txt 'aws key AKIAIOSFODNN7EXAMPLE' -Encoding Unicode
Set-Content C:\DlpTest\clean.txt 'nothing to see here' -Encoding UTF8
$np = Start-Process notepad.exe -PassThru
Start-Sleep 2
Stop-Process $np -Force
Start-Sleep 5

Write-Host '3. killing agent (simulated crash)'
Stop-Process $agent -Force
Start-Sleep 1
$orphan = (logman query -ets) -match 'DlpMonitor-Agent'

Write-Host '4. restarting agent'
$agent2 = Start-Agent "$out\run2.log"
Start-Sleep 4
Stop-Process $agent2 -Force
logman stop DlpMonitor-Agent -ets 2>$null | Out-Null

$log1 = Get-Content "$out\run1.log" -Raw
$log2 = Get-Content "$out\run2.log" -Raw
$checks = [ordered]@{
    'ETW session started'                 = $log1 -match 'ETW session DlpMonitor-Agent started'
    'process start seen (notepad)'        = $log1 -match 'process start \d+ .*notepad\.exe'
    'file_write for card.txt'             = $log1 -match '"kind":"file_write".*card\.txt'
    'violation pci-card'                  = $log1 -match 'VIOLATION.*"rule_id":"pci-card"'
    'violation pii-tw-id'                 = $log1 -match 'VIOLATION.*"rule_id":"pii-tw-id"'
    'violation secrets (UTF-16 file)'     = $log1 -match 'VIOLATION.*"rule_id":"secrets".*utf16\.txt'
    'no violation for clean.txt'          = -not ($log1 -match 'VIOLATION.*clean\.txt')
    'session orphaned after kill'         = [bool]$orphan
    'restart reclaimed orphan session'    = $log2 -match 'already exists, stopping orphan' -and $log2 -match 'ETW session DlpMonitor-Agent started'
}
$checks.GetEnumerator() | ForEach-Object {
    $mark = if ($_.Value) { 'PASS' } else { 'FAIL' }
    Write-Host ('  [{0}] {1}' -f $mark, $_.Key)
}
Write-Host "Logs: $out"
if ($checks.Values -contains $false) { exit 1 }

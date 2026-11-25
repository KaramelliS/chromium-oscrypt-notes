# Launches the phase 6 probe as SYSTEM via a one-shot scheduled task,
# then cleans the task up. Requires the UAC prompt to be accepted.
$ErrorActionPreference = 'Continue'

$py  = (Get-Command python).Source
$script = 'C:/Users/berkaycik/projects/chromium-oscrypt-notes/scripts/probe6_system_test.py'
$out = "$env:TEMP\abe_system.log"

if (Test-Path $out) { Remove-Item $out -Force }

$cmd = "`"$py`" `"$script`" > `"$out`" 2>&1"
$task = 'ABE_Recon_OneShot'

schtasks /create /tn $task /ru SYSTEM /rl HIGHEST /sc once /st 23:59 /tr $cmd /f | Out-Null
schtasks /run /tn $task | Out-Null
Start-Sleep -Seconds 25
schtasks /delete /tn $task /f | Out-Null

Write-Output "--- done, log at $out ---"
if (Test-Path $out) { Get-Content $out -Raw }

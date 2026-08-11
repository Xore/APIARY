# loldriver-gate-test.ps1 -- #901 acceptance evidence: attempt to load a
# LOLDrivers-listed vulnerable driver as a kernel service and report whether
# it actually loaded. Run against a clone with provision-loldrivers.sh
# already applied (expect success) and a clean clone (expect failure via
# the Microsoft Vulnerable Driver Blocklist).
#
# Not part of the normal detonation pipeline -- ad hoc verification script
# for this issue's acceptance evidence, run manually over WinRM against a
# disposable clone. Deletes the service afterward either way so a repeat
# run starts clean.

$ErrorActionPreference = 'Continue'
$driver = 'RTCore64.sys'
$path = "C:\Windows\Temp\$driver"
$svc = 'loldrivertest'

Write-Output "=== driver file present: $(Test-Path $path) ==="

sc.exe delete $svc 2>&1 | Out-Null

$create = sc.exe create $svc type= kernel binPath= $path 2>&1
Write-Output "=== sc create output ==="
Write-Output $create

$start = sc.exe start $svc 2>&1
Write-Output "=== sc start output ==="
Write-Output $start

$query = sc.exe query $svc 2>&1
Write-Output "=== sc query output ==="
Write-Output $query

$loaded = Get-CimInstance Win32_SystemDriver -Filter "Name='$svc'" -ErrorAction SilentlyContinue
Write-Output "=== driver loaded per Win32_SystemDriver: $($null -ne $loaded -and $loaded.State -eq 'Running') ==="

$blocklist = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name 'VulnerableDriverBlocklistEnable' -ErrorAction SilentlyContinue
Write-Output "=== VulnerableDriverBlocklistEnable: $($blocklist.VulnerableDriverBlocklistEnable) ==="

sc.exe stop $svc 2>&1 | Out-Null
sc.exe delete $svc 2>&1 | Out-Null

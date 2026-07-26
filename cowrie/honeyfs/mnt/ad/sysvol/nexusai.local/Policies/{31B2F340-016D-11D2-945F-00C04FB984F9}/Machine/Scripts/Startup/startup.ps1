# NexusAI Machine Startup Policy Script
# GPO: Default Domain Policy  Scope: Machine  Rev: 3
# Last updated: 2026-05-28  Owner: NEXUSAI\svc-jenkins

$ErrorActionPreference = 'SilentlyContinue'

# Ensure NTP sync on domain members
w32tm /config /manualpeerlist:"ad.nexusai.local" /syncfromflags:manual /reliable:yes /update | Out-Null
Restart-Service w32tm -Force | Out-Null

# Register machine in internal CMDB (fire-and-forget)
$body = @{ hostname = $env:COMPUTERNAME; domain = $env:USERDOMAIN; ts = (Get-Date -Format o) } | ConvertTo-Json
Invoke-RestMethod -Uri 'http://monitor.nexusai.local:9100/api/cmdb/checkin' -Method Post -Body $body -ContentType 'application/json' | Out-Null

# Verify Defender exclusions for ML training paths (latency-critical)
$paths = @('C:\mldata', 'D:\models', '\\fs01.nexusai.local\data', '\\fs01.nexusai.local\models')
foreach ($p in $paths) {
    Add-MpPreference -ExclusionPath $p
}

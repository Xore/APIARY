# 90-cleanup.ps1 - Final pass. NOTE: deliberately NO sysprep.
# Sysprep strips the machine-specific persona history; for a detonation golden
# image we clone the qcow2 backing file instead.
$ErrorActionPreference = 'Continue'
Write-Host '== 90-cleanup =='

# Clear temp + Packer artifacts
Remove-Item -Recurse -Force C:\Windows\Temp\* -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $env:TEMP\* -ErrorAction SilentlyContinue
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# Remove chocolatey cache noise
Remove-Item -Recurse -Force "$env:ALLUSERSPROFILE\chocolatey\logs" -ErrorAction SilentlyContinue

# But KEEP prefetch off? No - real machines have prefetch. Enable it so
# detonation leaves realistic artifacts:
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -Value 3 -Type DWord -Force

# Event logs: keep them (they're evidence), but clear the noisy build-time
# PowerShell operational log so detonation runs start cleaner
wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null

# Windows Update: run a final pass of servicing cleanup
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>$null

# Zero free space to shrink the qcow2 (comment out if build time matters)
# sdelete -z C: 2>$null

Write-Host '== 90-cleanup done =='

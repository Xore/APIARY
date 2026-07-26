@echo off
REM NexusAI Domain Logon Script v2.4
REM Deployed via GPO: Default Domain Policy
REM Last modified: 2026-06-12 by NEXUSAI\administrator

net use Z: \\fs01.nexusai.local\data /persistent:no
net use Y: \\fs01.nexusai.local\models /persistent:no

REM Map printer for research floor
rundll32 printui.dll,PrintUIEntry /in /n "\\print01.nexusai.local\HP-Color-LaserJet-MFP"

REM Set environment variables consumed by training launcher
setx NEXUSAI_MLOPS_ROOT \\fs01.nexusai.local\data\mlops /m
setx NEXUSAI_MODEL_REGISTRY \\fs01.nexusai.local\models /m

REM Invoke telemetry ping (non-blocking)
start /b wscript.exe \\%LOGONSERVER%\NETLOGON\scripts\telemetry.vbs

exit /b 0

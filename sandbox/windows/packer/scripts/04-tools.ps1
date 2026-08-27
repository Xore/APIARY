#Requires -RunAsAdministrator
# 04-tools.ps1 — Packer provisioner, step 3 of win11-analysis.pkr.hcl's build.
#
# The analysis tooling: Sysmon, PowerShell logging, FakeNet-NG, Regshot, the
# QEMU guest agent, the analysis directories and shares, the decoy environment,
# and the final resolver. Everything run_sample.py depends on in the guest is
# installed here -- Procmon, Regshot, FakeNet and Sysmon, none of which come
# from (or ever required) FLARE-VM, which is why this template no longer
# installs it at all as of 2026-08-02.
#
# Runs after the settle-restart (step 2 of the template), so any pending
# reboot from 01-hardening.ps1 is finished by the time any of it executes.

Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force
$ErrorActionPreference = 'Continue'

# Confirmed live (build errored after 6h15m despite every phase below it
# succeeding, including this script's own final "Setup complete" banner):
# `choco install X -ErrorAction SilentlyContinue` does not do what it looks
# like it does. -ErrorAction is a PowerShell cmdlet parameter; choco.exe is
# a native executable, so PowerShell never strips it -- choco's own CLI
# parser receives "-ErrorAction" and "SilentlyContinue" as literal argv and
# reads the latter as one more package name to install ("Chocolatey
# installed 3/4 packages. 1 packages failed... SilentlyContinue not
# installed"). That phantom package always fails, choco.exe exits non-zero,
# and because $LASTEXITCODE is only ever set by a native command (no
# PowerShell cmdlet touches it), that stale non-zero value survives
# untouched all the way to the end of the script -- which is exactly what
# Packer's own `exit $LastExitCode` provisioner wrapper reads as this
# script's overall result. Same failure class as the wevtutil incident
# documented in win11-analysis.pkr.hcl: a native command's exit code
# silently overriding real success, deleting a multi-hour build over
# tooling nothing downstream depends on.
#
# Invoke-OptionalChoco is the fix: run choco for real (no bogus flag to
# corrupt its argv), then explicitly consume and clear $LASTEXITCODE so a
# failed optional package is visible in the log but can never again poison
# this script's own final exit status. Every call site below already has
# its own fallback/marker-file handling for "the tool didn't show up" --
# this only fixes how that failure gets reported, not what happens after.
function Invoke-OptionalChoco {
    param([Parameter(Mandatory)][string]$Package)
    & choco install $Package -y --no-progress
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "[!] choco install $Package exited $LASTEXITCODE -- continuing, see the fallback/marker handling below"
        $global:LASTEXITCODE = 0
    }
}

Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - tooling'
Write-Host '================================================================'

'flarevm=not-installed (removed 2026-08-02, see win11-analysis.pkr.hcl)' | Add-Content 'C:\golden_image_provenance.txt'

# ── Runtime dependencies ─────────────────────────────────────────────────
# #368: al-khaser (and, by the same mechanism, plausibly a meaningful slice
# of real-world natively-compiled malware) failed to even launch on this
# image -- STATUS_DLL_NOT_FOUND, confirmed live -- because no Visual C++
# Redistributable was installed. A detonation that can't start looks
# identical in a report to one that did nothing interesting; this is a
# silent false-negative source for the sandbox's actual purpose, not a
# cosmetic gap. Install broadly rather than guessing which single runtime a
# given sample needs -- every package here is `Invoke-OptionalChoco`, so one
# failing (e.g. a package temporarily pulled from the community feed) can
# never cost the whole multi-hour build, same pattern as every other
# optional tool in this script.
Write-Host '[Phase 8] Installing common runtime dependencies...'
@(
    'vcredist-all',              # every VC++ redist, 2005 through 2015-2022, x86+x64 -- the actual #368 fix
    'dotnetfx',                  # classic .NET Framework -- some samples still target pre-4.x
    'dotnet-6.0-desktopruntime', # .NET 6 LTS desktop runtime (x64)
    'dotnet-8.0-desktopruntime', # .NET 8 LTS desktop runtime (x64)
    'javaruntime',                # JRE -- cross-platform/JAR-packaged samples
    'silverlight'                 # legacy web-delivered content some older samples still expect
) | ForEach-Object { Invoke-OptionalChoco -Package $_ }
'runtime_packages=vcredist-all,dotnetfx,dotnet-6.0-desktopruntime,dotnet-8.0-desktopruntime,javaruntime,silverlight' |
    Add-Content 'C:\golden_image_provenance.txt'
Write-Host '[+] Runtime dependencies installed'

# ── Install Sysmon ────────────────────────────────────────────────────────
Write-Host '[Phase 9] Installing Sysmon...'
$sysmonPath = 'C:\Tools\SysinternalsSuite'
if (-not (Test-Path "$sysmonPath\Sysmon64.exe")) {
    choco install sysinternals -y --no-progress
    # The choco package extracts to its own lib tree, not $sysmonPath --
    # confirmed live (2026-08-02): Sysmon installed successfully every time,
    # but silently failed to run afterward with CommandNotFoundException,
    # because C:\Tools\SysinternalsSuite\Sysmon64.exe never existed. Every
    # tool this build or run_sample.py expects under $sysmonPath (Sysmon,
    # Procmon, autorunsc) actually lands in one place:
    # C:\ProgramData\chocolatey\lib\sysinternals\tools\ -- copy the whole
    # tree once here rather than teaching each call site its own fallback
    # search (which is what autorunsc's already did, and it would have
    # silently found nothing either, for the same reason).
    $chocoSysinternals = 'C:\ProgramData\chocolatey\lib\sysinternals\tools'
    if ((Test-Path $chocoSysinternals) -and -not (Test-Path "$sysmonPath\Sysmon64.exe")) {
        New-Item $sysmonPath -ItemType Directory -Force | Out-Null
        Copy-Item "$chocoSysinternals\*" $sysmonPath -Force
    }
}
# The config comes from a third party at build time, so several things can go
# wrong and none should cost three hours. DownloadFile throws a terminating
# error, which would abort the whole provisioner at Phase 9 over a momentary
# blip on a host we do not control.
#
# #86: pinned to a commit, not `master` -- an unpinned branch tip means two
# builds a month apart can silently observe different things (different
# event filtering, different exclusions), and the golden image records no
# trace of which. The commit below is the exact one $sysmonConfigSha256
# was computed from (`curl -fsSL .../<sha>/sysmonconfig-export.xml |
# sha256sum`, verified 2026-08-05 to still match the live `master` tip's own
# bytes at the time of pinning). Re-pin deliberately -- bump both the SHA and
# the hash together, never just the hash -- rather than letting this drift
# quietly the way the unpinned URL did.
$sysmonConfigCommit = '1836897f12fbd6a0a473665ef6abc34a6b497e31'
$sysmonConfigSha256 = '055febc600e6d7448cdf3812307275912927a62b1f94d0d933b64b294bc87162'
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/$sysmonConfigCommit/sysmonconfig-export.xml"
$configPath = 'C:\Windows\sysmon_config.xml'
$sysmonConfigured = $false
try {
    (New-Object Net.WebClient).DownloadFile($configUrl, $configPath)
    # Pinning the commit stops the config from silently changing underneath
    # the build, but not a compromised/MITM'd raw.githubusercontent.com
    # response for that exact byte range -- verify what was actually
    # downloaded against the hash recorded above before trusting it, the
    # same "pin the commit, hash the bytes" shape as dashboard/frontend/
    # theme.lock's vendored-stylesheet check.
    # Get-FileHash's .Hash is uppercase hex; -eq is case-insensitive by
    # default in PowerShell so this would still compare correctly against
    # the lowercase pin above, but lowering both sides makes that explicit
    # rather than relying on a reader already knowing PowerShell's string
    # comparison defaults.
    $actualSha256 = (Get-FileHash -Path $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $sysmonConfigSha256) {
        throw "downloaded sysmon-config hash $actualSha256 does not match pinned $sysmonConfigSha256 (commit $sysmonConfigCommit)"
    }
    # A 404 or a captive-portal page downloads happily and is not XML. Sysmon
    # would reject it with a message no one reads until a report comes back
    # empty, so check here instead -- redundant with the hash check above for
    # a byte-for-byte match, but still catches the case where the pin itself
    # is stale (upstream history rewritten) and $configPath is whatever a
    # 404/portal page's own bytes happened to hash to.
    [xml](Get-Content $configPath) | Out-Null
    & "$sysmonPath\Sysmon64.exe" -accepteula -i $configPath
    $sysmonConfigured = $true
    Write-Host '[+] Sysmon installed with sysmon-config'
} catch {
    Write-Warning "[!] Sysmon config unusable ($($_.Exception.Message)) - falling back to defaults"
    & "$sysmonPath\Sysmon64.exe" -accepteula -i
}
# Record which of the two ran, and the exact pin a "sysmon-config" build used
# -- a thin-looking report should be traceable to this without guessing, and
# so should "which upstream commit shaped what this image observed."
"sysmon_config=$(if ($sysmonConfigured) { 'sysmon-config' } else { 'defaults' })" |
    Add-Content 'C:\golden_image_provenance.txt'
if ($sysmonConfigured) {
    "sysmon_config_commit=$sysmonConfigCommit" | Add-Content 'C:\golden_image_provenance.txt'
    "sysmon_config_sha256=$sysmonConfigSha256" | Add-Content 'C:\golden_image_provenance.txt'
}
Write-Host '[+] Sysmon installed'

# ── PowerShell Logging ────────────────────────────────────────────────────
Write-Host '[Phase 10] Enabling PowerShell logging...'
$logPaths = @{
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' = @{
        EnableScriptBlockLogging = 1; EnableScriptBlockInvocationLogging = 1
    }
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' = @{
        EnableModuleLogging = 1
    }
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' = @{
        EnableTranscripting = 1
        OutputDirectory = 'C:\PSTranscripts'
        EnableInvocationHeader = 1
    }
}
foreach ($p in $logPaths.Keys) {
    New-Item $p -Force | Out-Null
    foreach ($n in $logPaths[$p].Keys) { Set-ItemProperty $p $n $logPaths[$p][$n] }
}
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
    -Force | Out-Null
Set-ItemProperty `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
    -Name '*' -Value '*'
New-Item 'C:\PSTranscripts' -ItemType Directory -Force | Out-Null
Write-Host '[+] PowerShell logging enabled'

# ── Process Creation Auditing ─────────────────────────────────────────────
auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable
Set-ItemProperty `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    ProcessCreationIncludeCmdLine_Enabled 1 -Type DWORD -Force -ErrorAction SilentlyContinue

# ── Expand Event Log Sizes ────────────────────────────────────────────────
@('Microsoft-Windows-Sysmon/Operational',
  'Microsoft-Windows-PowerShell/Operational',
  'Security', 'System', 'Application') | ForEach-Object {
    wevtutil sl $_ /ms:524288000
}

# ── Install FakeNet-NG ────────────────────────────────────────────────────
# #100/#368-adjacent: confirmed live (2026-08-02) that this whole block
# silently produced nothing -- run_sample.py's hard-coded
# C:\Tools\FakeNet\fakenet.exe never existed on either of today's built
# images. Two independent bugs, both now fixed:
#   1. The choco package id was "fakenet-ng", which does not exist
#      (confirmed against the community feed: 404). The real id is
#      "fakenet".
#   2. The fallback's GitHub asset URL hard-coded "fakenet.zip", but the
#      actual current release asset is "fakenet3.5.zip" (confirmed via the
#      GitHub API) -- a filename that will drift again on every version
#      bump. Resolving the real asset name via the API instead of guessing
#      a filename fixes that permanently, not just for today's version.
Write-Host '[Phase 11] Installing FakeNet-NG...'
Invoke-OptionalChoco -Package fakenet
if (-not (Test-Path 'C:\Tools\FakeNet\fakenet.exe')) {
    try {
        $release = Invoke-RestMethod 'https://api.github.com/repos/mandiant/flare-fakenet-ng/releases/latest'
        $asset = $release.assets | Where-Object { $_.name -like '*.zip' } | Select-Object -First 1
        if (-not $asset) { throw 'no .zip asset found in latest release' }
        New-Item 'C:\Tools\FakeNet' -ItemType Directory -Force | Out-Null
        $zipPath = "C:\Tools\FakeNet\$($asset.name)"
        (New-Object Net.WebClient).DownloadFile($asset.browser_download_url, $zipPath)
        Expand-Archive $zipPath 'C:\Tools\FakeNet' -Force
        # The zip's own top-level folder name changes per version (matches
        # the asset filename minus .zip); flatten so fakenet.exe always ends
        # up directly under C:\Tools\FakeNet regardless of that name.
        $inner = Get-ChildItem 'C:\Tools\FakeNet' -Directory | Select-Object -First 1
        if ($inner -and (Test-Path "$($inner.FullName)\fakenet.exe") -and -not (Test-Path 'C:\Tools\FakeNet\fakenet.exe')) {
            Copy-Item "$($inner.FullName)\*" 'C:\Tools\FakeNet' -Recurse -Force
        }
    } catch {
        Write-Warning "[!] FakeNet-NG fallback download failed: $($_.Exception.Message)"
    }
}
if (Test-Path 'C:\Tools\FakeNet\fakenet.exe') {
    Write-Host '[+] FakeNet-NG installed'
} else {
    # Same honest-failure pattern as Regshot below: don't claim success.
    Write-Warning '[!] FakeNet-NG NOT installed - run_sample.py will fail to start it'
    'MISSING' | Set-Content 'C:\Tools\FakeNet\MISSING.txt'
}

# run_sample.py launches fakenet with
#   -c C:\Tools\FakeNet\configs\honeypot_fakenet.ini
# so the config has to be in the golden image, not applied at detonation time.
# The template's file provisioner stages it in Temp (the only directory that
# reliably exists before this script runs); it comes from config/fakenet.ini in
# the repo so there is one copy to review, not two.
$fnConfigDir = 'C:\Tools\FakeNet\configs'
New-Item $fnConfigDir -ItemType Directory -Force | Out-Null
$staged = 'C:\Windows\Temp\honeypot_fakenet.ini'
if (Test-Path $staged) {
    Move-Item $staged "$fnConfigDir\honeypot_fakenet.ini" -Force
    Write-Host '[+] FakeNet config installed'
} else {
    Write-Warning '[!] honeypot_fakenet.ini was not staged - FakeNet will use defaults'
}

# #294: fake-intranet landing page the HTTP/HTTPS listeners' Webroot points
# at. The destination MUST equal the absolute Webroot in
# honeypot_fakenet.ini: upstream's ListenerBase.abs_config_path resolves a
# relative webroot against the CWD / fakenet.exe directory and never against
# this config's directory, so a landing page parked under configs\ was
# unreachable and FakeNet served its stock pages instead (#2445).
$stagedWebroot = 'C:\Windows\Temp\honeypot_fakenet_defaultFiles'
$fnWebroot = 'C:\Tools\FakeNet\webroot'
if (Test-Path $stagedWebroot) {
    New-Item $fnWebroot -ItemType Directory -Force | Out-Null
    Move-Item "$stagedWebroot\*" $fnWebroot -Force
    Write-Host '[+] FakeNet intranet webroot installed'
} else {
    Write-Warning '[!] FakeNet webroot was not staged - HTTP/HTTPS will use the stock 200 OK'
}

# honeypot_fakenet.ini's DumpHTTPPostsFilePrefix is an absolute prefix under
# this directory; HTTPListener opens "<prefix>_<timestamp>.txt" verbatim and
# never creates directories (#2445), and run_sample.py's collector plus the
# orchestrator's fakenet_stop both expect the tree to be here.
New-Item 'C:\Logs\fakenet_downloads' -ItemType Directory -Force | Out-Null

# ── Install Regshot ───────────────────────────────────────────────────────
# orchestrate/run_sample.py shells out to a hard-coded
# C:\Tools\Regshot\Regshot-x64-Unicode.exe for the before/after registry diff.
# Chocolatey drops the binary under its own lib tree, so copy it to the path
# the orchestrator expects rather than teaching the orchestrator a second one —
# every other tool it drives lives under C:\Tools\.
Write-Host '[Phase 11b] Installing Regshot...'
$regshotDir = 'C:\Tools\Regshot'
$regshotExe = "$regshotDir\Regshot-x64-Unicode.exe"
New-Item $regshotDir -ItemType Directory -Force | Out-Null
Invoke-OptionalChoco -Package regshot
if (-not (Test-Path $regshotExe)) {
    $found = Get-ChildItem 'C:\ProgramData\chocolatey\lib' -Recurse `
        -Filter 'Regshot*x64*Unicode*.exe' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($found) { Copy-Item $found.FullName $regshotExe -Force }
}
if (Test-Path $regshotExe) {
    Write-Host '[+] Regshot installed'
} else {
    # Not fatal: a detonation without a registry diff is still a usable report,
    # and failing the whole 3-hour build over one optional tool is worse. The
    # marker file is what the smoke test checks.
    Write-Warning '[!] Regshot NOT installed - registry diffs will be missing'
    'MISSING' | Set-Content 'C:\Tools\Regshot\MISSING.txt'
}

# ── QEMU Guest Agent ─────────────────────────────────────────────────────
Write-Host '[Phase 12] Installing QEMU guest agent...'
Invoke-OptionalChoco -Package qemu-guest-agent
Start-Service QEMU-GA -ErrorAction SilentlyContinue

# ── Analysis Directories ─────────────────────────────────────────────────
# #91: these shares were 'Everyone' -- FullAccess on Samples, ReadAccess on
# Logs -- on a machine whose entire purpose is running a detonated sample
# with a writable, network-reachable path and a lab-shaped share name to
# find. Checked orchestrate/run_sample.py before narrowing this rather than
# removing the shares outright as #91 first suggested: it authenticates to
# both over SMB explicitly as -U 'analyst%<pass>' (copy_sample_to_vm,
# collect_artifacts), never relying on anonymous/Everyone access, so
# 'Everyone' was already redundant with what the orchestrator actually
# needs -- narrowing to the analyst account changes nothing for it and
# closes the share to every other process on the box, detonated sample
# included.
#
# #956: 'Samples' -> 'Inbox', for the exact "lab-shaped share name" reason
# #91 already called out above, just never acted on for the name itself --
# pafish's gensandbox_path() (real source, not guessed) flags any running
# module's path containing "\SAMPLE" as a sandbox tell, and every real
# detonation drops the sample at this exact path (run_sample.py's
# push_sample_to_guest()). Confirmed live: pafish's "Checking file path"
# read traced! against C:\Samples\pafish.exe. 'Inbox' avoids that
# substring (and "virus"/"malware"/"sandbox", the other strings
# gensandbox_path() checks for) while keeping the same terse, mundane
# naming style as the sibling Drops/Captures/Logs shares below.
@('C:\Inbox','C:\Logs','C:\Drops','C:\Captures') | ForEach-Object {
    New-Item $_ -ItemType Directory -Force | Out-Null
}
New-SmbShare -Name 'Inbox' -Path 'C:\Inbox' -FullAccess 'analyst' -ErrorAction SilentlyContinue
New-SmbShare -Name 'Logs'  -Path 'C:\Logs'  -ReadAccess 'analyst' -ErrorAction SilentlyContinue

# Decoy user environment (fake documents, a decoy SMB share, realistic
# recent-files) lives in scripts/05-decoy-content.ps1, the next provisioner
# in win11-analysis.pkr.hcl -- separate from this script deliberately, since
# it's cosmetic and nothing run_sample.py touches, unlike everything above.

# DNS-to-INetSim used to be set here (Phase 13) on the theory that this was
# the last phase, so it couldn't cost the build its own internet access.
# That assumption broke (#432) once 06-chrome-history.ps1 was added to
# win11-analysis.pkr.hcl after this script -- Chrome's download failed with
# DNS resolution errors every time, since 10.10.10.1 isn't reachable from
# the packer build's own network. Confirmed live (2026-08-03). Moved to
# win11-analysis.pkr.hcl's own final inline cleanup provisioner instead,
# which actually is guaranteed last regardless of what gets added to the
# provisioner chain between this script and it.
Write-Host '================================================================'
Write-Host '[+] Setup complete. Packer will now shut down and export qcow2.'
Write-Host '================================================================'

# Explicit, not implicit: Packer's provisioner wrapper does `exit
# $LastExitCode`, which reads whatever a native command last left behind --
# see Invoke-OptionalChoco's comment above for the incident that taught
# this. Every native call in this script already resets it, but this line
# means a future edit that adds one more without remembering that can never
# again cost a real, successful build over nothing.
exit 0

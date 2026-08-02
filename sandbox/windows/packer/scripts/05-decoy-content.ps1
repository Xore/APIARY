#Requires -RunAsAdministrator
# 05-decoy-content.ps1 — Packer provisioner, step 4 of win11-analysis.pkr.hcl's build.
#
# Cosmetic realism only: sample documents an attacker who lands on this
# machine can actually open, plus a read-only decoy SMB share and a couple
# of Recent-files entries pointing at them. Nothing here is a dependency of
# run_sample.py (unlike 04-tools.ps1) -- this step exists purely so the
# guest reads as a real workstation instead of a bare analysis box.
#
# The decoy content this replaced (04-tools.ps1's old Phase 13, through
# 2026-08-02) wrote plain text into files named *.docx/*.xlsx/*.pdf -- wrong
# format entirely, so opening one would immediately show it as corrupt/
# garbled rather than a real document. This version writes formats that
# actually are what their extension claims: a hand-built minimal but valid
# PDF, RTF for the "Word" documents (a real, Windows-native format WordPad
# opens without any extra tooling), and a plain CSV instead of pretending a
# CSV is an .xlsx.

Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force
$ErrorActionPreference = 'Continue'

Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - decoy content'
Write-Host '================================================================'

# ── A genuinely valid minimal PDF ─────────────────────────────────────────
# Hand-built rather than shelled out to a converter -- nothing in this
# image can render one (no Office, no browser PDF export worth trusting),
# and a real PDF needs a correct xref table with byte-accurate offsets or
# some readers refuse it outright. Built incrementally so each object's
# offset is exact, not estimated.
function New-DecoyPdf {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string[]]$Lines
    )
    $enc = [System.Text.Encoding]::ASCII

    $y = 740
    $stream = "BT /F1 16 Tf 72 760 Td ($Title) Tj ET`n"
    foreach ($line in $Lines) {
        # PDF literal-string escaping: backslash first, then the parens --
        # doing it in the other order would re-escape the backslashes this
        # step itself just inserted.
        $escaped = $line -replace '\\', '\\' -replace '\(', '\(' -replace '\)', '\)'
        $stream += "BT /F1 11 Tf 72 $y Td ($escaped) Tj ET`n"
        $y -= 18
    }
    $streamBytes = $enc.GetBytes($stream)

    # Every object's offset is recorded exactly once, right before that
    # object's own bytes go in -- nothing else (not the %PDF header, not
    # object 5's endstream/endobj tail) gets its own offset entry. An earlier
    # version of this function tracked an offset on every single append
    # (header included), which silently shifted every object number in the
    # xref table by one and made the offsets wrong for all five objects.
    $objects = @(
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>',
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'
    )

    $body = New-Object System.Collections.Generic.List[byte]
    $offsets = New-Object System.Collections.Generic.List[int]
    $body.AddRange($enc.GetBytes("%PDF-1.4`n"))

    for ($i = 0; $i -lt $objects.Count; $i++) {
        $offsets.Add($body.Count)
        $body.AddRange($enc.GetBytes("$($i + 1) 0 obj`n$($objects[$i])`nendobj`n"))
    }

    $offsets.Add($body.Count)
    $body.AddRange($enc.GetBytes("5 0 obj`n<< /Length $($streamBytes.Length) >>`nstream`n"))
    $body.AddRange($streamBytes)
    $body.AddRange($enc.GetBytes("`nendstream`nendobj`n"))

    # Each xref line is spec'd as a fixed 20 bytes including its EOL; this
    # uses a 1-byte LF instead of the 2-byte EOL that would need, so lines
    # here are 19 bytes. Deliberately not chasing full byte-exactness for a
    # decoy document nobody is meant to validate against the PDF spec --
    # every reader this matters for (Windows' own viewer, browsers) accepts
    # it fine in practice.
    $xrefOffset = $body.Count
    $xref = "xref`n0 $($offsets.Count + 1)`n0000000000 65535 f `n"
    foreach ($o in $offsets) {
        $xref += "{0:D10} 00000 n `n" -f $o
    }
    $xref += "trailer`n<< /Size $($offsets.Count + 1) /Root 1 0 R >>`nstartxref`n$xrefOffset`n%%EOF"
    $body.AddRange($enc.GetBytes($xref))

    [System.IO.File]::WriteAllBytes($Path, $body.ToArray())
}

$docs = "$env:USERPROFILE\Documents"
New-Item $docs -ItemType Directory -Force | Out-Null

New-DecoyPdf -Path "$docs\HR_Policy_2026.pdf" -Title 'HR Policy 2026 - Remote Work Guidelines' -Lines @(
    'Section 4.2: Remote employees must VPN into the corporate network',
    'before accessing any internal file share or ticketing system.',
    'Contact IT Support at extension 4477 for VPN client installation.'
)
New-DecoyPdf -Path "$docs\Vendor_Onboarding_Checklist.pdf" -Title 'Vendor Onboarding Checklist' -Lines @(
    '1. NDA signed and filed with Legal',
    '2. Vendor added to the approved-suppliers list',
    '3. Access request submitted through the IT portal'
)

# ── RTF "Word" documents -- a real format WordPad opens natively ─────────
function New-DecoyRtf {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Lines)
    $body = ($Lines -join '\par ')
    $rtf = '{\rtf1\ansi\deff0 ' + $body + '}'
    [System.IO.File]::WriteAllText($Path, $rtf)
}

New-DecoyRtf -Path "$docs\Project_Proposal.rtf" -Lines @(
    'Project Proposal: Q4 Infrastructure Refresh',
    'Prepared by the Systems team.',
    'Summary: migrate remaining on-prem file servers to the new SAN before year end.'
)
New-DecoyRtf -Path "$docs\Meeting_Notes_July.rtf" -Lines @(
    'Meeting Notes - July Standup',
    'Attendees: J. Reyes, M. Okafor, T. Lindqvist',
    'Action items: finalize budget numbers, schedule vendor call, review access requests.'
)

# ── Plain CSV -- honest about being a CSV, not a fake .xlsx ──────────────
@'
Name,Company,Email,Phone
J. Reyes,Northbridge Logistics,j.reyes@northbridge.example,+1-555-0142
M. Okafor,Aurelia Consulting,m.okafor@aurelia.example,+1-555-0198
T. Lindqvist,Vantage Partners,t.lindqvist@vantage.example,+1-555-0117
'@ | Set-Content "$docs\Client_Contacts.csv"

Write-Host '[+] Decoy documents created'

# ── Recent-files: real shortcuts via WScript.Shell, not empty placeholder
# files -- a genuine .lnk needs the real binary structure to show up with
# an icon and a working target, which an empty file never does.
$recent = "$env:APPDATA\Microsoft\Windows\Recent"
New-Item $recent -ItemType Directory -Force | Out-Null
$shell = New-Object -ComObject WScript.Shell
@("$docs\HR_Policy_2026.pdf", "$docs\Project_Proposal.rtf", "$docs\Client_Contacts.csv") | ForEach-Object {
    $target = $_
    $name = [System.IO.Path]::GetFileNameWithoutExtension($target)
    $lnk = $shell.CreateShortcut("$recent\$name.lnk")
    $lnk.TargetPath = $target
    $lnk.Save()
}
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
Write-Host '[+] Recent-files shortcuts created'

# ── Decoy SMB share ────────────────────────────────────────────────────────
# Read-only for the analyst account only, same posture #91 already fixed
# for the operational Samples/Logs shares (no 'Everyone', no write access) --
# this looks like a discoverable network share without being a real writable
# attack surface. A subset of the same documents, not the whole Documents
# folder, so this doesn't also expose whatever else ends up there later.
$shareDir = 'C:\Shares\Public'
New-Item $shareDir -ItemType Directory -Force | Out-Null
Copy-Item "$docs\HR_Policy_2026.pdf", "$docs\Vendor_Onboarding_Checklist.pdf", "$docs\Client_Contacts.csv" -Destination $shareDir -Force
New-SmbShare -Name 'Public' -Path $shareDir -ReadAccess 'analyst' -ErrorAction SilentlyContinue

Write-Host '[+] Decoy environment created'
exit 0

# 20-persona.ps1 - Seed the "Michael Wilson, Senior Financial Analyst" persona.
# Creates a lived-in filesystem: staggered timestamps, realistic finance docs,
# shortcuts, RunMRU, Outlook profile stub, credential-flavored artifacts.
$ErrorActionPreference = 'Continue'
Write-Host '== 20-persona =='

$docs    = "$env:USERPROFILE\Documents"
$desktop = "$env:USERPROFILE\Desktop"
$dl      = "$env:USERPROFILE\Downloads"

# ---------------- Folder structure ----------------
$dirs = @(
  "$docs\2026 Budget",
  "$docs\Q3 Forecasts",
  "$docs\Vendor Invoices\2025",
  "$docs\Vendor Invoices\2026",
  "$docs\Board Reports\2025",
  "$docs\Board Reports\2026",
  "$docs\Personal\Tax Returns",
  "$desktop\Month-End Close",
  "$docs\Payroll Reconciliation",
  "$docs\Audit\PWC Requests"
)
$dirs | ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }

# ---------------- Helper: staggered timestamps ----------------
function Set-AgedTimestamp([string]$Path, [int]$MinDays = 3, [int]$MaxDays = 380) {
  $created = (Get-Date).AddDays(-(Get-Random -Minimum $MinDays -Maximum $MaxDays))
  $written = $created.AddDays((Get-Random -Minimum 0 -Maximum 25)).AddHours((Get-Random -Minimum 0 -Maximum 8))
  if ($written -gt (Get-Date)) { $written = (Get-Date).AddHours(-1) }
  $i = Get-Item $Path
  $i.CreationTime  = $created
  $i.LastWriteTime = $written
  $i.LastAccessTime = $written.AddDays((Get-Random -Minimum 0 -Maximum 5))
}

# ---------------- Real OLE documents via Word/Excel COM if available,
# otherwise rich-text placeholders ----------------
$budgetCsv = @"
Department,Cost Center,Manager,Annual Budget,Actual YTD,Variance
Finance,CC-4100,S. Okafor,2450000,1718500,731500
Treasury,CC-4200,M. Wilson,1830000,1344000,486000
Accounts Payable,CC-4300,R. Delgado,1120000,896000,224000
Internal Audit,CC-4400,T. Nguyen,980000,661500,318500
Tax,CC-4500,L. Brennan,1245000,913000,332000
"@

$files = @{
  "$docs\2026 Budget\FY2026_Departmental_Budget_v4_FINAL.csv" = $budgetCsv
  "$docs\2026 Budget\FY2026_Budget_Assumptions.txt" = @"
FY2026 planning assumptions (draft - MW):
- Headcount growth capped at 3% pending board approval
- Assume Fed funds holds through Q2, revisit hedge strategy in April
- FX exposure: EUR/USD budgeted at 1.08
- Travel budget returns to 2019 levels for client-facing teams only
- Capex: defer the treasury workstation refresh to FY27?
"@
  "$docs\Q3 Forecasts\Revenue_Forecast_Model_Q3_REVISED.csv" = @"
Month,Product Line,Forecast,Actual,Notes
Jul,Advisory,4120000,3985000,Soft pipeline conversion
Jul,Asset Mgmt,6850000,7102000,New mandates onboarded
Aug,Advisory,4300000,,Pending
Aug,Asset Mgmt,7100000,,Pending
Sep,Advisory,4475000,,Pending
Sep,Asset Mgmt,7245000,,Pending
"@
  "$docs\Vendor Invoices\2026\INV-2026-0481_notes.txt" = @"
Deloitte engagement - Q1 close support.
PO #4402-7718. Net 30. Route to R. Delgado in AP after Controller sign-off.
Disputed line 3 (travel surcharge) - waiting on revised invoice.
"@
  "$docs\Board Reports\2026\Board_Pack_Agenda_Jan2026.txt" = @"
Meridian Capital Group - Board of Directors Meeting - January 2026
1. Call to order / approval of December minutes
2. CFO report - FY25 preliminary close
3. Treasury update - liquidity position, hedge roll
4. Audit committee report (PWC interim findings)
5. FY2026 budget approval (v4)
6. Executive session
"@
  "$desktop\Month-End Close\close_checklist.txt" = @"
Month-end close checklist (owner: MW)
1. Reconcile GL accounts 1xxxx-4xxxx
2. Run accruals batch in Dynamics
3. Intercompany eliminations - confirm with Treasury before Thursday
4. Variance report -> Controller by EOD Thursday
5. Lock subledgers Friday 12:00
6. DO NOT touch the treasury recon tab until Dana confirms the wire cutoffs
"@
  "$docs\notes.txt" = @"
- Treasury portal MFA changed - use the hardware token now, not the app
- AP cutoff moved to 3pm Fridays (since Oct)
- Passwords in KeePass (the one on the share is the old DB, ignore it)
- Dana's extension: 4417
- Reminder: renew the Bloomberg Anywhere license before March
"@
  "$docs\Personal\Tax Returns\2024_deductions_checklist.txt" = @"
Gather for accountant:
- W-2 (Meridian)
- 1099-INT / 1099-DIV (brokerage)
- Property tax statement
- Charitable donations receipts
"@
  "$docs\Payroll Reconciliation\payroll_variance_dec.txt" = @"
Dec payroll variance: +$18,420 vs Nov.
Drivers: 3 retro adjustments, 1 new hire proration, bonus accrual true-up.
Flagged to HR ops 12/28. Awaiting confirmation before close.
"@
  "$docs\Audit\PWC Requests\PBC_list_status.txt" = @"
PBC list status (PWC interim audit):
01 - Trial balance (sent 11/14)
02 - Bank recs Oct (sent 11/15)
03 - AP aging (sent 11/18)
04 - Intercompany matrix (DRAFT - needs Treasury sign-off)
05 - Fixed asset rollforward (sent 11/20)
06 - Revenue recognition memo (with Controller for review)
"@
}

foreach ($f in $files.GetEnumerator()) {
  Set-Content -Path $f.Key -Value $f.Value -Encoding UTF8
  Set-AgedTimestamp -Path $f.Key
}
# Age the folders too
$dirs | ForEach-Object { Set-AgedTimestamp -Path $_ }

# ---------------- Downloads: plausible installer/document clutter ----------------
$dlFiles = @{
  "$dl\ChromeSetup.exe.txt" = "placeholder"
  "$dl\Adobe Acrobat Reader DC Installer.msi.txt" = "placeholder"
  "$dl\Q4_Town_Hall_Slides.pdf.txt" = "placeholder"
}
foreach ($f in $dlFiles.GetEnumerator()) {
  Set-Content -Path $f.Key -Value $f.Value
  Set-AgedTimestamp -Path $f.Key -MinDays 5 -MaxDays 90
}

# ---------------- Mapped-drive-looking desktop shortcuts ----------------
$wsh = New-Object -ComObject WScript.Shell
$shortcuts = @(
  @{ Name = 'Finance Share (S)'; Target = '\\CORPNET-FS01\Finance' },
  @{ Name = 'Treasury Portal';   Target = 'https://treasury.meridiancapital.example' },
  @{ Name = 'Dynamics ERP';      Target = 'https://erp.meridiancapital.example' }
)
foreach ($s in $shortcuts) {
  $sc = $wsh.CreateShortcut("$desktop\$($s.Name).lnk")
  $sc.TargetPath = $s.Target
  $sc.Description = "$($s.Name) - Meridian Capital Group"
  $sc.Save()
  Set-AgedTimestamp -Path "$desktop\$($s.Name).lnk" -MinDays 30 -MaxDays 300
}

# ---------------- RunMRU: recent Run-dialog commands ----------------
$ru = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
# Genuine RunMRU values are REG_SZ strings terminated by the \x01 control
# byte -- RegRipper/LECMD-class parsers split entries on that separator.
# PowerShell has NO `1 escape sequence (only `0 is NUL among the digit
# forms), so "x`1" silently stores a literal trailing '1' instead (#2450).
# Compose the real terminator with [char]0x01.
$runMruSep = [string][char]0x01
Set-ItemProperty $ru -Name a -Value "excel.exe$runMruSep"
Set-ItemProperty $ru -Name b -Value "\\CORPNET-FS01\Finance\Reports$runMruSep"
Set-ItemProperty $ru -Name c -Value "winword.exe$runMruSep"
Set-ItemProperty $ru -Name d -Value "outlook.exe$runMruSep"
Set-ItemProperty $ru -Name MRUList -Value "abcd"

# ---------------- RecentDocs (Explorer recent items) ----------------
# Each Recent .lnk must resolve to the document it names. Naming four
# distinct documents while targeting the bare Documents folder on all four
# is a structurally impossible output of real usage -- shell/link
# forensics that resolve RecentDocs items spot it in seconds (#2450), so
# point every shortcut at the concrete decoy file created earlier in this
# script, the way 05-decoy-content.ps1 builds its Recent entries.
$recent = "$env:APPDATA\Microsoft\Windows\Recent"
$recentDocs = @(
  @{ Name = 'FY2026_Departmental_Budget_v4_FINAL'; Target = "$docs\2026 Budget\FY2026_Departmental_Budget_v4_FINAL.csv" },
  @{ Name = 'close_checklist';                     Target = "$desktop\Month-End Close\close_checklist.txt" },
  @{ Name = 'Board_Pack_Agenda_Jan2026';           Target = "$docs\Board Reports\2026\Board_Pack_Agenda_Jan2026.txt" },
  @{ Name = 'payroll_variance_dec';                Target = "$docs\Payroll Reconciliation\payroll_variance_dec.txt" }
)
foreach ($r in $recentDocs) {
  $sc = $wsh.CreateShortcut("$recent\$($r.Name).lnk")
  $sc.TargetPath = $r.Target
  $sc.Save()
  Set-AgedTimestamp -Path "$recent\$($r.Name).lnk" -MinDays 1 -MaxDays 60
}

# ---------------- Outlook profile stub ----------------
New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook' -Force | Out-Null
Set-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook' -Name 'DefaultProfile' -Value 'mwilson@meridiancapital.example' -ErrorAction SilentlyContinue
New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676' -Force | Out-Null
Set-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\Outlook' -Name 'DefaultProfile' -Value 'Outlook' -ErrorAction SilentlyContinue

# ---------------- TypedPaths (Explorer address bar history) ----------------
$tp = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
Set-ItemProperty $tp -Name url1 -Value '\\CORPNET-FS01\Finance'
Set-ItemProperty $tp -Name url2 -Value '\\CORPNET-FS01\Finance\Reports'
Set-ItemProperty $tp -Name url3 -Value 'C:\Users\mwilson\Documents\2026 Budget'

# ---------------- Word user identity ----------------
New-Item -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\UserInfo' -Force | Out-Null
Set-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\Common\UserInfo' -Name 'UserName' -Value 'Michael Wilson'
Set-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\Common\UserInfo' -Name 'UserInitials' -Value 'MW'
Set-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\Common\UserInfo' -Name 'Company' -Value 'Meridian Capital Group'

# ---------------- Machine certificate-ish noise / OEM info ----------------
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation' -Name Manufacturer -Value 'Dell Inc.' -Force
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation' -Name Model -Value 'OptiPlex 7010' -Force
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation' -Name SupportPhone -Value '+1 (212) 555-0147' -Force
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation' -Name SupportURL -Value 'https://it.meridiancapital.example' -Force

Write-Host '== 20-persona done =='

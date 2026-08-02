# 50-chrome-history.ps1 - Seed a believable Chrome browsing history with
# staggered timestamps directly into the History SQLite DB.
$ErrorActionPreference = 'Continue'
Write-Host '== 50-chrome-history =='

$py = Get-Content C:\ProgramData\persona\python-path.txt -ErrorAction SilentlyContinue
if ($py) { $py = ($py -replace '^Python: ','').Trim() }
if (-not $py -or -not (Test-Path $py)) { $py = (Get-Command python -ErrorAction SilentlyContinue).Source }

$chrome = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $chrome)) { $chrome = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe" }
if (-not (Test-Path $chrome)) { Write-Host 'Chrome not found, skipping history seeding'; exit 0 }

$profileDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"

# Launch & close Chrome once so the profile skeleton exists
& $chrome --no-first-run --no-default-browser-check --headless=new --disable-gpu about:blank 2>$null
Start-Sleep -Seconds 5
Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Python seeder: inserts aged history entries (URLs typed + visited).
$seeder = @'
import sqlite3, os, random, datetime, shutil, sys

profile = sys.argv[1]
hist = os.path.join(profile, "History")
if not os.path.exists(hist):
    print("History DB not found:", hist); sys.exit(1)

# Chrome timestamps: microseconds since 1601-01-01
EPOCH = datetime.datetime(1601, 1, 1)
def chrome_ts(dt):
    return int((dt - EPOCH).total_seconds() * 1_000_000)

random.seed(147)

URLS = [
    # (url, title, visits over past N days, typed_count)
    ("https://mail.google.com/", "Gmail", 60, 4),
    ("https://outlook.office.com/mail/", "Outlook - mwilson@meridiancapital.example", 55, 6),
    ("https://meridiancapital.sharepoint.com/sites/finance", "Finance - Home", 40, 2),
    ("https://erp.meridiancapital.example/", "Dynamics 365 - Meridian", 35, 8),
    ("https://treasury.meridiancapital.example/login", "Treasury Portal - Sign in", 22, 9),
    ("https://www.bloomberg.com/", "Bloomberg", 30, 3),
    ("https://www.wsj.com/finance", "WSJ - Finance", 25, 0),
    ("https://www.reuters.com/business/finance/", "Reuters - Finance", 18, 0),
    ("https://finance.yahoo.com/quote/SPY/", "SPY - Yahoo Finance", 14, 1),
    ("https://finance.yahoo.com/quote/EURUSD%3DX/", "EUR/USD - Yahoo Finance", 12, 0),
    ("https://www.irs.gov/businesses", "IRS - Businesses", 6, 0),
    ("https://www.linkedin.com/feed/", "LinkedIn", 20, 2),
    ("https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm", "FOMC Calendars", 5, 0),
    ("https://hr.meridiancapital.example/ess", "HR Self-Service", 8, 1),
    ("https://concur.meridiancapital.example/", "Concur - Expenses", 9, 1),
    ("https://en.wikipedia.org/wiki/XIRR", "XIRR - Wikipedia", 2, 0),
    ("https://stackoverflow.com/questions/tagged/excel", "Stack Overflow - excel", 7, 0),
    ("https://www.google.com/search?q=excel+xnpv+vs+npv", "excel xnpv vs npv - Google Search", 1, 0),
    ("https://www.google.com/search?q=ifrs+16+lease+accounting+summary", "ifrs 16 lease accounting summary - Google Search", 1, 0),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "YouTube", 3, 0),
]

now = datetime.datetime.now()
rows = []
for url, title, visits, typed in URLS:
    for _ in range(visits):
        d = now - datetime.timedelta(
            days=random.randint(0, 120),
            hours=random.randint(0, 9),
            minutes=random.randint(0, 59))
        # mostly business hours
        d = d.replace(hour=random.choice([8,9,10,11,12,13,14,15,16,17]))
        rows.append((url, title, chrome_ts(d), random.choice([0, 0, 0, typed])))

rows.sort(key=lambda r: r[2])

con = sqlite3.connect(hist)
cur = con.cursor()
for url, title, ts, typed in rows:
    cur.execute("INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?,?,?,?,?,0)",
                (url, title, 1, typed, ts))
    uid = cur.lastrowid
    cur.execute("INSERT INTO visits (url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (?,?,0,805306368,0,?)",
                (uid, ts, random.randint(5_000_000, 300_000_000)))
con.commit()

# Fix url-level aggregate counts
cur.execute("""UPDATE urls SET
    visit_count = (SELECT COUNT(*) FROM visits WHERE visits.url = urls.id)""")
con.commit()
con.close()
print(f"Seeded {len(rows)} history entries into {hist}")
'@

$seederPath = 'C:\ProgramData\persona\seed_history.py'
$seeder | Set-Content $seederPath -Encoding UTF8
& $py $seederPath "$profileDir"

# Default browser + first-run suppression
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -Name ProgId -Value 'ChromeHTML' -ErrorAction SilentlyContinue

Write-Host '== 50-chrome-history done =='

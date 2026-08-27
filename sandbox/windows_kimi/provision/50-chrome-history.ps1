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

$userDataDir = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$profileDir = "$userDataDir\Default"

# Launch & close Chrome once so the profile skeleton (incl. the History
# SQLite DB) exists. --user-data-dir is explicit rather than left to
# Chrome's default resolution (#2447): the twin 06-chrome-history.ps1
# confirmed live (2026-08-03) that a headless launch over a
# WinRM-provisioned session did NOT reliably create the profile under
# $env:LOCALAPPDATA\Google without it -- real chrome.exe child processes
# were running while %LOCALAPPDATA%\Google never appeared. This copy
# predates that lesson, so the History DB seeded below was
# non-deterministically absent.
& $chrome --no-first-run --no-default-browser-check --headless=new --disable-gpu "--user-data-dir=`"$userDataDir`"" about:blank 2>$null
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

# Transitions: CHAIN_START|CHAIN_END with core LINK (0) or TYPED (1).
# #2447: urls.typed_count must be backed by TYPED-core visits; from_visit=0
# with start/end chain flags makes every visit its own complete chain --
# internally consistent for direct/typed navigation.
TRANS_LINK  = 805306368   # 0x30000000 = CHAIN_START|CHAIN_END|LINK
TRANS_TYPED = 805306369   # 0x30000001 = CHAIN_START|CHAIN_END|TYPED

now = datetime.datetime.now()

# #2447: one urls row per DISTINCT URL, all of its visits pointing at it.
# The old loop inserted a brand-new urls record per visit (so visit_count
# could never exceed 1 and every site appeared as dozens of once-visited
# rows), then "corrected" the aggregates with an UPDATE that preserved
# exactly that. Group each URL's visits under a single row instead. The
# typed draw is hoisted to per-URL level so the row carries ONE coherent
# typed_count, and exactly that many of its visits get the TYPED-core
# transition -- the real Chrome invariant (typed_count counts typed
# navigations, each of which records a TYPED visit).
plan = []  # (url, title, typed_count, [(ts, visit_duration), ...])
for url, title, visits, typed in URLS:
    typed_count = min(random.choice([0, 0, 0, typed]), visits)
    vlist = []
    for _ in range(visits):
        d = now - datetime.timedelta(
            days=random.randint(0, 120),
            hours=random.randint(0, 9),
            minutes=random.randint(0, 59))
        # mostly business hours
        d = d.replace(hour=random.choice([8, 9, 10, 11, 12, 13, 14, 15, 16, 17]))
        vlist.append(chrome_ts(d))
    vlist.sort()
    durations = [random.randint(5_000_000, 300_000_000) for _ in vlist]
    plan.append((url, title, typed_count, list(zip(vlist, durations))))

# Insert urls rows oldest-first: Chrome assigns urls.id in first-visit
# order, so id ordering should follow earliest visit.
plan.sort(key=lambda p: p[3][0][0])

con = sqlite3.connect(hist)
cur = con.cursor()

# Idempotency guard (#2447): a provisioner re-run against an already
# seeded profile would insert the corpus a second time, recreating the
# duplicate-urls defect this fix removes. Skip instead of double-seeding.
corpus = [u for u, _, _, _ in URLS]
already = cur.execute(
    "SELECT COUNT(*) FROM urls WHERE url IN (%s)" % ",".join("?" * len(corpus)),
    corpus).fetchone()[0]
if already:
    print(f"History already contains {already} corpus URLs -- skipping re-seed")
    con.close()
    sys.exit(0)

for url, title, typed_count, vlist in plan:
    n = len(vlist)
    cur.execute(
        "INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?,?,?,?,?,0)",
        (url, title, n, typed_count, vlist[-1][0]))
    uid = cur.lastrowid
    # Scatter the TYPED visits roughly evenly across the URL's own
    # chronology rather than clustering them at the oldest end.
    stride = n // typed_count if typed_count else 0
    for i, (ts, dur) in enumerate(vlist):
        is_typed = typed_count and stride and i % stride == 0 and i // stride < typed_count
        cur.execute(
            "INSERT INTO visits (url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (?,?,0,?,0,?)",
            (uid, ts, TRANS_TYPED if is_typed else TRANS_LINK, dur))
con.commit()

# Self-check (#2447 acceptance criteria): aggregate integrity must hold in
# the committed DB, not just in what this loop believes it inserted.
sum_counts, total_visits = cur.execute(
    "SELECT (SELECT SUM(visit_count) FROM urls), (SELECT COUNT(*) FROM visits)").fetchone()
dupes, unbacked = cur.execute(
    "SELECT (SELECT COUNT(*) FROM (SELECT url FROM urls GROUP BY url HAVING COUNT(*) > 1)),"
    " (SELECT COUNT(*) FROM urls u WHERE u.typed_count >"
    "   (SELECT COUNT(*) FROM visits v WHERE v.url = u.id AND (v.transition & 255) = 1))").fetchone()
if sum_counts != total_visits or dupes or unbacked:
    print(f"History invariant broken: SUM(urls.visit_count)={sum_counts} vs COUNT(visits)={total_visits},"
          f" duplicate-url rows={dupes}, typed_count rows lacking TYPED visits={unbacked}")
    con.close()
    sys.exit(1)

con.close()
print(f"Seeded {len(plan)} urls / {sum_counts} visits into {hist}")
'@

$seederPath = 'C:\ProgramData\persona\seed_history.py'
$seeder | Set-Content $seederPath -Encoding UTF8
& $py $seederPath "$profileDir"
# #2447: the seeder's honest-failure paths (missing History DB, failed
# self-check) exit non-zero -- previously absorbed into an unconditional
# "done", so provisioning reported success with an empty profile. Python's
# stderr is already on the provisioning log; fail the provisioner loudly.
if ($LASTEXITCODE -ne 0) {
    Write-Warning "[!] Chrome history seeder exited $LASTEXITCODE -- history NOT seeded"
    exit $LASTEXITCODE
}

# The old "default browser" write set UserChoice ProgId=ChromeHTML without
# computing the UserChoice Hash, which Windows 10+ verifies and ignores
# outright (#2447) -- inert config implying a registration that never
# happened. Removed rather than left as decorative registry output.

Write-Host '== 50-chrome-history done =='

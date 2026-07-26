# Multi-Scanner Analysis Pipeline

Automatic multi-scanner submission for all samples captured by Cowrie/Dionaea.

## Scanners

| Scanner | Type | Free | API Docs | Secret Name |
|---------|------|------|----------|-------------|
| **VirusTotal** | 70+ AV engines (static) | Yes (4 req/min) | [developers.virustotal.com](https://developers.virustotal.com/reference) | `VT_API_KEY` |
| **MalwareBazaar** | Community DB, hash lookup | Yes | [bazaar.abuse.ch/api](https://bazaar.abuse.ch/api/) | `MALWAREBAZAAR_API_KEY` |
| **Hybrid-Analysis** | Falcon Sandbox, dynamic | Yes (limited) | [hybrid-analysis.com/docs/api/v2](https://www.hybrid-analysis.com/docs/api/v2) | `HYBRID_ANALYSIS_KEY` |
| **Malshare** | Community repo, hash lookup | Yes (2k/day) | [malshare.com/doc.php](https://malshare.com/doc.php) | `MALSHARE_API_KEY` |
| **CAPE Sandbox** | Dynamic, config extraction | Self-hosted / public | [capesandbox.com/apiv2](https://capesandbox.com/apiv2/) | `CAPE_API_URL` + `CAPE_API_KEY` |
| **Any.run** | Interactive cloud sandbox | Paid API | [any.run/api-documentation](https://any.run/api-documentation/) | `ANYRUN_API_KEY` |

## How to Get API Keys

### VirusTotal (required)
1. Register at [virustotal.com](https://www.virustotal.com)
2. Go to your profile → **API Key**
3. Free tier: 4 requests/min, 500/day
4. Add as secret: `VT_API_KEY`

### MalwareBazaar (recommended)
1. Register at [bazaar.abuse.ch](https://bazaar.abuse.ch)
2. Go to **Account → API Key**
3. Free, no rate limit
4. Add as secret: `MALWAREBAZAAR_API_KEY`

### Hybrid-Analysis (recommended)
1. Register at [hybrid-analysis.com](https://www.hybrid-analysis.com)
2. Go to **Profile → API key**
3. Free tier available
4. Add as secret: `HYBRID_ANALYSIS_KEY`

### Malshare (optional)
1. Register at [malshare.com](https://malshare.com/register.php)
2. API key shown on dashboard
3. Free, 2000 req/day
4. Add as secret: `MALSHARE_API_KEY`

### CAPE Sandbox (optional)
- **Self-hosted**: Use your own CAPE instance URL (e.g. `http://cape.internal:8000`)
- **Public**: [capesandbox.com](https://capesandbox.com) — register for API access
- Add as secrets: `CAPE_API_URL` and `CAPE_API_KEY`

### Any.run (optional, paid)
1. Register at [any.run](https://any.run)
2. Requires paid plan for API access
3. Add as secret: `ANYRUN_API_KEY`

## Archive Handling

Samples are often stored as password-protected archives (honeypot best practice).
The scanner **extracts archives first**, then submits the raw executable:

```
samples/PE/mirai.zip (password: infected)
  └── mirai.elf              ← THIS is submitted to scanners
  └── dropper.exe            ← THIS is submitted to scanners
```

**Supported formats**: `.zip` (plain + AES), `.7z`, `.tar`, `.tar.gz`,
`.tgz`, `.tar.bz2`, `.rar`

**Default passwords tried** (in order): `infected`, `malware`, `infected123`, `virus`

Custom passwords can be passed: `--archive-passwords mypass1,mypass2`

## Hash-First Strategy

Before uploading any file, the scanner checks if the hash is **already known**
to each service. If known, it retrieves the existing report (no upload needed).
This:
- Saves API quota (VT free is only 500 uploads/day)
- Returns results instantly for known malware
- Avoids duplicate submissions to MalwareBazaar

## Workflow Triggers

The workflow triggers automatically when files are committed to:
- `samples/` — Cowrie/Dionaea downloads
- `uploads/` — manually staged samples

Manual trigger via **Actions → Multi-Scanner Analysis → Run workflow**
with an optional specific path.

## Report Format

Each sample produces `reports/scanner/<sha256>.json`:

```json
{
  "file": "samples/PE/d41d8cd98f00b204e9800998ecf8427e.exe",
  "filename": "evil.exe",
  "sha256": "d41d8cd98f00b204e9800998ecf8427e...",
  "sha1":   "...",
  "md5":    "...",
  "size":   102400,
  "scanned_at": "2026-07-26T14:00:00Z",
  "results": {
    "VirusTotalScanner": {
      "source": "virustotal",
      "known": true,
      "positives": 54,
      "total": 72,
      "permalink": "https://www.virustotal.com/gui/file/d41d..."
    },
    "MalwareBazaarScanner": {
      "source": "malwarebazaar",
      "known": true,
      "signature": "AgentTesla",
      "tags": ["AgentTesla", "stealer"]
    },
    ...
  }
}
```

## Required Secrets

Set in **Settings → Secrets and variables → Actions**:

| Secret | Required | Notes |
|--------|----------|-------|
| `GH_PAT` | **Yes** | PAT with `repo` + `workflow` scope (for git push) |
| `VT_API_KEY` | **Yes** | VirusTotal |
| `MALWAREBAZAAR_API_KEY` | Recommended | Free at bazaar.abuse.ch |
| `HYBRID_ANALYSIS_KEY` | Recommended | Free tier |
| `MALSHARE_API_KEY` | Optional | Free |
| `CAPE_API_URL` | Optional | Your CAPE instance or public |
| `CAPE_API_KEY` | Optional | With CAPE_API_URL |
| `ANYRUN_API_KEY` | Optional | Paid plan required |

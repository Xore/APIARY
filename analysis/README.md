# Malware Analysis Pipeline

This folder documents and hosts the analysis pipeline that automatically submits honeypot-captured payloads to **VirusTotal** and **JoeSandbox**, generates PDF reports, and commits everything to [Xore/Honeypot](https://github.com/Xore/Honeypot).

---

## Architecture

```
honeypot-stack (this repo)         Xore/Honeypot (sample archive)
┌───────────────────────────┐       ┌───────────────────────────┐
│  Cowrie / Dionaea / Conpot  │       │  samples/ELF/             │
│  ↓ capture payloads         │       │  samples/PE/              │
│  analysis/collect.sh        │  ──►  │  samples/Scripts/         │
│  ↓ push to Honeypot repo    │       │  reports/virustotal/*.pdf  │
│  GitHub Actions trigger     │       │  reports/joesandbox/*.pdf  │
└───────────────────────────┘       │  iocs/hashes.csv           │
                                        └───────────────────────────┘
        │                                      ↑
        │           External APIs              │
        │  ┌─────────────────────┐          │
        └─►│ VirusTotal API v3     │          │
           │ JoeSandbox Cloud API  │────────┘
           └─────────────────────┘
```

---

## Components

| File | Purpose |
|------|---------|
| `analysis/collect.sh` | Run on the honeypot host; copies new payloads from Cowrie/Dionaea, then pushes to Xore/Honeypot |
| `analysis/pipeline.py` | Standalone pipeline script (same logic as Honeypot repo's `.github/scripts/analyze_samples.py`) |
| `analysis/SANDBOX_APIS.md` | API capability comparison and rate limit reference |

The actual GitHub Actions workflow lives in [Xore/Honeypot/.github/workflows/analyze.yml](https://github.com/Xore/Honeypot/blob/main/.github/workflows/analyze.yml) and runs automatically when samples are pushed there.

---

## Quick Start

### 1. Set Secrets in Xore/Honeypot

Go to **Settings → Secrets and variables → Actions**:

| Secret | How to get |
|--------|------------|
| `VT_API_KEY` | https://www.virustotal.com → Profile → API Key (free tier: 4 req/min, 500/day) |
| `JOESANDBOX_API_KEY` | https://www.joesandbox.com → Account → API Key (free community tier available) |
| `GH_PAT` | GitHub → Settings → Developer Settings → PAT with `repo` write scope |

### 2. Install collect.sh on the honeypot host

```bash
cp analysis/collect.sh /opt/honeypot-collect.sh
chmod +x /opt/honeypot-collect.sh

# Add cron: run every 30 min
echo '*/30 * * * * root /opt/honeypot-collect.sh' >> /etc/cron.d/honeypot-collect
```

### 3. Manual single-sample analysis

```bash
pip install requests vt-py weasyprint jinja2
export VT_API_KEY=your_key
export JOESANDBOX_API_KEY=your_key
python3 analysis/pipeline.py --sample /path/to/malware.elf
```

---

## API Rate Limits Reference

| Service | Free Tier | Paid Tier | File Size Limit |
|---------|-----------|-----------|------------------|
| VirusTotal | 4 req/min, 500/day | Per SLA | 32 MB (direct), 650 MB (URL upload) |
| JoeSandbox | Community: limited submissions/month | Business/Enterprise | 100 MB |

The pipeline uses a **16-second sleep** between VT requests to stay safely under the public 4 req/min cap. JoeSandbox uses `report-cache: 1` to avoid re-analysing already-known samples.

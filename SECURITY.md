# Security policy

This repository intentionally contains honeypot personas, synthetic credentials,
attack signatures, and defensive malware-analysis tooling. Values marked
`DECOY_ONLY` are fictional and must never be reused for real authentication.

Do not report expected honeypot behavior as a vulnerability. Please privately
report issues that could expose the host, bypass sandbox isolation, leak a real
secret, or turn a decoy into an uncontrolled relay.

Use GitHub private vulnerability reporting for this repository. Do not attach
live malware, private keys, production `.env` files, packet captures containing
private traffic, or unredacted logs to a public issue.

Supported security fixes target the current `main` branch.

## The leak gate, and what it already blocks

"Leak a real secret" is enforced in CI, not by review alone.
`scripts/check-public-leaks.py` fails the build on private keys, GitHub/AWS/Slack
tokens, literal `PASSWORD=`/`SECRET=`/`TOKEN=`/`API_KEY=` assignments, credentials
embedded in a URL, any file named `.env`, and private/runtime binaries (`.pcap`,
`.qcow2`, `.key`, `.pem`, …). It also carries four deployment-specific literals —
one public domain, the VPS address, the home-server address and a known default
password — assembled from fragments at runtime so the checker does not harbor the
values it bans, and a `Host()` rule over `vps/traefik/*.yml` that requires a
reserved `.example`/`.test`/`.invalid`/`.localhost` name, so an installer smoke
test cannot resolve live DNS.

Exemptions are explicit and fail-closed, in three sets at the top of the script:
`ALLOWED_DOTENV` (3 paths), `ALLOWED_LITERAL_FIXTURE_FILES` (2 paths), and the
`change-me` / `DECOY_ONLY` / `${…}` / `$(…)` / `<PLACEHOLDER>` forms inside the
credential-assignment pattern. A file that is exempt from the literal scan is
still scanned for every other pattern.

The gate reads `git ls-files -co --exclude-standard`, so **untracked files are
scanned too**: a scratch note left in your own checkout fails the check exactly
like a committed one. Gitignore it or delete it — the address and domain values
this repository is deployed against are named literals in the checker, and a
dispatch brief or run log that quotes one will trip it.

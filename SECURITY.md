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

# Zeek site config for the sensing lab.
#
# Deliberately close to what a real deployment would load, so what we measure
# here predicts what the VPS would produce -- with one exception, noted below.

# Every zkg-installed package: JA4+, HASSH, and the ICSNPP parsers.
@load packages

# JSON output, one object per line, so Filebeat's stock `zeek` module can read
# it unchanged -- the ingest path #1727 assumes.
@load policy/tuning/json-logs

# Community ID on every record. Built into Zeek since 6.0, so no package is
# needed; this is the same key Suricata stamps (seed 0) and the one portbridge
# now emits (#1728). It is what makes the three logs joinable at all.
@load policy/protocols/conn/community-id-logging

# File hashing: record MD5/SHA1/SHA256 for every file seen on the wire, which
# is what lets an extracted artefact join to `honeypot.shasum` and the payload
# pipeline.
@load base/files/hash

# NOT loaded: policy/frameworks/files/extract-all-files.zeek.
# That writes every file crossing the wire -- including live attacker-delivered
# malware -- to disk. It is the point of #1738 and it is a deliberate decision
# with a storage and handling posture attached, not something the lab should do
# implicitly on a workstation. Turn it on knowingly or not at all.

# Keep the local run quiet about things that only matter in a cluster.
redef Log::default_rotation_interval = 0 secs;

# Zeek site config for the VPS sensor (#1742, S5 per #1727 §0).
#
# Kept close to dev/sensing-lab/local.zeek on purpose: what the lab measured is
# only evidence about production if production loads the same scripts. The
# differences below are all about running live rather than over a pcap.

# Every zkg-installed package: JA4+, HASSH, and the ICSNPP parsers.
@load packages

# JSON, one object per line, so Filebeat's ndjson parser reads it directly.
@load policy/tuning/json-logs

# Community ID on conn.log. Built in since Zeek 6, and the key that joins these
# records to Suricata, portbridge and huginn-sidecar. Seed 0 to match
# suricata.yaml's community-id-seed -- a different seed still produces
# well-formed IDs that silently never match anything.
@load policy/protocols/conn/community-id-logging

# #1764: IEC-104 on 2404. ICSNPP covers every other ICS port we expose but
# not this one, so without it 2404 produces a conn.log row and nothing else.
@load /usr/local/share/zeek-site/iec104/iec104.hlto
@load /usr/local/share/zeek-site/iec104/iec104.zeek

# MD5/SHA1/SHA256 for every file seen on the wire, so an artefact joins to
# honeypot.shasum and the payload pipeline by hash.
@load base/files/hash

# NOT loaded: policy/frameworks/files/extract-all-files.zeek.
# That writes every file crossing the wire -- live attacker-delivered malware
# included -- to disk. It is the subject of #1738 and needs a storage and
# handling posture attached before it goes anywhere near the VPS.

# Hourly rotation. Zeek renames the active file rather than creating a new one,
# which is inode-stable: a Filebeat harvester already attached follows the
# rename through to EOF and then picks up the freshly created log, exactly the
# property that makes Suricata's own rotate-interval safe here. Copytruncate
# would not be.
redef Log::default_rotation_interval = 1hr;
# No gzip postprocessor: Filebeat cannot read a compressed rotated file, and
# retention is the ILM policy's job, not the sensor's.
redef Log::default_rotation_postprocessor_cmd = "";

# The VPS's own addresses. Without this Zeek has no notion of inside vs
# outside, and every scan looks like it originates locally.
redef Site::local_nets = { 87.106.162.235/32, 10.8.0.0/24 };

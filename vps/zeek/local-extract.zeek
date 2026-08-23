# Zeek site config WITH wire-level file extraction enabled (#1738).
#
# Selected by setting ZEEK_SITE_SCRIPT to this file in the VPS environment;
# the default remains local.zeek, which extracts nothing.
#
# Kept as a separate entry point rather than a boolean inside local.zeek so
# that "are we writing attacker payloads to this host right now?" is answerable
# by reading one line of compose config, not by tracing a flag through a
# script. It is also why enabling it cannot happen by accident during an
# unrelated Zeek change.

@load ./local.zeek
@load ./extract.zeek

# Where the bytes land. Its own directory, its own volume, its own pruner --
# see zeek-extract-prune in vps/docker-compose.yml, which enforces the total
# cap that extract.zeek's per-file limit cannot.
redef FileExtract::prefix = "/logs/zeek-extract/";

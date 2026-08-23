# Zeek site config for the homeserver's decoy-side sensor (#1742, decision 8).
#
# The VPS sensor watches ens6 and sees every packet an attacker sends -- but
# Traefik terminates TLS for the Host-routed decoys (hellpot, galah, wordpot),
# so for those the VPS sensor gets the ClientHello and then ciphertext. This
# instance watches the honeynet bridge on the homeserver, where the same
# requests arrive in plaintext at the decoy containers.
#
# Placed here rather than on the VPS's own proxy bridge deliberately: the VPS
# has two cores and already runs Suricata, Zeek and the huginn sidecar. A
# fourth sniffer there would contend with the three that see the real attacker
# packets, which is the traffic we least want to drop.
#
# The two sensors see complementary halves of one request, and neither is
# redundant:
#
#   VPS sensor      real TCP peer, the ClientHello, JA4 -- but no request
#   this sensor     method, path, headers, bodies, transferred files -- but
#                   the peer is the tunnel, so it cannot attribute anything
#
# Attribution comes from the join, not from this sensor: #1765 ties Traefik's
# request record to the VPS sensor's JA4 by wire tuple. What this adds on top
# is the detail Traefik's own access log cannot carry -- it logs the request
# line, not the headers, the body, or the files that crossed.

# Do not discard packets whose TCP/UDP checksum looks wrong.
#
# Both sensors capture on interfaces where the checksum is computed after the
# packet is handed to the kernel -- NIC transmit offload on the VPS NIC, and
# the tunnel on wg0 -- so outbound packets are seen before the checksum exists.
# Zeek validates by default and silently drops the payload of anything that
# fails, which meant it was discarding almost everything the *responder* sent.
#
# Measured over six hours before this was set:
#
#   sensor        flows    responder bad-checksum   responder data   responder SYN-ACK
#   zeek (VPS)   58,153            66.4%                 0.7%              0.0%
#   zeek-proxy   15,483            94.5%                 0.9%              0.0%
#
# ('c' and 'd' and 'h' in conn.log's history string; lowercase is the
# responder.) A sensor that sees one side of every conversation is not a
# partial sensor, it is a misleading one: server banners never appeared, so
# ssh.log carried a client version and nothing else and HASSH could never fire
# (#1730); resp_bytes was ~0, so any byte total counted a single direction;
# and conn_state was dominated by SH/S0, which reads as "no response" rather
# than "response discarded".
#
# This is the standard treatment for live capture off an offloading NIC. The
# cost is that genuinely corrupt packets are now analysed too -- acceptable
# here, because on this perimeter a malformed packet is far more likely to be
# our own offload artifact than a real transmission error, and the alternative
# is not seeing the honeypots answer at all.
redef ignore_checksums = T;

@load packages
@load policy/tuning/json-logs
@load policy/protocols/conn/community-id-logging
@load base/files/hash

# Deliberately NOT loaded here, unlike the VPS sensor:
#
#   - the ICSNPP parsers and the IEC-104 one. No ICS protocol reaches this
#     bridge in a form worth parsing twice -- those ports are forwarded by
#     portbridge and the VPS sensor already sees them with the real peer
#     attached. Parsing them again here would produce a second set of
#     transaction records attributed to the tunnel.
#   - extract-all-files. Wire-level extraction happens once, at the VPS
#     sensor (#1738). Doing it here as well would store a second copy of
#     every artefact under a different uid, with no new information.

# Everything on this bridge is local by definition -- a docker network behind
# a tunnel, with no "outside" for Zeek to reason about. Without this, every
# request looks like it originates locally and Site::local_nets is meaningless.
redef Site::local_nets = { 172.16.0.0/12, 10.0.0.0/8, 192.168.0.0/16 };

# Same rename-on-rotate pattern as the VPS sensor: inode-stable, so a Filebeat
# harvester follows the rename to EOF and then picks up the fresh file.
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "";

# #1738: wire-level file extraction, decoy-side only. Loaded from its own
# script so what it does -- and the posture it commits to -- is readable
# without wading through the sensor config.
@load /usr/local/share/zeek-site/proxy-extract.zeek

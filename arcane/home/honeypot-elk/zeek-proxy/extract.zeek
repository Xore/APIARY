# Wire-level file extraction for the decoy-side sensor (#1738).
#
# Runs here and only here. The VPS is the internet-facing host; writing live
# attacker-delivered malware onto it would put payloads on the one machine an
# attacker can already reach, for no analytical gain -- this sensor sees the
# same transfers in plaintext after Traefik terminates TLS, which is the half
# that matters for carving files out.
#
# What this buys: today a file crossing the wire is recorded and its bytes
# thrown away. Suricata's fileinfo counted 16,059 such records over seven days
# and kept none of them. Anything delivered over a protocol our honeypots do
# not fully emulate was observed and discarded.
#
# ---------------------------------------------------------------------------
# Handling posture
# ---------------------------------------------------------------------------
# 1. Names are Zeek's own file id, never the attacker-supplied filename. A
#    filename off the wire is attacker-controlled input and belongs nowhere
#    near a path.
# 2. Per-file size is capped. Without it, one large transfer fills the disk.
# 3. The extract directory is not executable and is never served. Files leave
#    it only by being pulled into the analysis pipeline, which already treats
#    its input as hostile.
# 4. Nothing here decompresses, parses or executes what it writes. This script
#    moves bytes to disk and stops.
#
# Scope is deliberately wide: every protocol Zeek can carve from, and every
# MIME type. The narrow HTTP/FTP-only policy the VPS script carries was a
# concession to running on the perimeter host with ~60 GB free. Here the
# constraint is different, and the noise -- 404 bodies, scanner HTML -- is
# worth accepting to avoid deciding in advance which delivery path matters.
# If disk becomes the problem, reintroduce a skip list rather than narrowing
# the protocols: it is the volume that hurts, not the coverage.

@load base/files/extract
@load base/files/hash

module ProxyFileExtract;

export {
    ## Largest single file to write. Comfortably above the largest sample this
    ## deployment has actually captured (a repeatedly-delivered 5 MB DLL),
    ## with room for archives, and small enough that one transfer cannot run
    ## away with the disk.
    const max_file_bytes = 25 * 1024 * 1024 &redef;
}

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    # Zeek needs somewhere to put it and something to call it. Without a file
    # id there is no safe name, so there is no extraction.
    if ( ! f?$id || f$id == "" )
        return;

    Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
                        [$extract_filename = fmt("%s.bin", f$id),
                         $extract_limit = max_file_bytes]);
    }

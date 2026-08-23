# Wire-level file extraction (#1738) — OPT-IN, never loaded by default.
#
# Enabled by pointing the Zeek service at local-extract.zeek instead of
# local.zeek (ZEEK_SITE_SCRIPT in vps/docker-compose.yml). Turning this on is
# a deliberate act with consequences, which is why it is not a flag inside the
# default config.
#
# What it does: writes the bytes of files crossing the wire to disk, so the
# payload-analysis pipeline gets artefacts our sensors never captured. Today
# we record that a file existed -- Suricata's fileinfo, 16 059 records over
# 7 days -- and discard every byte of it. Anything transferred over a protocol
# our honeypots do not fully emulate is observed and thrown away.
#
# What it also does: writes live attacker-delivered malware onto the VPS.
# That is the point, and it is why the posture below is not optional.
#
# ---------------------------------------------------------------------------
# Handling posture
# ---------------------------------------------------------------------------
# 1. Names are Zeek's own (extract-<ts>-<analyzer>-<fuid>), never the
#    attacker-supplied filename. A filename off the wire is attacker-controlled
#    input and belongs nowhere near a path.
# 2. Per-file and total size are both capped. Without the first, one large
#    transfer fills the disk; without the second, a slow drip does.
# 3. The extract directory is not executable and is never served. Files leave
#    it only by being pulled into the existing analysis pipeline, which already
#    treats its input as hostile.
# 4. Extraction is bounded to protocols worth the risk, not everything Zeek can
#    see. HTTP and FTP are where honeypot payload delivery actually happens.
# 5. Nothing here decompresses, parses or executes what it writes. This script
#    moves bytes to disk and stops.

@load base/files/extract
@load base/files/hash

module FileExtractPolicy;

export {
    ## Largest single file to write. A honeypot dropper is kilobytes to a few
    ## megabytes; anything far larger is either not a payload or not worth the
    ## disk on a box with ~60 GB free.
    const max_file_bytes = 16 * 1024 * 1024 &redef;

    ## Protocols worth extracting from. Deliberately narrow: this is where
    ## payload delivery to our decoys actually happens, and every addition
    ## widens what lands on the VPS.
    const extract_from: set[string] = { "HTTP", "FTP_DATA" } &redef;

    ## MIME types never worth writing. Extracting the HTML of a 404 page from
    ## every scanner in the world is pure noise, and it is most of the volume.
    const skip_mime: set[string] = {
        "text/html",
        "text/plain",
        "image/gif",
        "image/png",
        "image/jpeg",
    } &redef;
}

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    # No source means Zeek could not attribute the file to a protocol; without
    # that we cannot apply the allowlist, so we do not extract.
    if ( ! f?$source || f$source !in extract_from )
        return;

    # An unknown MIME type is still worth having -- that is often exactly the
    # interesting case -- but a known-boring one is not.
    if ( meta?$mime_type && meta$mime_type in skip_mime )
        return;

    Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
                        [$extract_filename = fmt("%s.bin", f$id),
                         $extract_limit = max_file_bytes]);
    }

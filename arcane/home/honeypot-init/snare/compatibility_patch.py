"""Compatibility and response-safety patch for the pinned SNARE release."""

from pathlib import Path


cloner = Path("/opt/snare/snare/cloner.py")
source = cloner.read_text()
needle = '            "content-length",\n            "date",'
replacement = (
    '            "content-length",\n'
    '            "keep-alive",\n'
    '            "proxy-authenticate",\n'
    '            "proxy-authorization",\n'
    '            "te",\n'
    '            "trailer",\n'
    '            "transfer-encoding",\n'
    '            "upgrade",\n'
    '            "date",'
)
if needle not in source:
    raise SystemExit("SNARE cloner header patch target was not found")
cloner.write_text(source.replace(needle, replacement, 1))

server = Path("/opt/snare/snare/server.py")
source = server.read_text()
needle = "        return web.Response(body=content, status=status_code, headers=headers)"
replacement = """        # Cached metadata can predate the cloner filter. Never replay HTTP
        # framing or hop-by-hop headers; aiohttp generates correct framing.
        for name in (
            \"Connection\",
            \"Content-Length\",
            \"Keep-Alive\",
            \"Proxy-Authenticate\",
            \"Proxy-Authorization\",
            \"TE\",
            \"Trailer\",
            \"Transfer-Encoding\",
            \"Upgrade\",
        ):
            headers.popall(name, None)

        return web.Response(body=content, status=status_code, headers=headers)"""
if needle not in source:
    raise SystemExit("SNARE response header patch target was not found")
server.write_text(source.replace(needle, replacement, 1))

# #3119: upstream issues sess_uuid pre-auth and on every request with no
# cookie attributes at all -- cookie-confidentiality-only today (no
# fixation, no reachable state-changing endpoint on this decoy), but a
# session-theft enabler the moment any XSS or authenticated flow lands here.
source = server.read_text()
needle = '                headers.add("Set-Cookie", "sess_uuid=" + cur_sess_id)'
replacement = (
    '                headers.add(\n'
    '                    "Set-Cookie",\n'
    '                    "sess_uuid=" + cur_sess_id + "; HttpOnly; Secure; SameSite=Lax",\n'
    '                )'
)
if needle not in source:
    raise SystemExit("SNARE session cookie patch target was not found")
server.write_text(source.replace(needle, replacement, 1))

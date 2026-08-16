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

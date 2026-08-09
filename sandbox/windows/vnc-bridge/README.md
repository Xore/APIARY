# Read-only sandbox VNC bridge (#805)

Watch the Windows sandbox's detonation VM live, without being able to
touch it. The VM's own libvirt definition already runs a VNC server
(`sandbox/windows/packer/win11-kvm.xml`'s `<graphics type='vnc' .../>`) —
this bridge is the only thing standing between that and an operator's
browser, and it enforces read-only at the RFB protocol level, not by
trusting the browser.

See `server.py`'s own module docstring for exactly which RFB message types
are forwarded (`SetPixelFormat`, `SetEncodings`, `FramebufferUpdateRequest`)
versus parsed-and-discarded (`KeyEvent`, `PointerEvent`, `ClientCutText`),
and why an unrecognised message type or security handshake closes the
connection instead of falling back to unfiltered passthrough.

## Install

Installed automatically by `sandbox/windows/install-worker.sh` alongside
the rest of the Windows sandbox worker — nothing extra to run. That script:

- copies `server.py` to `/usr/local/libexec/honeypot-sandbox/windows/vnc-bridge/server.py`
- installs and enables `honeypot-windows-vnc-bridge.service`
- adds `VNC_BRIDGE_BIND`/`VNC_BRIDGE_PORT` to
  `/etc/default/honeypot-windows-sandbox` (shared with the detonation
  worker — one host config file per component, not per script)

The service is loopback-only (`127.0.0.1:6090`) by default, same posture
as the Ghidra/statictools containers, and does nothing until a browser
actually connects — it just waits.

## Reaching it from the dashboard

Off by default (`SANDBOX_VNC_BRIDGE_WS` unset on the dashboard side): the
sandbox page shows no "Watch live" link and `/sandbox/vnc` 404s with a
clear reason, same convention as `REVDECK_API_BASE`/`STATICTOOLS_API_BASE`.

To turn it on:

1. Set `VNC_BRIDGE_BIND` in `/etc/default/honeypot-windows-sandbox` to this
   host's WireGuard address (same pattern as Rev·Deck's own "reaching it
   remotely" section in `docs/analysis/ghidra/revdeck/README.md`) and
   restart `honeypot-windows-vnc-bridge.service`.
2. Set `SANDBOX_VNC_BRIDGE_WS` in the dashboard's own `.env` to
   `ws://<that-address>:6090/vnc` (or `wss://...` if fronted by Traefik +
   Keycloak/oauth2-proxy the same way Rev·Deck is) and restart the dashboard.

The dashboard adds this one origin to its own Content-Security-Policy
`connect-src` (`setVNCBridgeOrigin`, `dashboard/render.go`) — no other page
is affected, and nothing is relaxed if this stays unset.

## What an operator sees

`/sandbox`'s list page shows a banner the moment a Windows-sandbox
detonation is actually running (`windowsSandboxLiveJob()` checks for a
`*.request.running` file in the request spool — the same claim-before-work
file the worker itself already renames). The banner links to
`/sandbox/vnc`, which requires the admin role (same gate as raw PCAP/
diagnostics downloads) and embeds vendored noVNC
(`dashboard/static/vendor/novnc/`, pinned in
`dashboard/frontend/novnc.lock`) with `viewOnly` set as client-side
belt-and-suspenders on top of the bridge's own server-side enforcement.

## Tests

`tests/test_server.py` exercises the actual WebSocket frame decode and RFB
message filtering against real `socket.socketpair()`s — not mocks of
either protocol — and is the part of this bridge that has to be provably
correct: every `KeyEvent`/`PointerEvent`/`ClientCutText` byte must be
consumed (to stay in sync with the stream) but never reach the VM socket.

#!/usr/bin/env python3
"""Test conpot/proxy_patch.py (#2883) against representative fixtures.

Two things are checked without needing gevent or a container:

1. The patch applies cleanly to a pristine fixture built from the module's
   own SNIPPET/MARKER text, is idempotent, and the result is valid Python
   (syntactic parity with test_json_log_rotation_patch.py's approach).
2. `_conpot_proxy_peer`'s header-parsing logic -- extracted from the applied
   SNIPPET and exec'd standalone against a minimal fake socket -- correctly
   parses a PROXY v1 header, passes through unrecognised traffic unchanged,
   and does not hang or raise on a socket that never sends anything.

3. The do_handle restructuring itself -- the actual #2883 fix -- against a
   stand-in that reproduces gevent's spawn/close contract exactly: the peek
   runs inside what gets spawned (not at accept time), the protocol handler
   receives the rewritten address, the socket is closed on the way out, and a
   BaseException from spawn() still closes rather than leaking.

What this suite still cannot cover is gevent's own greenlet scheduling -- the
race the fix exists to win needs a real StreamServer on the pinned base
image's gevent 25.9.1, and was exercised there (see ISSUE-2883/HANDOVER.md
#6). What it does cover is the shape that makes winning it possible, so a
regression back to a do_read-style accept-time peek fails in CI.

Usage: conpot/tests/test_proxy_patch.py
"""
import importlib.util
import re
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "proxy_patch.py"
SPEC = importlib.util.spec_from_file_location("proxy_patch", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ApplyPatchTest(unittest.TestCase):
    def test_patches_a_pristine_fixture(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "__init__.py"
            target.write_text('__version__ = "0.6.0"\n')
            msg = MODULE.apply_patch(target)
            self.assertIn("appended PROXY v1 shim", msg)
            patched = target.read_text()
            self.assertIn(MODULE.MARKER, patched)
            self.assertIn("_conpot_proxy_do_handle", patched)
            self.assertNotIn("_ProxyStreamServer.do_read = ", patched)
            compile(patched, str(target), "exec")  # still valid Python

    def test_second_run_is_a_no_op(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "__init__.py"
            target.write_text('__version__ = "0.6.0"\n')
            MODULE.apply_patch(target)
            once = target.read_text()
            msg = MODULE.apply_patch(target)
            self.assertIn("already patched", msg)
            self.assertEqual(target.read_text(), once)


class FakeSocket:
    """Minimal recv(n, flags)-only stand-in. buf is consumed byte-by-byte for
    plain recv() calls; MSG_PEEK calls never advance the cursor."""
    def __init__(self, data: bytes):
        self.buf = data
        self.pos = 0

    def recv(self, n, flags=0):
        MSG_PEEK = 2  # socket.MSG_PEEK on Linux; avoid importing socket for a constant
        if flags & MSG_PEEK:
            return self.buf[self.pos:self.pos + n]
        chunk = self.buf[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk


def _load_snippet_namespace():
    """Exec the SNIPPET standalone so its module-level functions can be tested
    without gevent or a container. Two substitutions make that possible:

    * the `gevent.Timeout` wrapper is swapped for a no-op `if True:` -- a plain
      call never blocks against a FakeSocket, and the parsing logic under test
      is unchanged either way;
    * `gevent` itself is stubbed via sys.modules so the SNIPPET's imports
      succeed (the real package only exists inside the pinned conpot image,
      not this repo's CI environment). The stub's
      `_handle_and_close_when_done` is faithful to gevent 25.9.1's own body
      (minus its error-handler bookkeeping), because the do_handle tests
      depend on those semantics being real.
    """
    import os
    import sys
    import types

    snippet = MODULE.SNIPPET.replace(
        "with _proxy_gevent.Timeout(_PROXY_PEEK_TIMEOUT, False):",
        "if True:",
    )

    def _handle_and_close_when_done(handle, close, args):
        try:
            return handle(*args)
        finally:
            close(*args)

    fake_gevent = types.ModuleType("gevent")
    fake_gevent_server = types.ModuleType("gevent.server")
    fake_gevent_server.StreamServer = type("StreamServer", (), {})
    fake_gevent_baseserver = types.ModuleType("gevent.baseserver")
    fake_gevent_baseserver._handle_and_close_when_done = _handle_and_close_when_done
    fake_gevent.server = fake_gevent_server
    fake_gevent.baseserver = fake_gevent_baseserver
    patched = {
        "gevent": fake_gevent,
        "gevent.server": fake_gevent_server,
        "gevent.baseserver": fake_gevent_baseserver,
    }
    originals = {name: sys.modules.get(name) for name in patched}
    sys.modules.update(patched)

    had_env = "CONPOT_PROXY_PROTOCOL" in os.environ
    prev_env = os.environ.get("CONPOT_PROXY_PROTOCOL")
    os.environ["CONPOT_PROXY_PROTOCOL"] = "1"
    try:
        ns: dict = {}
        exec(compile(snippet, "proxy_patch_snippet", "exec"), ns)
    finally:
        if had_env:
            os.environ["CONPOT_PROXY_PROTOCOL"] = prev_env
        else:
            del os.environ["CONPOT_PROXY_PROTOCOL"]
        for name, mod in originals.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
    return ns


SNIPPET_NS = _load_snippet_namespace()
PEER = SNIPPET_NS["_conpot_proxy_peer"]
DO_HANDLE = SNIPPET_NS["_conpot_proxy_do_handle"]
STREAM_SERVER = SNIPPET_NS["_ProxyStreamServer"]


class ProxyPeerParsingTest(unittest.TestCase):
    """Exercises _conpot_proxy_peer's parsing logic directly, against fake
    sockets."""

    peer = staticmethod(PEER)

    def test_parses_proxy_v1_header(self):
        sock = FakeSocket(b"PROXY TCP4 203.0.113.9 10.8.0.5 41234 502\r\n")
        result = self.peer(sock, ("127.0.0.1", 9999))
        self.assertEqual(result, ("203.0.113.9", 41234))

    def test_non_proxy_traffic_passes_through(self):
        sock = FakeSocket(b"\x00\x01\x00\x00\x00\x06\x01\x03")  # modbus, not PROXY
        result = self.peer(sock, ("127.0.0.1", 9999))
        self.assertEqual(result, ("127.0.0.1", 9999))

    def test_empty_socket_falls_through_without_raising(self):
        sock = FakeSocket(b"")
        result = self.peer(sock, ("127.0.0.1", 9999))
        self.assertEqual(result, ("127.0.0.1", 9999))

    def test_malformed_header_falls_through(self):
        sock = FakeSocket(b"PROXY GARBAGE\r\n")
        result = self.peer(sock, ("127.0.0.1", 9999))
        self.assertEqual(result, ("127.0.0.1", 9999))


class FakeServer:
    """Stand-in for gevent's BaseServer with the three attributes do_handle
    touches. `spawn=None` exercises the synchronous branch; a callable
    exercises the spawned branch."""

    def __init__(self, handle, spawn=None):
        self._handle = handle
        self._spawn = spawn
        self.closed = []

    def do_close(self, *args):
        self.closed.append(args)


class DoHandleRestructureTest(unittest.TestCase):
    """#2883's actual fix: the peek must happen inside what do_handle spawns
    -- i.e. in the per-connection greenlet where blocking is legal -- and not
    at accept time. A regression to the old do_read-style shim, or to peeking
    in do_handle's own body before the spawn, fails here."""

    def _server(self, spawn=None):
        seen = []

        def handle(sock, address):
            seen.append(address)

        return FakeServer(handle, spawn), seen

    def test_handler_gets_the_header_address_when_spawned(self):
        spawned = []

        def spawn(fn, *args):
            spawned.append(fn)
            return fn(*args)

        server, seen = self._server(spawn)
        sock = FakeSocket(b"PROXY TCP4 203.0.113.9 10.8.0.5 41234 502\r\n")
        DO_HANDLE(server, sock, ("10.8.0.1", 51336))
        self.assertEqual(seen, [("203.0.113.9", 41234)])
        self.assertEqual(len(spawned), 1)
        self.assertEqual(server.closed, [(sock, ("10.8.0.1", 51336))])

    def test_handler_gets_the_header_address_without_a_spawner(self):
        server, seen = self._server(None)
        sock = FakeSocket(b"PROXY TCP4 203.0.113.9 10.8.0.5 41234 502\r\n")
        DO_HANDLE(server, sock, ("10.8.0.1", 51336))
        self.assertEqual(seen, [("203.0.113.9", 41234)])

    def test_peek_happens_inside_the_spawned_call_not_at_accept_time(self):
        """The whole point of #2883. Capture what do_handle hands to spawn
        without running it: the socket must still be unread, i.e. nothing
        peeked or consumed it in do_handle's own (Hub-context) body."""
        deferred = []

        def spawn(fn, *args):
            deferred.append((fn, args))

        server, seen = self._server(spawn)
        sock = FakeSocket(b"PROXY TCP4 203.0.113.9 10.8.0.5 41234 502\r\n")
        DO_HANDLE(server, sock, ("10.8.0.1", 51336))
        self.assertEqual(sock.pos, 0)
        self.assertEqual(seen, [])
        self.assertEqual(server.closed, [])
        fn, args = deferred[0]
        fn(*args)
        self.assertEqual(seen, [("203.0.113.9", 41234)])
        self.assertGreater(sock.pos, 0)

    def test_non_proxy_connection_keeps_its_real_address(self):
        server, seen = self._server(lambda fn, *a: fn(*a))
        sock = FakeSocket(b"\x00\x01\x00\x00\x00\x06\x01\x03")
        DO_HANDLE(server, sock, ("127.0.0.1", 9999))
        self.assertEqual(seen, [("127.0.0.1", 9999)])

    def test_base_exception_from_spawn_still_closes_the_socket(self):
        """gevent's do_handle uses a bare `except:` here; a GreenletExit or a
        gevent.Timeout out of spawn() is a BaseException, and swallowing it
        into an `except Exception:` would leak the socket."""

        class Shutdown(BaseException):
            pass

        def spawn(fn, *args):
            raise Shutdown

        server, _ = self._server(spawn)
        sock = FakeSocket(b"")
        with self.assertRaises(Shutdown):
            DO_HANDLE(server, sock, ("10.8.0.1", 51336))
        self.assertEqual(server.closed, [(sock, ("10.8.0.1", 51336))])

    def test_patch_targets_stream_server_so_udp_is_unaffected(self):
        self.assertIs(STREAM_SERVER.do_handle, DO_HANDLE)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Let the operator txtcmds_path overlay shadow a bare-name builtin (#2926).

Upstream's HoneyPotBaseProtocol.getCommand() (src/cowrie/shell/protocol.py)
returns a bare-name builtin from self.commands unconditionally, before the
operator overlay configured by cowrie.cfg's `txtcmds_path` is ever
consulted -- the overlay is only reachable through a full-path invocation
(`/usr/bin/free`, not `free`) -- and not even then for a name cowrie also
keys by its absolute path, which is every builtin. Attackers overwhelmingly
type bare names, so eleven of this repo's persona overlay entries were
silently dead at the pinned commit (netstat, ps, uname, free, id, last,
lspci, uptime, w, who, plus the generated bin/dd): `nproc` disagreeing with
`lscpu` in the same session (#2926's own reproduction) is the cheapest tell,
but `free`/`uptime`/`lspci` leaking the real container host's stats instead
of the gpu01 persona's are the ones that actually cost a session.

This patch makes getCommand() check the overlay directory first for a
bare-name match, falling through to upstream's original builtin-first
behaviour when no overlay file exists.

Two deliberate limits on that, both of which cost real emulation if
dropped (measured against the live hp-cowrie container, not assumed):

* **Bare names only.** ``self.commands`` is keyed by the absolute path as
  well as the bare name (``commands["free"]`` *and*
  ``commands["/usr/bin/free"]`` -- 105 absolute keys at the pinned
  commit), so this block is entered for a path-form invocation too. And
  ``Path("txtcmds") / "bin" / "/bin/echo"`` is ``/bin/echo``: pathlib
  resets on an absolute right-hand operand. Probing the overlay for a
  path-form command therefore reads the *container's real binary* and
  writes it to the session -- 67 of those 105 keys resolve to a real file
  inside the runtime image, so ``/bin/ls``, ``/bin/cat``, ``/bin/bash``
  and 64 others would dump an ELF instead of being emulated.

* **An allow-list, not every builtin.** Only argument-insensitive
  informational commands, where a static text file is a faithful stand-in
  for the builtin. ``uname`` and ``dd`` are the counter-examples that set
  the rule: ``Command_uname`` renders the persona from cowrie.cfg's
  ``[shell]`` keys (a canned "Linux" overlay is a *bigger* tell than the
  one #2926 was filed for) and ``Command_dd`` parses if=/of=/bs=/count=
  and captures ``input_data`` -- ``cat payload | dd of=/tmp/x`` is a live
  capture path. Their overlays are retired rather than promoted; see
  bin/gen-dynamic-txtcmds.py.

Same shape as hellpot/router_patch.py and mailoney's json-sink patches:
exact-match string replacement with a marker for idempotency, applied at
Docker build time against the real upstream source (not a monkeypatch
injected via a separate importable module), because getCommand is called
directly by class method dispatch with no seam to override without editing
the class body itself.
"""
from pathlib import Path

MARKER = "honeypot-stack: overlay-before-builtin (#2926)"
TARGET = Path("/cowrie/cowrie-git/src/cowrie/shell/protocol.py")

# Verbatim from cowrie v3.0.12 (ced855a5cda953eb4ad439d8ee8060afe4234fe4),
# src/cowrie/shell/protocol.py's HoneyPotBaseProtocol.getCommand().
OLD = '''    def getCommand(self, cmd, paths, cwd):
        if not cmd.strip():
            return None
        path = None
        if cmd in self.commands:
            return self.commands[cmd]'''

NEW = '''    def getCommand(self, cmd, paths, cwd):
        if not cmd.strip():
            return None
        path = None
        if cmd in self.commands:
            # --- MARKER_PLACEHOLDER ---
            # A bare-name overlay file takes priority over the builtin --
            # upstream only consulted txtcmds_path for a path-form
            # invocation, so an override placed at a builtin's own name
            # (free, uptime, ...) was unreachable. Checked against every
            # directory a bare command name could plausibly resolve from,
            # since getCommand has no $PATH context at this point -- only
            # cmd itself, before path resolution below.
            #
            # Bare names ONLY: self.commands is keyed by the absolute path
            # too, and Path(txtcmds_path) / prefix / "/bin/echo" is just
            # "/bin/echo" -- probing on a path-form command would read the
            # container's real binary and write the ELF to the session.
            #
            # Allow-list, not every builtin: a flat text file is only a
            # faithful stand-in for an argument-insensitive informational
            # command. uname (persona rendered from cowrie.cfg's [shell]
            # keys) and dd (operand parsing + input_data capture) both
            # regress if a canned overlay outranks them.
            if "/" not in cmd and cmd in (
                "free", "id", "last", "lspci", "netstat",
                "ps", "uptime", "w", "who",
            ):
                txtcmds_path = CowrieConfig.get("honeypot", "txtcmds_path", fallback="")
                if txtcmds_path:
                    for prefix in ("bin", "usr/bin", "sbin", "usr/sbin"):
                        operator_path = Path(txtcmds_path) / prefix / cmd
                        if operator_path.is_file():
                            return self.txtcmd(operator_path.read_bytes())
            return self.commands[cmd]'''.replace("MARKER_PLACEHOLDER", MARKER)


def apply_patch(target: Path) -> str:
    """Idempotently apply the reorder; returns a one-line status message.
    Factored out (importable without side effects) so
    tests/test_txtcmds_priority_patch.py can exercise this module without
    a real cowrie install."""
    text = target.read_text()
    if MARKER in text:
        return f"txtcmds_priority_patch: {target} already patched, skipping"
    count = text.count(OLD)
    if count != 1:
        raise SystemExit(
            f"txtcmds_priority_patch: expected exactly 1 match for "
            f"getCommand()'s builtin-return block in {target}, found {count}"
        )
    target.write_text(text.replace(OLD, NEW, 1))
    return f"txtcmds_priority_patch: reordered getCommand() in {target}"


if __name__ == "__main__":
    print(apply_patch(TARGET))

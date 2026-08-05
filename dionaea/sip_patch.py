#!/usr/bin/env python3
"""Fix two crashing bugs in dionaea's SIP idle-timeout/timer plumbing (#724).

Confirmed live (`docker logs --since 60m hp-dionaea`): on essentially every
SIP connection, one or both of these fire on the connection-handler thread
(caught per-thread by threading's own default exception handler, so the
container stays "healthy" but the log is drowned in noise and idle-timeout
cleanup for SIP calls is silently broken):

    TypeError: __handle_timeout_idle() missing 2 required positional
    arguments: 'watcher' and 'events'

    AttributeError: 'Timer' object has no attribute 'active'

Both bugs are leftovers from dionaea/__init__.py's Timer/SubTimer classes
being a pure-Python threading-based replacement for the old pyev/libev event
loop (see that file's own docstring): SubTimer.run() calls
`self.function(*self.args, **self.kwargs)` with whatever args were bound at
registration time -- it no longer supplies a (watcher, events) pair the way
pyev's real event loop used to, and the new Timer class exposes none of
pyev's Watcher attributes (`active`, `pending`, `stop()`) at all, only
`start()`/`cancel()`/`reset()`.

sip/__init__.py's SipCall still assumes the old pyev API in two places:

1. `self._timers["idle"] = Timer(60.0, self.__handle_timeout_idle, ...)`
   registers a callback that takes `(self, watcher, events)`, but nothing
   ever supplies watcher/events any more -- every fire is a TypeError.
2. `close()`'s debug-log line unconditionally evaluates `timer.active` and
   `timer.pending` as `str.format()` arguments (evaluated regardless of the
   configured log level), and the following `timer.stop()` calls a method
   that doesn't exist either -- both raise AttributeError before the SIP
   call can actually tear down its timers.

This patch drops the two unused positional parameters from
__handle_timeout_idle (nothing in its body reads watcher/events), removes
the broken active/pending debug line, and calls the Timer class's real
cancel() method instead of the nonexistent stop().
"""
from pathlib import Path

MARKER = "honeypot-stack: SIP idle-timer Timer-API patch (#724)"
TARGET = Path("/opt/dionaea/lib/dionaea/python/dionaea/sip/__init__.py")

OLD_CALLBACK = """    def __handle_timeout_idle(self, watcher, events):
        logger.debug("{!s} __handle_timeout_idle".format(self))"""

NEW_CALLBACK = """    # --- {marker} ---
    # See #724: Timer/SubTimer (dionaea/__init__.py) no longer supplies a
    # (watcher, events) pair the way pyev's real event loop used to --
    # every fire raised TypeError before this fix.
    def __handle_timeout_idle(self):
        logger.debug("{{!s}} __handle_timeout_idle".format(self))
    # --- end {marker} ---""".format(marker=MARKER)

OLD_CLOSE = """            logger.debug("SipCall timer {} active {} pending {}".format(timer,timer.active,timer.pending))
            #if timer.active == True or timer.pending == True:
            #    logger.warn("SipCall Stopping {}".format(name))

            timer.stop()"""

NEW_CLOSE = """            # --- {marker} ---
            # See #724: the new Timer class has no active/pending
            # attributes and no stop() method (only start/cancel/reset) --
            # both the debug line above and timer.stop() raised
            # AttributeError on every call teardown before this fix.
            timer.cancel()
            # --- end {marker} ---""".format(marker=MARKER)

text = TARGET.read_text()
if MARKER in text:
    print(f"sip_patch: {TARGET} already patched, skipping")
else:
    if text.count(OLD_CALLBACK) != 1:
        raise SystemExit("sip_patch: expected exactly one occurrence of __handle_timeout_idle's (watcher, events) signature, refusing to patch blind")
    if text.count(OLD_CLOSE) != 1:
        raise SystemExit("sip_patch: expected exactly one occurrence of the active/pending/stop() teardown block, refusing to patch blind")
    text = text.replace(OLD_CALLBACK, NEW_CALLBACK, 1)
    text = text.replace(OLD_CLOSE, NEW_CLOSE, 1)
    TARGET.write_text(text)
    print(f"sip_patch: fixed the idle-timer Timer-API mismatches in {TARGET}")

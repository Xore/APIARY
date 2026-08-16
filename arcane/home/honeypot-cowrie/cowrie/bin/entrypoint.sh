#!/bin/sh
set -e

# Generate dynamic txtcmds (free / df / dd / ss / proc/*) with
# randomised-but-plausible values before Cowrie starts.
# Each container boot produces fresh numbers so repeated sessions
# never see identical output.
/cowrie/cowrie-env/bin/python3 \
    /cowrie/cowrie-git/bin/gen-dynamic-txtcmds.py \
    /cowrie/cowrie-git/txtcmds

exec /cowrie/cowrie-env/bin/python3 \
     /cowrie/cowrie-env/bin/twistd \
     -n --umask=0022 --pidfile= \
     --logger cowrie.python.logfile.stdoutLogger \
     cowrie

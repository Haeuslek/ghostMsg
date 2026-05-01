#!/bin/sh
# Wrapper script installed to /usr/bin/ghostchat
# Launches ghostchat with bytecode caching suppressed.
PYTHONDONTWRITEBYTECODE=1 exec python3 /usr/share/ghostchat/ghostchat.py "$@"

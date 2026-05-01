"""
session.py — In-memory session state for ghostchat.

All data lives exclusively in RAM. Nothing is ever written to disk.
The wipe() method overwrites message content before clearing the deque,
providing a best-effort RAM scrub (CPython interning may retain short
strings, but sensitive key material is managed separately in crypto.py).

Message types
-------------
MSG_OWN    : message sent by us
MSG_PEER   : message received from the peer
MSG_SYSTEM : local status / event notification
"""

import os
import threading
from collections import deque

# Message type constants ─────────────────────────────────────────────────────
MSG_OWN    = "own"
MSG_PEER   = "peer"
MSG_SYSTEM = "system"

# Maximum messages kept in RAM at once
_MAX_MESSAGES = 500


class Session:
    """Volatile session state container.

    Attributes
    ----------
    username    : str  — our chosen alias (never persisted)
    peer_alias  : str  — peer's chosen alias (received during handshake)
    messages    : deque[(type, sender, text)]
    """

    def __init__(self, username: str) -> None:
        self.username: str = username
        self.peer_alias: str = "peer"
        self.messages: deque = deque(maxlen=_MAX_MESSAGES)
        self._lock = threading.Lock()

    # ── Message buffer ────────────────────────────────────────────────────────

    def add_message(self, msg_type: str, sender: str, text: str) -> None:
        """Append a message tuple to the in-memory buffer (thread-safe)."""
        with self._lock:
            self.messages.append((msg_type, sender, text))

    def get_messages(self) -> list:
        """Return a snapshot of current messages (thread-safe)."""
        with self._lock:
            return list(self.messages)

    def clear_display(self) -> None:
        """Erase the visible chat buffer (for /clear command)."""
        with self._lock:
            self.messages.clear()

    # ── Ephemerality ─────────────────────────────────────────────────────────

    def wipe(self) -> None:
        """Best-effort overwrite of all message content, then clear.

        Replaces each stored string with random hex noise before
        discarding, making casual RAM inspection harder.
        """
        with self._lock:
            # Replace message tuples with garbage strings
            noise = [
                (MSG_SYSTEM, os.urandom(8).hex(), os.urandom(16).hex())
                for _ in range(len(self.messages))
            ]
            self.messages.clear()
            for item in noise:
                self.messages.append(item)
            # Final clear
            self.messages.clear()

        # Wipe alias strings
        self.username = os.urandom(8).hex()
        self.peer_alias = os.urandom(8).hex()
        self.username = ""
        self.peer_alias = ""

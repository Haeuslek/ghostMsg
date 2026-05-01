"""
tui.py — Curses TUI for ghostchat.

Layout
------
  row 0          : header bar  (alias ↔ peer info)
  rows 1…(h-4)   : scrolling message log
  row (h-3)      : horizontal divider
  row (h-2)      : input prompt  "> "
  row (h-1)      : status / keybindings hint

Color pairs
-----------
  1 → cyan   : our own messages    (right-aligned)
  2 → white  : peer messages       (left-aligned)
  3 → yellow : system / events     (center-aligned)
  4 → header : black-on-cyan       (header bar)
  5 → dim    : status bar hint

The TUI owns the main thread (via curses.wrapper). The receive thread
calls notify_refresh() to trigger a redraw from the background.
"""

import curses
import threading
import time

from session import MSG_OWN, MSG_PEER, MSG_SYSTEM

# Colour pair IDs ────────────────────────────────────────────────────────────
_CP_OWN    = 1   # cyan   — sent messages
_CP_PEER   = 2   # white  — received messages
_CP_SYS    = 3   # yellow — system events
_CP_HEADER = 4   # black on cyan — header bar
_CP_STATUS = 5   # dim white — status bar

# Minimum usable terminal size
_MIN_COLS = 40
_MIN_ROWS = 8


class TUI:
    """Full-screen curses chat interface.

    Parameters
    ----------
    session    : Session object (message buffer + aliases)
    send_fn    : callable(text: str) — encrypt+send a message or command
    on_quit_fn : callable() — triggered by /quit or Ctrl-C
    on_burn_fn : callable() — triggered by /burn
    peer_info  : display string for the remote peer (e.g. "192.168.1.2:5555")
    """

    def __init__(self, session, send_fn, on_quit_fn, on_burn_fn,
                 peer_info: str) -> None:
        self._session    = session
        self._send_fn    = send_fn
        self._on_quit    = on_quit_fn
        self._on_burn    = on_burn_fn
        self._peer_info  = peer_info
        self._input_buf  = ""
        self._running    = True
        self._refresh    = threading.Event()

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Enter the curses event loop (blocks until quit)."""
        curses.wrapper(self._main)

    def notify_refresh(self) -> None:
        """Signal the TUI to redraw on its next tick (safe to call from any thread)."""
        self._refresh.set()

    def stop(self) -> None:
        """Request the TUI event loop to exit."""
        self._running = False
        self._refresh.set()

    # ── Curses setup ──────────────────────────────────────────────────────────

    def _init_colors(self) -> None:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(_CP_OWN,    curses.COLOR_CYAN,   -1)
        curses.init_pair(_CP_PEER,   curses.COLOR_WHITE,  -1)
        curses.init_pair(_CP_SYS,    curses.COLOR_YELLOW, -1)
        curses.init_pair(_CP_HEADER, curses.COLOR_BLACK,  curses.COLOR_CYAN)
        curses.init_pair(_CP_STATUS, curses.COLOR_WHITE,  -1)

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _main(self, stdscr) -> None:
        self._stdscr = stdscr
        self._init_colors()
        curses.curs_set(1)
        stdscr.nodelay(True)   # non-blocking getch
        stdscr.keypad(True)
        self._refresh.set()    # force first draw

        while self._running:
            h, w = stdscr.getmaxyx()

            # Guard: terminal too small
            if h < _MIN_ROWS or w < _MIN_COLS:
                stdscr.erase()
                msg = f"Terminal too small (need {_MIN_COLS}x{_MIN_ROWS})"
                try:
                    stdscr.addstr(0, 0, msg, curses.color_pair(_CP_SYS))
                except curses.error:
                    pass
                stdscr.refresh()
                time.sleep(0.1)
                ch = stdscr.getch()
                if ch == curses.KEY_RESIZE:
                    self._refresh.set()
                continue

            # Redraw when flagged
            if self._refresh.is_set():
                self._draw(stdscr)
                self._refresh.clear()

            # Input
            ch = stdscr.getch()
            if ch == curses.ERR:
                time.sleep(0.04)   # ~25 fps idle
                continue
            self._handle_key(ch)

    # ── Drawing ───────────────────────────────────────────────────────────────

    def _draw(self, stdscr) -> None:
        h, w = stdscr.getmaxyx()
        stdscr.erase()

        # ── Header bar (row 0) ────────────────────────────────────────────────
        header = f" ghostchat  {self._session.username} ↔ {self._peer_info} "
        header = header[:w - 1].ljust(w - 1)
        try:
            stdscr.addstr(0, 0, header, curses.color_pair(_CP_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

        # ── Message log (rows 1 … h-4) ────────────────────────────────────────
        msg_rows = h - 4
        msgs = self._session.get_messages()
        visible = msgs[-msg_rows:] if msg_rows > 0 else []
        for idx, (mtype, sender, text) in enumerate(visible):
            row = 1 + idx
            if row >= h - 3:
                break
            self._draw_message(stdscr, row, w, mtype, sender, text)

        # ── Divider (h-3) ─────────────────────────────────────────────────────
        try:
            stdscr.addstr(h - 3, 0, "─" * (w - 1), curses.color_pair(_CP_STATUS))
        except curses.error:
            pass

        # ── Input prompt (h-2) ────────────────────────────────────────────────
        prompt = "> "
        max_input = w - len(prompt) - 1
        input_display = self._input_buf[-max_input:] if max_input > 0 else ""
        try:
            stdscr.addstr(h - 2, 0, prompt + input_display,
                          curses.color_pair(_CP_STATUS))
        except curses.error:
            pass

        # ── Status bar (h-1) ──────────────────────────────────────────────────
        status = " /quit  /clear  /burn  /whoami  /ping"
        try:
            stdscr.addstr(h - 1, 0, status[:w - 1],
                          curses.color_pair(_CP_SYS) | curses.A_DIM)
        except curses.error:
            pass

        # ── Cursor position ───────────────────────────────────────────────────
        cursor_x = min(len(prompt) + len(input_display), w - 1)
        try:
            stdscr.move(h - 2, cursor_x)
        except curses.error:
            pass

        stdscr.refresh()

    def _draw_message(self, stdscr, row: int, w: int,
                      mtype: str, sender: str, text: str) -> None:
        try:
            if mtype == MSG_SYSTEM:
                line = f"  *** {text} ***"
                x = max(0, (w - len(line)) // 2)
                stdscr.addstr(row, x, line[:w - 1], curses.color_pair(_CP_SYS))
            elif mtype == MSG_OWN:
                line = f"{sender}: {text}"
                x = max(0, w - len(line) - 1)
                stdscr.addstr(row, x, line[:w - 1],
                              curses.color_pair(_CP_OWN) | curses.A_BOLD)
            else:  # MSG_PEER
                line = f"{sender}: {text}"
                stdscr.addstr(row, 0, line[:w - 1], curses.color_pair(_CP_PEER))
        except curses.error:
            pass   # Harmless overrun at terminal edge

    # ── Input handling ────────────────────────────────────────────────────────

    def _handle_key(self, ch: int) -> None:
        if ch == curses.KEY_RESIZE:
            self._refresh.set()

        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if self._input_buf:
                self._input_buf = self._input_buf[:-1]
                self._refresh.set()

        elif ch in (10, 13, curses.KEY_ENTER):
            text = self._input_buf.strip()
            self._input_buf = ""
            if text:
                self._dispatch(text)
            self._refresh.set()

        elif 32 <= ch <= 126:
            self._input_buf += chr(ch)
            self._refresh.set()

    def _dispatch(self, text: str) -> None:
        """Route a confirmed input line to a command handler or send it."""
        if text == "/quit":
            self._session.add_message(MSG_SYSTEM, "", "Disconnecting…")
            self._refresh.set()
            self._running = False
            self._on_quit()

        elif text == "/clear":
            self._session.clear_display()
            self._refresh.set()

        elif text == "/burn":
            self._session.add_message(MSG_SYSTEM, "", "BURN — wiping both peers…")
            self._refresh.set()
            self._running = False
            self._on_burn()

        elif text == "/whoami":
            info = (f"alias='{self._session.username}'  "
                    f"peer={self._peer_info}")
            self._session.add_message(MSG_SYSTEM, "", info)
            self._refresh.set()

        elif text == "/ping":
            # Delegate to send_fn which will timestamp and dispatch
            self._send_fn("/ping")

        else:
            # Ordinary chat message
            self._session.add_message(MSG_OWN, self._session.username, text)
            self._send_fn(text)
            self._refresh.set()

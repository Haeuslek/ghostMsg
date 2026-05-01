#!/usr/bin/env python3
"""
ghostchat.py — Entrypoint for the ghostchat ephemeral P2P terminal messenger.

Usage
-----
  python ghostchat.py --host 5555
  python ghostchat.py --connect 192.168.1.100 5555
  python ghostchat.py --host 5555 --passphrase abc123

All key material and messages live exclusively in RAM and are overwritten
on exit. No logs, no temp files, no .pyc cache.
"""

# ── Prevent any bytecode cache writes before importing anything ──────────────
import os, sys
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

# Ensure sibling modules are importable when installed to /usr/share/ghostchat
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import threading
import time

from session import Session, MSG_SYSTEM
from crypto import (
    generate_keypair,
    derive_shared_key,
    wipe_buf,
    passphrase_handshake_host,
    passphrase_handshake_client,
)
from network import (
    send_frame,
    recv_frame,
    send_message,
    host_listen,
    client_connect,
    RecvThread,
)
from tui import TUI


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="ghostchat",
        description="Ephemeral encrypted P2P terminal chat. No logs. No trace.",
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--host", metavar="PORT", type=int,
        help="Host mode: listen on PORT for an incoming connection",
    )
    mode.add_argument(
        "--connect", nargs=2, metavar=("HOST", "PORT"),
        help="Client mode: connect to HOST on PORT",
    )
    p.add_argument(
        "--passphrase", metavar="SECRET",
        help="Optional shared passphrase gate (HMAC-verified before chat opens)",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Start-up banner
# ---------------------------------------------------------------------------

def _banner() -> None:
    G, Y, R = "\033[1;32m", "\033[0;33m", "\033[0m"
    print(f"{G}")
    print("   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗ ██████╗██╗  ██╗ █████╗ ████████╗")
    print("  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗╚══██╔══╝")
    print("  ██║  ███╗███████║██║   ██║███████╗   ██║   ██║     ███████║███████║   ██║   ")
    print("  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║     ██╔══██║██╔══██║   ██║   ")
    print("  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚██████╗██║  ██║██║  ██║   ██║   ")
    print("   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝  ")
    print(f"{R}")
    print("  Ephemeral P2P encrypted terminal chat. No logs. No persistence.")
    print()
    print(f"  {Y}⚠  Add a SPACE before this command to exclude it from shell history.{R}")
    print()


def _get_username() -> str:
    while True:
        name = input("  Enter your alias (never stored): ").strip()
        if 1 <= len(name) <= 32:
            return name
        print("  Alias must be 1–32 characters.")


# ---------------------------------------------------------------------------
# ECDH handshake
# ---------------------------------------------------------------------------

def _perform_handshake(sock, is_host: bool):
    """Exchange X25519 public keys over the raw socket.

    Host sends first; client sends second.
    Returns (private_key, peer_public_bytes).
    """
    private_key, my_pub = generate_keypair()
    if is_host:
        send_frame(sock, my_pub)
        peer_pub = recv_frame(sock)
    else:
        peer_pub = recv_frame(sock)
        send_frame(sock, my_pub)
    return private_key, peer_pub


# ---------------------------------------------------------------------------
# Graceful shutdown (called from main thread or receive thread)
# ---------------------------------------------------------------------------

def _make_shutdown(
    sock, aes_key_ref: list, session: Session, tui_ref: list,
    recv_thread_ref: list, shutdown_event: threading.Event,
):
    """Factory that returns a thread-safe, idempotent shutdown callable."""

    def shutdown(
        notice: str = "",
        send_disconnect: bool = False,
        send_burn: bool = False,
        delay: float = 0.0,
    ) -> None:
        if shutdown_event.is_set():
            return
        shutdown_event.set()

        # Optionally notify peer before closing
        if send_disconnect or send_burn:
            try:
                msg_type = "burn" if send_burn else "disconnect"
                send_message(sock, aes_key_ref[0], {"type": msg_type})
            except Exception:
                pass

        if notice:
            session.add_message(MSG_SYSTEM, "", notice)

        # Stop the receive thread
        if recv_thread_ref[0]:
            recv_thread_ref[0].stop()

        # Stop the TUI (unblocks curses.wrapper)
        if tui_ref[0]:
            tui_ref[0].stop()

        # Brief delay so any final message renders in the TUI
        if delay:
            time.sleep(delay)

    return shutdown


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()
    _banner()
    username = _get_username()
    print()

    is_host = args.host is not None
    aes_key_ref: list     = [None]
    tui_ref: list         = [None]
    recv_thread_ref: list = [None]
    shutdown_event        = threading.Event()

    # ── TCP connection ────────────────────────────────────────────────────────
    sock = None
    peer_info = ""
    try:
        if is_host:
            port = args.host
            print(f"  Listening on 0.0.0.0:{port}  (waiting for peer…)")
            sock, addr = host_listen(port)
            peer_info = f"{addr[0]}:{addr[1]}"
            print(f"  Peer connected from {peer_info}")
        else:
            host_arg, port_arg = args.connect[0], int(args.connect[1])
            peer_info = f"{host_arg}:{port_arg}"
            print(f"  Connecting to {peer_info}…")
            sock = client_connect(host_arg, port_arg)
            print("  Connected.")
    except ConnectionRefusedError:
        print("\n  [!] Connection refused — is the host listening?")
        sys.exit(1)
    except OSError as exc:
        print(f"\n  [!] Network error: {exc}")
        sys.exit(1)

    # ── ECDH handshake ────────────────────────────────────────────────────────
    print("  Performing key exchange…")
    try:
        private_key, peer_pub_bytes = _perform_handshake(sock, is_host)
        aes_key = derive_shared_key(private_key, peer_pub_bytes)
        aes_key_ref[0] = aes_key
        del private_key          # remove private key reference
    except Exception as exc:
        print(f"  [!] Key exchange failed: {exc}")
        sock.close()
        sys.exit(1)

    # ── Passphrase gate (optional) ────────────────────────────────────────────
    if args.passphrase:
        print("  Verifying passphrase…")
        try:
            _send_raw = lambda d: send_frame(sock, d)
            _recv_raw = lambda: recv_frame(sock)
            if is_host:
                ok = passphrase_handshake_host(_send_raw, _recv_raw, args.passphrase)
            else:
                ok = passphrase_handshake_client(_send_raw, _recv_raw, args.passphrase)
            if not ok:
                print("  [!] Passphrase mismatch — disconnecting.")
                sock.close()
                sys.exit(1)
            print("  Passphrase verified ✓")
        except Exception as exc:
            print(f"  [!] Passphrase verification failed: {exc}")
            sock.close()
            sys.exit(1)

    print("  Encrypted channel established. Starting chat…\n")
    time.sleep(0.4)

    # ── Session + shutdown ────────────────────────────────────────────────────
    session = Session(username)
    shutdown = _make_shutdown(
        sock, aes_key_ref, session, tui_ref, recv_thread_ref, shutdown_event
    )

    # ── Ping tracking ─────────────────────────────────────────────────────────
    _ping_lock: threading.Lock = threading.Lock()
    _pending_ping: dict = {}

    # ── send_fn (called from TUI thread) ──────────────────────────────────────
    def send_fn(text: str) -> None:
        try:
            if text == "/ping":
                ts = time.time()
                with _ping_lock:
                    _pending_ping["ts"] = ts
                send_message(sock, aes_key_ref[0], {"type": "ping", "ts": ts})
            else:
                send_message(sock, aes_key_ref[0], {"type": "msg", "text": text})
        except Exception:
            session.add_message(MSG_SYSTEM, "", "Send failed — peer may have disconnected.")
            if tui_ref[0]:
                tui_ref[0].notify_refresh()

    # ── Receive callbacks (called from RecvThread) ────────────────────────────
    def on_message(payload: dict) -> None:
        mtype = payload.get("type", "")

        if mtype == "msg":
            session.add_message("peer", session.peer_alias,
                                 payload.get("text", ""))

        elif mtype == "alias":
            session.peer_alias = payload.get("name", "peer")
            session.add_message(MSG_SYSTEM, "",
                                 f"Peer is '{session.peer_alias}'")

        elif mtype == "ping":
            # Respond with pong immediately
            try:
                send_message(sock, aes_key_ref[0],
                             {"type": "pong", "ts": payload.get("ts", 0)})
            except Exception:
                pass
            return   # No display update needed

        elif mtype == "pong":
            with _ping_lock:
                sent_ts = _pending_ping.pop("ts", None)
            if sent_ts is not None:
                rtt = (time.time() - sent_ts) * 1000
                session.add_message(MSG_SYSTEM, "", f"Pong! RTT {rtt:.1f} ms")

        elif mtype == "disconnect":
            shutdown(notice="Peer disconnected.", delay=1.2)
            return

        elif mtype == "burn":
            shutdown(notice="BURN received — wiping…", delay=0.6)
            return

        if tui_ref[0]:
            tui_ref[0].notify_refresh()

    def on_disconnect() -> None:
        shutdown(notice="Peer disconnected unexpectedly.", delay=1.0)

    # ── TUI callbacks (called from TUI / main thread) ─────────────────────────
    def on_quit() -> None:
        shutdown(send_disconnect=True)

    def on_burn() -> None:
        shutdown(send_burn=True, delay=0.4)

    # ── Start receive thread ──────────────────────────────────────────────────
    recv_thread = RecvThread(sock, aes_key_ref, on_message, on_disconnect)
    recv_thread_ref[0] = recv_thread
    recv_thread.start()

    # ── Announce our alias to peer ────────────────────────────────────────────
    try:
        send_message(sock, aes_key_ref[0], {"type": "alias", "name": username})
    except Exception:
        pass

    # ── Build and run TUI ─────────────────────────────────────────────────────
    tui = TUI(session, send_fn, on_quit, on_burn, peer_info)
    tui_ref[0] = tui

    session.add_message(MSG_SYSTEM, "",
                        f"Connected to {peer_info}  |  /quit to exit")

    try:
        tui.run()          # blocks until TUI exits
    except KeyboardInterrupt:
        shutdown(send_disconnect=True)

    # ── Post-TUI cleanup: wipe all sensitive data ─────────────────────────────
    recv_thread.stop()
    try:
        sock.close()
    except Exception:
        pass

    # Overwrite AES key bytes
    if aes_key_ref[0] is not None:
        key_buf = bytearray(aes_key_ref[0])
        wipe_buf(key_buf)
        aes_key_ref[0] = None
        del key_buf

    session.wipe()
    del session

    # Clear the visible terminal buffer
    os.system("clear" if os.name != "nt" else "cls")
    print("Session ended. All keys and messages wiped from memory.")


if __name__ == "__main__":
    main()

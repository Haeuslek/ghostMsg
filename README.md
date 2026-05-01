# ghostchat

Ephemeral encrypted P2P terminal messenger. No server, no logs, no persistence.  
Everything lives in RAM and is wiped the moment you disconnect.

```
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗ ██████╗██╗  ██╗ █████╗ ████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██║     ███████║███████║   ██║
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║     ██╔══██║██╔══██║   ██║
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚██████╗██║  ██║██║  ██║   ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
```

---

## Features

- **X25519 ECDH** key exchange — ephemeral keypair, never touches disk  
- **AES-256-GCM** per-message encryption with a fresh random nonce each time  
- **HKDF-SHA256** key derivation from the raw ECDH shared secret  
- **Optional passphrase gate** — Scrypt KDF + HMAC-SHA256 challenge-response  
- **Curses TUI** — split-pane (message log + input bar), colour-coded, resize-aware  
- **Zero disk writes** — no logs, no temp files, no `.pyc` cache  
- **/burn** command — both peers wipe simultaneously on demand  

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Python      | 3.10+   |
| cryptography | any recent release |

```bash
pip install cryptography
```

> **Shell history tip:** Add a leading space before the command to prevent it
> being written to `~/.bash_history` / `~/.zsh_history`
> (requires `HISTCONTROL=ignorespace` in bash, default in zsh).

---

## Installation

### Run directly (no install)

```bash
git clone https://github.com/example/ghostchat
cd ghostchat
pip install cryptography
python ghostchat/ghostchat.py --host 5555
```

### Install system-wide (Linux)

```bash
sudo pip3 install cryptography
sudo cp ghostchat/*.py /usr/share/ghostchat/
sudo install -m755 debian/ghostchat.sh /usr/bin/ghostchat
```

### Install from .deb

```bash
dpkg -i ghostchat_1.0.0_all.deb
# or after adding the PPA:
apt install ghostchat
```

---

## Usage

### LAN — two machines on the same network

**Machine A (host):**
```bash
 python ghostchat/ghostchat.py --host 5555
```

**Machine B (client):**
```bash
 python ghostchat/ghostchat.py --connect 192.168.1.100 5555
```

### Internet — via port forwarding

Forward TCP port `5555` on your router to Machine A's LAN IP, then:

```bash
 python ghostchat/ghostchat.py --connect <your-public-ip> 5555
```

### With passphrase gate

```bash
# Host
 python ghostchat/ghostchat.py --host 5555 --passphrase "correct horse battery"

# Client (must supply the same passphrase)
 python ghostchat/ghostchat.py --connect 192.168.1.100 5555 --passphrase "correct horse battery"
```

---

## In-chat Commands

| Command  | Effect |
|----------|--------|
| `/quit`  | Graceful disconnect, wipe keys + messages, exit |
| `/clear` | Wipe the visible chat display (session continues) |
| `/burn`  | Send self-destruct to both peers; both wipe and exit |
| `/whoami`| Show your alias and peer connection info |
| `/ping`  | Measure round-trip latency to peer |

---

## Security Model

```
Alice                              Bob
  │                                 │
  │── TCP connect ─────────────────►│
  │                                 │
  │◄── X25519 pubkey ───────────────│  (raw 32 bytes, length-framed)
  │── X25519 pubkey ───────────────►│
  │                                 │
  │  Both derive:  ECDH(priv, peer_pub)
  │  Both apply:   HKDF-SHA256(shared_secret, info="ghostchat-v1")
  │  Result:       identical 32-byte AES-256-GCM key
  │                                 │
  │  [Optional passphrase gate]     │
  │◄── salt(16) || challenge(32) ───│
  │── HMAC-SHA256(gate_key, ch) ───►│  (gate_key = Scrypt(passphrase, salt))
  │                                 │
  │◄══ Encrypted JSON messages ════►│  [4B len][12B nonce][ciphertext+GCM tag]
```

### Properties

| Property | Detail |
|----------|--------|
| **Forward secrecy** | Ephemeral X25519 keypair per session — no key reuse |
| **Message integrity** | AES-GCM authentication tag detects tampering |
| **Nonce freshness** | 12 random bytes per message — collision probability negligible |
| **No persistence** | `PYTHONDONTWRITEBYTECODE=1`, no `open()`, no `tempfile` |
| **Key wipe** | `wipe_buf()` overwrites key bytes with zeros before `del` |
| **Passphrase privacy** | Gate key derived via Scrypt; never transmitted |

### Threat model / limitations

- Protects against **passive eavesdroppers** and **network packet capture**.
- Does **not** protect against a compromised OS / kernel (e.g. `/dev/mem` reads,
  swap file, cold-boot attacks). Disable swap for maximum ephemerality.
- The passphrase gate authenticates *knowledge of the passphrase*, but provides
  no defence against a MITM who controls the network before the TCP handshake.
  For MITM protection, verify your peer's IP/port via an out-of-band channel.
- CPython's garbage collector may keep copies of string objects in memory beyond
  the explicit `wipe_buf()` calls. This is a fundamental limitation of managed
  runtimes; the wipe provides best-effort protection, not a cryptographic guarantee.

---

## Building the .deb

### Prerequisites (Debian/Ubuntu)

```bash
sudo apt install devscripts debhelper dh-python python3-all python3-cryptography
```

### Build source package (for Launchpad PPA)

```bash
cd /path/to/ghostchat
debuild -S -sa
# Produces: ../ghostchat_1.0.0.dsc, ../ghostchat_1.0.0.tar.gz, etc.
```

### Build binary package locally

```bash
debuild -b -uc -us
sudo dpkg -i ../ghostchat_1.0.0_all.deb
```

### Submit to Launchpad PPA

```bash
# Sign and upload the source package
dput ppa:<your-launchpad-id>/<ppa-name> ../ghostchat_1.0.0_source.changes
```

---

## Encryption self-test (no socket needed)

Run this one-liner from the `ghostchat/` directory to verify that ECDH key
agreement and AES-256-GCM round-trip correctly:

```bash
cd ghostchat && python3 -c "
from crypto import generate_keypair, derive_shared_key, encrypt_message, decrypt_message
k1, p1 = generate_keypair()
k2, p2 = generate_keypair()
key_a = derive_shared_key(k1, p2)   # Alice's view
key_b = derive_shared_key(k2, p1)   # Bob's view
assert key_a == key_b, 'ECDH key mismatch!'
ct = encrypt_message(key_a, b'hello ghost')
pt = decrypt_message(key_b, ct)
print('OK:', pt.decode())
"
```

Expected output: `OK: hello ghost`

---

## File Structure

```
ghostchat/
├── ghostchat.py   # Entrypoint: argparse, connection setup, orchestration
├── crypto.py      # X25519 ECDH, HKDF, AES-256-GCM, passphrase gate
├── network.py     # TCP host/client, length-framing, RecvThread
├── tui.py         # Curses TUI: split pane, colours, input handling
└── session.py     # In-memory message buffer (deque), wipe on exit

debian/
├── control        # Package metadata and dependencies
├── rules          # debhelper build rules
├── changelog      # Package version history
├── copyright      # MIT licence
├── install        # File installation paths
├── ghostchat.sh   # /usr/bin/ghostchat wrapper script
└── compat         # debhelper compat level (13)
```

---

## Licence

MIT — see [debian/copyright](debian/copyright).

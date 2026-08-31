# P2P Terminal Chat

A peer-to-peer, end-to-end encrypted chat app that runs entirely in your
terminal. No server, no accounts, no cloud — two people run the app on
the same network, exchange a one-time code out of band, and talk with
real E2E encryption the whole way.

```
 ██████╗ ██████╗ ██████╗      ██████╗██╗  ██╗ █████╗ ████████╗
 ██╔══██╗╚════██╗██╔══██╗    ██╔════╝██║  ██║██╔══██╗╚══██╔══╝
 ██████╔╝ █████╔╝██████╔╝    ██║     ███████║███████║   ██║
 ██╔═══╝ ██╔═══╝ ██╔═══╝     ██║     ██╔══██║██╔══██║   ██║
 ██║     ███████╗██║         ╚██████╗██║  ██║██║  ██║   ██║
 ╚═╝     ╚══════╝╚═╝          ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
```

## Features

- **End-to-end encryption** — Curve25519 key exchange + XSalsa20-Poly1305
  authenticated encryption via PyNaCl (libsodium). Keys are ephemeral,
  generated fresh every run; there's no account or long-term identity.
- **Zero-infrastructure discovery** — the host generates a short one-time
  code; the joiner enters it and the app finds the host via a UDP
  broadcast on the LAN, matched by a fingerprint of the code (the raw
  code itself is never sent over the network).
- **No server, ever** — once discovery finds the peer, it's a direct
  TCP socket between the two machines. If broadcast is blocked on your
  network, you can also connect directly with `CODE@ip:port`.
- **Polished terminal UI** — built with [Textual](https://textual.textualize.io/):
  animated fade-in chat bubbles, a live "peer is typing…" indicator, a
  pulsing "encrypted" status bar, and connection spinners.
- **File transfer** — `/sendfile <path>` streams a file to your peer in
  encrypted chunks; received files land in `received_files/`.

## Install

```bash
pip install -r requirements.txt
```

Needs Python 3.10+.

## Run

On each machine:

```bash
python main.py
```

1. One person picks **Host a chat** — they'll be shown a short code
   (e.g. `7F3KQD`) and the app starts listening.
2. They share that code with their peer *any way except through this
   app* — say it out loud, text it, whatever.
3. The other person picks **Join a chat**, types the code in, and the
   app finds the host over the LAN and connects.
4. Chat. Both sides see a green "🔒 Encrypted" status bar and a short
   fingerprint of the other side's key — if you want to be paranoid
   about a LAN attacker swapping keys, read the fingerprint aloud to
   each other and compare.

If UDP broadcast is blocked on your network (some corporate/guest
Wi-Fi does this), the joiner can instead type `CODE@192.168.1.12:51712`
using the host's IP and port shown after they connect.

### In the chat

- Just type and hit enter to send a message.
- `/sendfile /path/to/file` sends a file to your peer.
- `/quit` or `Ctrl+C` exits.

## How it works

```
crypto_utils.py   Curve25519 keypairs, one-time codes, NaCl Box encryption
discovery.py      UDP broadcast discovery, matched by code fingerprint
network.py        Asyncio TCP framing, handshake, encrypted PeerConnection
ui.py             Textual TUI: welcome / host / join / chat screens + animation
main.py           Entry point
```

Nothing is written to disk except files you explicitly `/sendfile` (or
receive), and there's no persistent identity — every run generates a
brand-new keypair, so there's nothing to leak or reuse across sessions.

## Limitations

- Discovery only works on the same broadcast domain (same Wi-Fi/LAN
  segment) — this is by design ("same network"), not a bug. For chat
  across different networks you'd need port forwarding / a relay,
  which is intentionally out of scope for a zero-infrastructure app.
- It's a 1:1 chat — one host, one joiner, no group chat.
- No message persistence — closing the app clears history, as there's
  no server or account to sync it from.

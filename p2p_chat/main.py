#!/usr/bin/env python3
"""
P2P Terminal Chat
==================
A peer-to-peer, end-to-end encrypted chat that runs entirely in your
terminal. No server, no accounts, no cloud -- two people run this app on
the same network, exchange a one-time code out of band, and chat with
NaCl (Curve25519 + XSalsa20-Poly1305) encryption the whole way.

Usage:
    python main.py

Then pick "Host a chat" on one machine and "Join a chat" on the other,
using the code the host is shown.
"""
from ui import run

if __name__ == "__main__":
    run()

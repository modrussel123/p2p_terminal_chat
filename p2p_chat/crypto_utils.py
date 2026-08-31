"""
crypto_utils.py
----------------
End-to-end encryption primitives for P2P Terminal Chat, built on PyNaCl
(libsodium). Uses Curve25519 key exchange (nacl.public.Box) which gives
every message authenticated encryption (XSalsa20-Poly1305) -- so peers get
confidentiality *and* tamper detection for free, with no central server
and no accounts.

Nothing in this file touches the network. It only knows about bytes.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import string

import nacl.public
import nacl.utils
import nacl.exceptions


# --------------------------------------------------------------------------
# Keypairs
# --------------------------------------------------------------------------

def generate_keypair() -> tuple[nacl.public.PrivateKey, nacl.public.PublicKey]:
    """Generate a fresh Curve25519 keypair for this session.

    Keys are ephemeral -- generated fresh every run and never written to
    disk. There is no long-term identity, which is the point: this is a
    one-time, code-based pairing, not an account system.
    """
    private_key = nacl.public.PrivateKey.generate()
    return private_key, private_key.public_key


def pubkey_to_str(pubkey: nacl.public.PublicKey) -> str:
    """Serialize a public key to a URL-safe base64 string for transport."""
    return base64.urlsafe_b64encode(bytes(pubkey)).decode("ascii")


def pubkey_from_str(s: str) -> nacl.public.PublicKey:
    return nacl.public.PublicKey(base64.urlsafe_b64decode(s.encode("ascii")))


def pubkey_short_fingerprint(pubkey: nacl.public.PublicKey) -> str:
    """A short human-checkable fingerprint (like an SSH key fingerprint),
    shown in the UI so both sides can optionally read it aloud / compare
    to guard against a LAN MITM swapping keys."""
    digest = hashlib.sha256(bytes(pubkey)).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 16, 4)).upper()


# --------------------------------------------------------------------------
# One-time pairing codes
# --------------------------------------------------------------------------

_CODE_ALPHABET = "".join(
    c for c in (string.ascii_uppercase + string.digits) if c not in "O0I1"
)


def generate_one_time_code(length: int = 6) -> str:
    """A short, easy-to-read-aloud code the host shares with their peer
    out-of-band (in person, over a phone call, in a Slack DM -- anything
    except this app itself, since there's no server to carry it)."""
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(length))


def code_fingerprint(code: str) -> str:
    """We never send the raw code over the LAN broadcast. Instead we send
    a fingerprint of it, so a passive listener on the network can't just
    read the code out of the discovery packet."""
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()[:20]


# --------------------------------------------------------------------------
# Secure channel
# --------------------------------------------------------------------------

class SecureChannel:
    """Wraps a NaCl Box (Curve25519 + XSalsa20-Poly1305) between exactly
    two peers. Every call to encrypt() uses a fresh random nonce, and
    decrypt() will raise if the ciphertext was tampered with or the nonce
    reused incorrectly -- so authentication is automatic, not an
    afterthought."""

    def __init__(self, my_private_key: nacl.public.PrivateKey,
                 their_public_key: nacl.public.PublicKey):
        self.box = nacl.public.Box(my_private_key, their_public_key)
        self.peer_fingerprint = pubkey_short_fingerprint(their_public_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        return bytes(self.box.encrypt(plaintext, nonce))

    def decrypt(self, ciphertext: bytes) -> bytes:
        try:
            return self.box.decrypt(ciphertext)
        except nacl.exceptions.CryptoError as exc:
            raise ValueError(f"Failed to decrypt/authenticate message: {exc}") from exc

"""
network.py
----------
Asyncio TCP transport for the actual chat session, once two peers have
found each other via discovery.py.

Wire format: every frame is a 4-byte big-endian length prefix followed by
that many bytes of payload. During the handshake the payload is a raw
public key string; after the handshake every payload is NaCl ciphertext
wrapping a small JSON control message (chat text, typing pings, file
chunks, ...).
"""
from __future__ import annotations

import asyncio
import base64
import json
import struct
from typing import Awaitable, Callable, Optional

from crypto_utils import SecureChannel, pubkey_from_str

HEADER_LEN = 4
MAX_FRAME = 32 * 1024 * 1024  # 32MB safety cap


async def send_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(HEADER_LEN)
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME:
        raise ValueError("Frame too large -- possible protocol mismatch")
    return await reader.readexactly(length)


# --------------------------------------------------------------------------
# Handshake: exchange public keys in the clear (they're not secret -- only
# the shared secret they produce is), then build a SecureChannel.
# --------------------------------------------------------------------------

async def _handshake(reader, writer, my_private_key, my_pubkey_str, *, initiator: bool) -> SecureChannel:
    if initiator:
        await send_frame(writer, my_pubkey_str.encode())
        their_pubkey_str = (await read_frame(reader)).decode()
    else:
        their_pubkey_str = (await read_frame(reader)).decode()
        await send_frame(writer, my_pubkey_str.encode())
    return SecureChannel(my_private_key, pubkey_from_str(their_pubkey_str))


async def start_server_and_wait_for_peer(tcp_port: int, my_private_key, my_pubkey_str):
    """Host side: listen on tcp_port, accept exactly one peer, handshake,
    and return (reader, writer, SecureChannel). The listening socket is
    closed as soon as one peer connects -- this is a 1:1 chat, not a
    server."""
    result: dict = {}
    connected = asyncio.Event()

    async def handle(reader, writer):
        if result:
            writer.close()
            return
        secure = await _handshake(reader, writer, my_private_key, my_pubkey_str, initiator=False)
        result.update(reader=reader, writer=writer, secure=secure)
        connected.set()

    server = await asyncio.start_server(handle, "0.0.0.0", tcp_port)
    try:
        await connected.wait()
    finally:
        # NOTE: we deliberately do NOT await server.wait_closed() here.
        # As of Python 3.12, wait_closed() blocks until *all* accepted
        # connections finish -- but we want to keep this one connection
        # open for the chat session itself. close() alone is enough to
        # stop accepting any further peers.
        server.close()
    return result["reader"], result["writer"], result["secure"]


async def connect_to_peer(host_ip: str, tcp_port: int, my_private_key, my_pubkey_str):
    """Joiner side: open a connection to the host and handshake."""
    reader, writer = await asyncio.open_connection(host_ip, tcp_port)
    secure = await _handshake(reader, writer, my_private_key, my_pubkey_str, initiator=True)
    return reader, writer, secure


# --------------------------------------------------------------------------
# Established, encrypted connection
# --------------------------------------------------------------------------

OnMessage = Callable[[dict], Awaitable[None]]


class PeerConnection:
    """An established, authenticated, encrypted connection to the other
    peer. `on_message` is awaited for every decrypted control message,
    including a synthetic {"type": "_disconnected"} when the socket ends."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 secure: SecureChannel, on_message: OnMessage):
        self.reader = reader
        self.writer = writer
        self.secure = secure
        self.on_message = on_message
        self._closed = False

    async def send(self, msg_type: str, **fields) -> None:
        payload = json.dumps({"type": msg_type, **fields}).encode()
        await send_frame(self.writer, self.secure.encrypt(payload))

    async def send_file_start(self, filename: str, size: int, total_chunks: int) -> None:
        await self.send("file_start", filename=filename, size=size, total_chunks=total_chunks)

    async def send_file_chunk(self, index: int, chunk: bytes) -> None:
        await self.send("file_chunk", index=index, data=base64.b64encode(chunk).decode())

    async def send_file_end(self, filename: str) -> None:
        await self.send("file_end", filename=filename)

    async def listen(self) -> None:
        try:
            while not self._closed:
                ciphertext = await read_frame(self.reader)
                plaintext = self.secure.decrypt(ciphertext)
                msg = json.loads(plaintext.decode())
                await self.on_message(msg)
        except (asyncio.IncompleteReadError, ConnectionResetError, ValueError):
            pass
        finally:
            self._closed = True
            await self.on_message({"type": "_disconnected"})

    def close(self) -> None:
        self._closed = True
        try:
            self.writer.close()
        except Exception:
            pass

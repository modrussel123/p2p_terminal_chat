# P2P Terminal Chat

A peer-to-peer, end-to-end encrypted terminal chat app built in Python.
It works without a server, without accounts, and without a cloud service.
Two people run the app on the same local network, exchange a short one-time
code out of band, and chat directly over a secure channel.

## Features

- End-to-end encryption using Curve25519 and NaCl
- Same-network peer discovery via UDP broadcast
- Direct TCP connection after pairing
- Textual terminal user interface
- Encrypted file transfer
- No persistent identity or central server

## How it works

1. One user hosts a chat session.
2. The host generates a short one-time code.
3. The other user joins using that code.
4. The app discovers the host on the local network.
5. A direct encrypted connection is established.
6. Messages and files are sent securely between the two peers.

## Requirements

- Python 3.10+
- pip

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the app

From the project folder:

```bash
python main.py
```

Then choose:
- Host a chat
- Join a chat

## File transfer

Use the chat command:

```text
/sendfile C:\path\to\file.txt
```

Incoming files are saved to the user's Downloads folder when possible, with a
local fallback if needed.

## Current limitations

- This is a 1:1 chat app, not a group chat app.
- Discovery works only on the same LAN / broadcast domain.
- No message history is stored on a server.
- There is no account system or remote relay.

## Project structure

```text
main.py
ui.py
network.py
discovery.py
crypto_utils.py
requirements.txt
README.md
```

## Security note

This app is intended for local, same-network use with ephemeral keys. It does
not provide long-term identity, central storage, or multi-user room logic.

## License

This project is provided as-is for learning and experimentation.

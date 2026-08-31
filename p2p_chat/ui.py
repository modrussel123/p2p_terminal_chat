"""
ui.py
-----
Textual-based terminal UI for P2P Terminal Chat.

Screens
=======
WelcomeScreen  -> choose Host or Join
HostScreen     -> generates a one-time code, waits (animated) for a peer
JoinScreen     -> enter the code, (animated) searches the LAN for the host
ChatScreen     -> the actual encrypted chat, with animated message bubbles,
                  a live typing indicator, and /sendfile support

All networking is async and runs on Textual's own event loop via workers,
so the UI never blocks waiting on a socket.
"""
from __future__ import annotations

import asyncio
import base64
import os
import time
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, LoadingIndicator, Static

import crypto_utils
import discovery
import network

RECEIVED_DIR = Path("received_files")

BANNER = r"""[bold cyan]
 ██████╗ ██████╗ ██████╗      ██████╗██╗  ██╗ █████╗ ████████╗
 ██╔══██╗╚════██╗██╔══██╗    ██╔════╝██║  ██║██╔══██╗╚══██╔══╝
 ██████╔╝ █████╔╝██████╔╝    ██║     ███████║███████║   ██║
 ██╔═══╝ ██╔═══╝ ██╔═══╝     ██║     ██╔══██║██╔══██║   ██║
 ██║     ███████╗██║         ╚██████╗██║  ██║██║  ██║   ██║
 ╚═╝     ╚══════╝╚═╝          ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
[/][dim]  end-to-end encrypted · no server · no accounts · same-LAN P2P[/]
"""


def fade_in(widget: Static, *, y_offset: int = 1, duration: float = 0.28) -> None:
    """Small helper: fade a freshly-mounted widget into place."""
    widget.styles.opacity = 0.0
    widget.styles.animate("opacity", value=1.0, duration=duration)


# ==========================================================================
# Welcome
# ==========================================================================

class WelcomeScreen(Screen):
    BINDINGS = [Binding("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="welcome_container"):
            yield Static(BANNER, id="banner")
            yield Static("Two people. One code. Nothing in between.", id="tagline")
            with Horizontal(id="button_row"):
                yield Button("\u25b8  Host a chat", id="host_btn", variant="primary")
                yield Button("\u25b8  Join a chat", id="join_btn", variant="success")
        yield Footer()

    def on_mount(self) -> None:
        fade_in(self.query_one("#banner", Static), y_offset=-2, duration=0.5)
        fade_in(self.query_one("#tagline", Static), duration=0.5)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "host_btn":
            self.app.push_screen(HostScreen())
        elif event.button.id == "join_btn":
            self.app.push_screen(JoinScreen())


# ==========================================================================
# Host flow
# ==========================================================================

class HostScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]
    status = reactive("Starting up...")

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="setup_container"):
            yield Static("HOST A CHAT", id="setup_title")
            yield Static("", id="code_display")
            yield Static(
                "Share this code with your peer (voice, SMS, anything but this app).\n"
                "They enter it on their machine to connect.",
                id="setup_hint",
            )
            yield LoadingIndicator(id="spinner")
            yield Static(self.status, id="status_line")
        yield Footer()

    def on_mount(self) -> None:
        self.private_key, self.public_key = crypto_utils.generate_keypair()
        self.pubkey_str = crypto_utils.pubkey_to_str(self.public_key)
        self.code = crypto_utils.generate_one_time_code()
        self.fingerprint = crypto_utils.code_fingerprint(self.code)
        self.tcp_port = 51500 + (hash(self.code) % 400)

        code_widget = self.query_one("#code_display", Static)
        spaced = "  ".join(self.code)
        code_widget.update(f"[bold black on cyan]  {spaced}  [/]")
        fade_in(code_widget)

        self.responder = discovery.DiscoveryResponder(self.fingerprint, self.tcp_port, self.pubkey_str)
        self.responder.start()
        self.set_status(f"Waiting for your peer on port {self.tcp_port}...")
        self.wait_for_peer()

    def set_status(self, text: str) -> None:
        self.status = text
        self.query_one("#status_line", Static).update(text)

    @work(exclusive=True, group="host_wait")
    async def wait_for_peer(self) -> None:
        try:
            reader, writer, secure = await network.start_server_and_wait_for_peer(
                self.tcp_port, self.private_key, self.pubkey_str
            )
        except OSError as exc:
            self.set_status(f"[red]Could not open port {self.tcp_port}: {exc}[/]")
            return
        finally:
            self.responder.stop()
        self.set_status("[green]Peer found! Establishing encrypted channel...[/]")
        await asyncio.sleep(0.4)
        self.app.push_screen(ChatScreen(reader, writer, secure, role="host"))


class JoinScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="setup_container"):
            yield Static("JOIN A CHAT", id="setup_title")
            yield Static(
                "Enter the code your host shared with you.\n"
                "[dim]Tip: if LAN broadcast is blocked, use CODE@ip:port instead.[/]",
                id="setup_hint",
            )
            yield Input(placeholder="e.g.  7F3KQD   or   7F3KQD@192.168.1.12:51712", id="code_input")
            yield Button("Connect", id="connect_btn", variant="primary")
            yield LoadingIndicator(id="spinner")
            yield Static("", id="status_line")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#spinner", LoadingIndicator).display = False
        self.query_one("#code_input", Input).focus()

    def set_status(self, text: str) -> None:
        self.query_one("#status_line", Static).update(text)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.try_connect(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "connect_btn":
            self.try_connect(self.query_one("#code_input", Input).value)

    def try_connect(self, raw: str) -> None:
        raw = raw.strip()
        if not raw:
            self.set_status("[red]Enter a code first.[/]")
            return
        self.query_one("#spinner", LoadingIndicator).display = True
        self.query_one("#connect_btn", Button).disabled = True
        if "@" in raw:
            code, addr = raw.split("@", 1)
            host_ip, _, port = addr.partition(":")
            self.connect_manual(code.strip(), host_ip.strip(), int(port))
        else:
            self.connect_via_discovery(raw)

    @work(exclusive=True, group="join_connect")
    async def connect_via_discovery(self, code: str) -> None:
        private_key, public_key = crypto_utils.generate_keypair()
        pubkey_str = crypto_utils.pubkey_to_str(public_key)
        fingerprint = crypto_utils.code_fingerprint(code)

        self.set_status(f"Searching the LAN for code [bold]{code.upper()}[/]...")
        peer = await discovery.discover_peer_async(fingerprint, timeout=25.0, retry_interval=1.0)

        if peer is None:
            self.set_status("[red]No host found. Check the code, or try CODE@ip:port.[/]")
            self.query_one("#spinner", LoadingIndicator).display = False
            self.query_one("#connect_btn", Button).disabled = False
            return

        self.set_status(f"Found host at {peer.host_ip}. Establishing encrypted channel...")
        try:
            reader, writer, secure = await network.connect_to_peer(
                peer.host_ip, peer.tcp_port, private_key, pubkey_str
            )
        except OSError as exc:
            self.set_status(f"[red]Connection failed: {exc}[/]")
            self.query_one("#spinner", LoadingIndicator).display = False
            self.query_one("#connect_btn", Button).disabled = False
            return
        await asyncio.sleep(0.3)
        self.app.push_screen(ChatScreen(reader, writer, secure, role="joiner"))

    @work(exclusive=True, group="join_connect")
    async def connect_manual(self, code: str, host_ip: str, port: int) -> None:
        private_key, public_key = crypto_utils.generate_keypair()
        pubkey_str = crypto_utils.pubkey_to_str(public_key)
        self.set_status(f"Connecting directly to {host_ip}:{port}...")
        try:
            reader, writer, secure = await network.connect_to_peer(host_ip, port, private_key, pubkey_str)
        except OSError as exc:
            self.set_status(f"[red]Connection failed: {exc}[/]")
            self.query_one("#spinner", LoadingIndicator).display = False
            self.query_one("#connect_btn", Button).disabled = False
            return
        await asyncio.sleep(0.3)
        self.app.push_screen(ChatScreen(reader, writer, secure, role="joiner"))


# ==========================================================================
# Chat
# ==========================================================================

class MessageBubble(Static):
    """A single chat line, styled by who sent it, that fades/slides into
    view when mounted."""

    def __init__(self, text: str, css_class: str):
        super().__init__(text)
        self.add_class(css_class)

    def on_mount(self) -> None:
        fade_in(self, y_offset=1, duration=0.22)


class TypingIndicator(Static):
    """Three animated dots shown while the peer is typing."""

    frames = [".", "..", "...", "...."]

    def __init__(self):
        super().__init__("")
        self._frame = 0
        self._timer = None

    def on_mount(self) -> None:
        self.display = False

    def start(self, peer_label: str) -> None:
        self.peer_label = peer_label
        self.display = True
        self._frame = 0
        if self._timer:
            self._timer.stop()
        self._timer = self.set_interval(0.35, self._tick)

    def stop(self) -> None:
        self.display = False
        if self._timer:
            self._timer.stop()
            self._timer = None

    def _tick(self) -> None:
        self._frame = (self._frame + 1) % len(self.frames)
        self.update(f"[dim italic]{self.peer_label} is typing{self.frames[self._frame]}[/]")


class ChatScreen(Screen):
    BINDINGS = [Binding("ctrl+c", "app.quit", "Quit")]

    def __init__(self, reader, writer, secure, role: str):
        super().__init__()
        self.reader = reader
        self.writer = writer
        self.secure = secure
        self.role = role  # "host" or "joiner"
        self.peer_label = "Peer"
        self.connected = True
        self._last_typing_sent = 0.0
        self._peer_typing_timer = None
        self._incoming_files: dict[str, dict] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="chat_root"):
            yield Static(self._status_line(), id="chat_status")
            yield VerticalScroll(id="chat_log")
            yield TypingIndicator()
            with Horizontal(id="input_row"):
                yield Input(placeholder="Type a message · /sendfile <path> · /quit", id="chat_input")
        yield Footer()

    def _status_line(self) -> str:
        fp = self.secure.peer_fingerprint
        return f"[bold green]\U0001F512 Encrypted[/]  ·  peer key [dim]{fp}[/]  ·  role: {self.role}"

    def on_mount(self) -> None:
        self.query_one("#chat_input", Input).focus()
        self.post_system_message("Secure channel established. Say hi!")
        self.pulse_lock()
        self.listen_worker()

    @work(exclusive=True, group="pulse")
    async def pulse_lock(self) -> None:
        # Gentle pulsing highlight on the status bar to signal "live and
        # encrypted", without being distracting.
        status = self.query_one("#chat_status", Static)
        bright = True
        while self.connected:
            await asyncio.sleep(1.6)
            if not self.connected:
                break
            bright = not bright
            style = "bold green" if bright else "green"
            status.update(self._status_line().replace("bold green", style))

    def mount_bubble(self, text: str, css_class: str) -> None:
        log = self.query_one("#chat_log", VerticalScroll)
        log.mount(MessageBubble(text, css_class))
        log.scroll_end(animate=True, duration=0.2)

    def post_system_message(self, text: str) -> None:
        self.mount_bubble(f"[dim]· {text} ·[/]", "system")

    def post_own_message(self, text: str) -> None:
        ts = time.strftime("%H:%M")
        self.mount_bubble(f"[bold cyan]You[/] [dim]{ts}[/]\n{text}", "me")

    def post_peer_message(self, text: str) -> None:
        ts = time.strftime("%H:%M")
        self.mount_bubble(f"[bold magenta]{self.peer_label}[/] [dim]{ts}[/]\n{text}", "peer")

    # -- outgoing -----------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return
        if text == "/quit":
            self.app.exit()
            return
        if text.startswith("/sendfile "):
            path = text[len("/sendfile "):].strip().strip('"')
            self.send_file(path)
            return
        self.post_own_message(text)
        self.send_chat(text)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "chat_input":
            return
        now = time.monotonic()
        if now - self._last_typing_sent > 1.0:
            self._last_typing_sent = now
            self.send_typing_ping()

    @work(exclusive=False, group="chat_send")
    async def send_chat(self, text: str) -> None:
        await self._safe_send("chat", text=text)

    @work(exclusive=False, group="chat_send")
    async def send_typing_ping(self) -> None:
        await self._safe_send("typing")

    async def _safe_send(self, msg_type: str, **fields) -> None:
        if not self.connected:
            return
        try:
            payload = network.json.dumps({"type": msg_type, **fields}).encode()
            ciphertext = self.secure.encrypt(payload)
            await network.send_frame(self.writer, ciphertext)
        except (ConnectionError, OSError):
            self.handle_disconnect()

    @work(exclusive=True, group="file_send")
    async def send_file(self, path: str) -> None:
        p = Path(path).expanduser()
        if not p.is_file():
            self.post_system_message(f"[red]File not found: {path}[/]")
            return
        data = p.read_bytes()
        chunk_size = 48 * 1024
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)] or [b""]
        self.post_system_message(f"Sending {p.name} ({len(data)} bytes, {len(chunks)} chunks)...")
        try:
            payload = network.json.dumps({
                "type": "file_start", "filename": p.name,
                "size": len(data), "total_chunks": len(chunks),
            }).encode()
            await network.send_frame(self.writer, self.secure.encrypt(payload))
            for i, chunk in enumerate(chunks):
                payload = network.json.dumps({
                    "type": "file_chunk", "index": i,
                    "data": base64.b64encode(chunk).decode(),
                }).encode()
                await network.send_frame(self.writer, self.secure.encrypt(payload))
            payload = network.json.dumps({"type": "file_end", "filename": p.name}).encode()
            await network.send_frame(self.writer, self.secure.encrypt(payload))
        except (ConnectionError, OSError):
            self.handle_disconnect()
            return
        self.post_system_message(f"[green]Sent {p.name}.[/]")

    # -- incoming -------------------------------------------------------

    @work(exclusive=True, group="listen")
    async def listen_worker(self) -> None:
        try:
            while self.connected:
                ciphertext = await network.read_frame(self.reader)
                plaintext = self.secure.decrypt(ciphertext)
                msg = network.json.loads(plaintext.decode())
                self.handle_message(msg)
        except (asyncio.IncompleteReadError, ConnectionResetError, ValueError, OSError):
            pass
        finally:
            self.handle_disconnect()

    def handle_message(self, msg: dict) -> None:
        mtype = msg.get("type")
        if mtype == "chat":
            self.query_one(TypingIndicator).stop()
            self.post_peer_message(msg.get("text", ""))
        elif mtype == "typing":
            self.query_one(TypingIndicator).start(self.peer_label)
        elif mtype == "file_start":
            self._incoming_files[msg["filename"]] = {
                "chunks": [None] * msg["total_chunks"],
                "size": msg["size"],
            }
            self.post_system_message(f"Receiving {msg['filename']} ({msg['size']} bytes)...")
        elif mtype == "file_chunk":
            for fname, info in self._incoming_files.items():
                if info["chunks"][msg["index"]] is None:
                    info["chunks"][msg["index"]] = base64.b64decode(msg["data"])
                    break
        elif mtype == "file_end":
            fname = msg["filename"]
            info = self._incoming_files.pop(fname, None)
            if info is None:
                return
            RECEIVED_DIR.mkdir(exist_ok=True)
            out_path = RECEIVED_DIR / fname
            with open(out_path, "wb") as fh:
                for chunk in info["chunks"]:
                    fh.write(chunk or b"")
            self.post_system_message(f"[green]Received {fname} -> {out_path}[/]")

    def handle_disconnect(self) -> None:
        if not self.connected:
            return
        self.connected = False
        self.post_system_message("[red]Peer disconnected. Press ctrl+c to exit.[/]")
        try:
            self.writer.close()
        except Exception:
            pass


# ==========================================================================
# App
# ==========================================================================

class P2PChatApp(App):
    TITLE = "P2P Terminal Chat"
    CSS = """
    Screen {
        align: center middle;
        background: $surface;
    }

    #welcome_container {
        width: auto;
        height: auto;
        align: center middle;
    }
    #banner { content-align: center middle; margin-bottom: 1; }
    #tagline { content-align: center middle; color: $text-muted; margin-bottom: 2; }
    #button_row { align: center middle; height: auto; }
    #button_row Button { margin: 0 2; min-width: 22; }

    #setup_container {
        width: 60%;
        height: auto;
        align: center middle;
        border: round $primary;
        padding: 2 4;
    }
    #setup_title { text-style: bold; content-align: center middle; margin-bottom: 1; }
    #code_display { content-align: center middle; margin: 1 0; text-style: bold; }
    #setup_hint { color: $text-muted; content-align: center middle; margin-bottom: 1; }
    #status_line { content-align: center middle; margin-top: 1; color: $text-muted; }
    #spinner { height: 3; }
    #code_input { margin: 1 0; }
    #connect_btn { width: 100%; }

    #chat_root { width: 100%; height: 100%; }
    #chat_status {
        height: 1;
        padding: 0 2;
        background: $panel;
        content-align: left middle;
    }
    #chat_log {
        height: 1fr;
        padding: 1 2;
        background: $surface;
    }
    MessageBubble {
        width: auto;
        max-width: 80%;
        padding: 0 1;
        margin: 0 0 1 0;
        border: round $primary-lighten-2;
    }
    MessageBubble.me { border: round $success; }
    MessageBubble.peer { border: round $accent; }
    MessageBubble.system {
        border: none;
        color: $text-muted;
        width: 100%;
        content-align: center middle;
    }
    TypingIndicator { height: 1; padding: 0 2; }
    #input_row { height: 3; padding: 0 1; }
    #chat_input { width: 100%; }
    """

    SCREENS = {}

    def on_mount(self) -> None:
        self.push_screen(WelcomeScreen())


def run() -> None:
    P2PChatApp().run()

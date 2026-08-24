"""Relay logic for 'shell-line' mode devices (network-appliance CLIs such as
PAN-OS that only speak an interactive PTY shell, never a bare exec channel).

There is no protocol-level boundary for "one command" in an interactive
shell stream, so we impose one: each newline-terminated chunk the agent
sends is treated as exactly one command. That command is checked against
the allowlist *before* it is ever written to the device's shell channel.
Device output is streamed straight through to the agent unmodified — the
allowlist only gates what runs, not what comes back.
"""
from __future__ import annotations

import threading
import time

from .allowlist import check_command
from .audit import log_command
from .config import DeviceConfig

_TAIL_KEEP = 256
_MAX_LINE_LENGTH = 4096  # bound memory growth if the agent never sends a newline


def _drain_until_idle(channel, idle_seconds: float = 3.0, max_seconds: float = 15.0) -> bytes:
    """Read until the device stops sending for `idle_seconds`, rather than a
    fixed window — a fixed window can cut off mid-response and leak the
    tail of one command's output into the next capture."""
    start = time.time()
    last_data_time = start
    buf = bytearray()
    while True:
        if channel.recv_ready():
            buf.extend(channel.recv(4096))
            last_data_time = time.time()
            continue
        now = time.time()
        if now - last_data_time >= idle_seconds or now - start >= max_seconds:
            break
        time.sleep(0.05)
    return bytes(buf)


def run_init_sequence(device_channel, init_commands: list[str]) -> bytes:
    """Send device-specific setup commands (e.g. disabling a pager) before
    the agent ever gets a byte. Returns the trailing bytes of whatever the
    device showed last, used as a best-effort prompt string."""
    last = _drain_until_idle(device_channel)
    for cmd in init_commands:
        device_channel.sendall(cmd.encode("utf-8") + b"\n")
        last = _drain_until_idle(device_channel)
    return last


class ShellLineSession:
    def __init__(self, agent_channel, device_channel, device_cfg: DeviceConfig, audit_logger, peer: str, username: str, initial_tail: bytes = b""):
        self.agent_channel = agent_channel
        self.device_channel = device_channel
        self.device_cfg = device_cfg
        self.audit_logger = audit_logger
        self.peer = peer
        self.username = username

        self._tail_lock = threading.Lock()
        self._tail = initial_tail[-_TAIL_KEEP:]
        self._stop = threading.Event()

    def _update_tail(self, data: bytes) -> None:
        with self._tail_lock:
            self._tail = (self._tail + data)[-_TAIL_KEEP:]

    def _prompt_guess(self) -> bytes:
        with self._tail_lock:
            tail = self._tail
        idx = tail.rfind(b"\n")
        return tail if idx == -1 else tail[idx + 1:]

    def _device_to_agent_pump(self) -> None:
        while not self._stop.is_set():
            try:
                data = self.device_channel.recv(4096)
            except Exception:
                break
            if not data:
                break
            self._update_tail(data)
            try:
                self.agent_channel.sendall(data)
            except Exception:
                break
        self._stop.set()

    def run(self) -> None:
        # Show the agent a clean prompt instead of the device's raw login banner.
        try:
            self.agent_channel.sendall(self._prompt_guess())
        except Exception:
            pass

        pump_thread = threading.Thread(target=self._device_to_agent_pump, daemon=True)
        pump_thread.start()

        buffer = bytearray()
        try:
            while not self._stop.is_set():
                try:
                    data = self.agent_channel.recv(4096)
                except Exception:
                    break
                if not data:
                    break
                buffer.extend(data)
                while True:
                    idx_n = buffer.find(b"\n")
                    idx_r = buffer.find(b"\r")
                    candidates = [i for i in (idx_n, idx_r) if i != -1]
                    if not candidates:
                        break
                    idx = min(candidates)
                    raw_line = bytes(buffer[:idx])
                    # A lone CR, a lone LF, and a CRLF pair are all "Enter" —
                    # real interactive terminals send CR, scripted clients
                    # typically send LF; treat CRLF as one terminator so a
                    # CRLF-sending client doesn't leave a stray empty line.
                    if buffer[idx:idx + 1] == b"\r" and buffer[idx + 1:idx + 2] == b"\n":
                        del buffer[: idx + 2]
                    else:
                        del buffer[: idx + 1]
                    if raw_line:  # pressing Enter on an empty line is a no-op, not a command
                        self._handle_line(raw_line)
                if len(buffer) > _MAX_LINE_LENGTH:
                    self._reject_overlong_buffer(len(buffer))
                    buffer.clear()
        finally:
            self._stop.set()
            for chan in (self.device_channel, self.agent_channel):
                try:
                    chan.close()
                except Exception:
                    pass
            pump_thread.join(timeout=2)

    def _handle_line(self, raw_line: bytes) -> None:
        line = raw_line.rstrip(b"\r").decode("utf-8", errors="replace")
        # Strip incidental leading/trailing spaces before matching/forwarding.
        # An agent that pastes "show clock " or " show clock" means exactly
        # the allowlisted command; the outer spaces carry no security meaning
        # of their own. This only ever removes literal " " characters at the
        # two ends, so it cannot hide a control/escape byte from
        # is_well_formed() (which still sees it if present) and cannot change
        # whether any guarded metacharacter appears elsewhere in the string --
        # it's a pure usability normalization, not a widening of what matches.
        command = line.strip(" ")
        allowed, reason = check_command(command, self.device_cfg.allow, self.device_cfg.mode)
        log_command(self.audit_logger, self.peer, self.username, command, allowed, reason)

        if allowed:
            try:
                self.device_channel.sendall(command.encode("utf-8") + b"\n")
            except Exception:
                self._stop.set()
            return

        message = (
            raw_line
            + b"\r\n*** blocked by proxy policy: "
            + reason.encode("utf-8", errors="replace")
            + b" ***\r\n"
            + self._prompt_guess()
        )
        try:
            self.agent_channel.sendall(message)
        except Exception:
            self._stop.set()

    def _reject_overlong_buffer(self, buffered_len: int) -> None:
        reason = f"line exceeds maximum length of {_MAX_LINE_LENGTH} bytes without a newline"
        log_command(self.audit_logger, self.peer, self.username, f"<discarded, {buffered_len} bytes>", False, reason)
        message = b"\r\n*** blocked by proxy policy: " + reason.encode() + b" ***\r\n" + self._prompt_guess()
        try:
            self.agent_channel.sendall(message)
        except Exception:
            self._stop.set()


def handle_shell(agent_channel, device_cfg: DeviceConfig, downstream_client, audit_logger, peer: str, username: str, term: str, width: int, height: int) -> None:
    transport = downstream_client.get_transport()
    device_channel = transport.open_session(timeout=device_cfg.connect_timeout)
    device_channel.get_pty(term=term or "vt100", width=width or 200, height=height or 1000)
    device_channel.invoke_shell()

    initial_tail = run_init_sequence(device_channel, device_cfg.init_commands)

    session = ShellLineSession(
        agent_channel=agent_channel,
        device_channel=device_channel,
        device_cfg=device_cfg,
        audit_logger=audit_logger,
        peer=peer,
        username=username,
        initial_tail=initial_tail,
    )
    session.run()

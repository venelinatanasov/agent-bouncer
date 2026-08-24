"""Relay logic for 'shell-line' mode devices (network-appliance CLIs such as
PAN-OS that only speak an interactive PTY shell, never a bare exec channel).

Every byte the agent sends is forwarded to the device live, *except* the
Enter keystroke (CR or LF) — that one is held back until we've checked what
command it would submit. If allowed, the held-back Enter is forwarded so
the command actually runs. If not, the Enter is never forwarded — instead
we send Ctrl+U to clear the device's own pending input line (verified
empirically: it fully erases the line and prevents it from executing) and
tell the agent why.

The pending command is tracked with simple local keystroke shadowing
(append on a printable character, pop on backspace) rather than by parsing
the device's echoed redraws: PAN-OS's redraw conventions turned out to be
inconsistent (a full "\\r" + reprint for some edits, a bare backspace/space/
backspace or an ANSI cursor-move+erase for others), which made anchoring on
raw byte patterns fragile. Local shadowing is deterministic for typing and
backspace. Tab and "?" are the two keys that can change the buffer in ways
local shadowing can't predict (completion, unknown-command handling), so
those two specifically trigger a resync from the device's own echo — and if
that resync can't be confidently parsed, the line is marked *poisoned*
rather than left on stale shadow content, so Enter fails closed instead of
possibly letting the device run something different from what was checked.
Anything the terminal sends that we don't specifically handle (escape
sequences, i.e. arrow keys, and other control bytes) also poisons the line
and is not forwarded at all, rather than risk the device's real buffer
diverging from what we're tracking.
"""
from __future__ import annotations

import threading
import time

from .allowlist import check_command
from .audit import log_command
from .config import DeviceConfig

_TAIL_KEEP = 4096  # bounds memory retained for prompt/resync parsing
_MAX_SHADOW_LEN = 4096  # bounds memory for the locally-tracked pending line
_CANCEL_LINE = b"\x15"  # Ctrl+U: verified against the real device to fully clear
                         # the pending input line and prevent it from executing.
                         # Ctrl+C was tried first and rejected: it did NOT reliably
                         # stop a recognized command from running.
_RESYNC_KEYS = (0x09, 0x3f)  # Tab, '?' -- can change the buffer unpredictably


def _drain_until_idle(channel, idle_seconds: float = 3.0, max_seconds: float = 30.0) -> bytes:
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
        self._last_device_activity = time.time()

        # The prompt text as it looked with nothing typed yet for the
        # in-progress line. Only used to strip the prompt back off when
        # resyncing from the device's echo after Tab/'?'. Re-derived at the
        # start of every line that actually reaches the device, so it
        # tracks a changing prompt correctly (e.g. "admin@PA-VM> " vs
        # "admin@PA-VM# " after entering config mode).
        self._prompt_prefix = initial_tail[-_TAIL_KEEP:]
        self._prompt_locked = False

        # Locally-tracked pending command text, built from keystrokes we
        # know how to interpret deterministically (see module docstring).
        self._shadow: list[str] = []
        self._line_poisoned = False
        self._escape_buf = b""  # non-empty while mid-escape-sequence
        self._just_saw_cr = False

    def _update_tail(self, data: bytes) -> None:
        with self._tail_lock:
            self._tail = (self._tail + data)[-_TAIL_KEEP:]
        self._last_device_activity = time.time()

    def _wait_for_device_quiet(self, idle_seconds: float = 0.3, max_seconds: float = 20.0) -> None:
        """Passive wait only -- never touches device_channel directly, so it
        can't race the pump thread's recv() calls. Used before making a
        security decision (at Enter, after a cancel, and before a Tab/'?'
        resync) so we're not reading a mid-redraw snapshot of the echo."""
        start = time.time()
        while time.time() - start < max_seconds:
            if time.time() - self._last_device_activity >= idle_seconds:
                return
            time.sleep(0.03)

    def _tail_since_last_lf(self) -> bytes:
        with self._tail_lock:
            tail = self._tail
        idx = tail.rfind(b"\n")
        return tail if idx == -1 else tail[idx + 1:]

    def _extract_from_device_echo(self) -> str | None:
        """Best-effort read of the device's own idea of the current line.
        Used only right after Tab/'?', since those can change the buffer
        beyond what local keystroke shadowing predicts. Returns None if it
        can't be confidently parsed -- the caller must treat that as
        untrustworthy and fail closed rather than fall back to stale shadow
        content, since the device's real buffer may have already changed."""
        tail = self._tail_since_last_lf()
        idx = tail.rfind(b"\r")
        frame = tail[idx + 1:] if idx != -1 else tail
        if frame.startswith(b"\x1b[K"):
            frame = frame[3:]
        frame = frame.lstrip(b"\x00")
        if not frame.startswith(self._prompt_prefix):
            return None
        content = frame[len(self._prompt_prefix):]
        return content.decode("utf-8", errors="replace")

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
            self.agent_channel.sendall(self._prompt_prefix)
        except Exception:
            pass

        pump_thread = threading.Thread(target=self._device_to_agent_pump, daemon=True)
        pump_thread.start()

        try:
            while not self._stop.is_set():
                try:
                    data = self.agent_channel.recv(4096)
                except Exception:
                    break
                if not data:
                    break
                for b in data:
                    self._process_byte(b)
        finally:
            self._stop.set()
            for chan in (self.device_channel, self.agent_channel):
                try:
                    chan.close()
                except Exception:
                    pass
            pump_thread.join(timeout=2)

    def _forward(self, ch: bytes) -> None:
        try:
            self.device_channel.sendall(ch)
        except Exception:
            self._stop.set()

    def _process_byte(self, b: int) -> None:
        ch = bytes((b,))

        if self._escape_buf:
            # Consume the whole escape sequence: never forward or shadow any
            # of it, since we don't track cursor position and letting the
            # device act on it (or misreading it as literal characters
            # typed) could desync our shadow from the device's real buffer.
            self._escape_buf += ch
            if len(self._escape_buf) >= 2 and self._escape_buf[1:2] != b"[":
                self._escape_buf = b""
            elif len(self._escape_buf) >= 3 and 0x40 <= b <= 0x7E:
                self._escape_buf = b""
            elif len(self._escape_buf) > 16:
                self._escape_buf = b""
            return

        if ch in (b"\r", b"\n"):
            if self._just_saw_cr and ch == b"\n":
                # second half of a CRLF pair the agent sent for one Enter
                self._just_saw_cr = False
                return
            self._just_saw_cr = ch == b"\r"
            if self._handle_enter():
                # Command actually ran -- the prompt may now be different
                # (e.g. after entering config mode), so re-derive it fresh
                # for the next line.
                self._prompt_locked = False
            self._shadow = []
            self._line_poisoned = False
            return

        self._just_saw_cr = False

        if not self._prompt_locked:
            # First byte of a new line: freeze what the prompt looks like
            # *before* this byte is forwarded, for use if Tab/'?' need a
            # resync later in this line. Use a longer idle threshold than
            # the default: this is waiting for the *previous* command's
            # output to fully finish, and PAN-OS has a real multi-second
            # internal processing pause mid-response -- a short gap here
            # can look like "done" while output is still about to arrive,
            # freezing an empty/wrong prefix that corrupts any later
            # resync on this line.
            self._wait_for_device_quiet(idle_seconds=3.0, max_seconds=30.0)
            self._prompt_prefix = self._tail_since_last_lf()
            self._prompt_locked = True

        if ch in (b"\x7f", b"\x08"):  # backspace/DEL
            if self._shadow:
                self._shadow.pop()
            self._forward(ch)
            return

        if b in _RESYNC_KEYS:  # Tab, '?': device may change the buffer unpredictably
            had_content_before = bool(self._shadow)
            self._forward(ch)
            # '?' can produce a very large help dump; a short idle gap
            # partway through (or just before the final line's trailing
            # reprint) can look like "done" too early. Wait longer here
            # than the default before trusting the echo.
            self._wait_for_device_quiet(idle_seconds=2.0, max_seconds=25.0)
            resynced = self._extract_from_device_echo()
            # A resync that comes back empty right after we had real
            # content is a stronger signal of "settled too early" than
            # "the device actually erased everything" -- neither Tab nor
            # '?' should ever remove prior text. Don't silently accept an
            # answer that implies the buffer changed in a way it shouldn't.
            if resynced is None or (had_content_before and resynced == ""):
                self._line_poisoned = True
            else:
                self._shadow = list(resynced)
            return

        if ch == b"\x1b":
            self._escape_buf = ch
            self._line_poisoned = True
            return

        if 0x20 <= b <= 0x7E:  # other printable ASCII
            if len(self._shadow) >= _MAX_SHADOW_LEN:
                self._line_poisoned = True
            else:
                self._shadow.append(chr(b))
            self._forward(ch)
            return

        # Any other control byte or high-bit byte: don't trust it, don't
        # forward it, fail the line closed at Enter.
        self._line_poisoned = True

    def _handle_enter(self) -> bool:
        """Returns True if a real Enter was forwarded to the device (the
        prompt may now differ and should be re-derived for the next line),
        False if the line was cancelled (the device never saw it, so its
        prompt is unchanged -- don't re-freeze from the cancel's own echo)."""
        if self._line_poisoned:
            command = "".join(self._shadow)
            self._cancel_and_reject(
                "input contained an unsupported control sequence, or a Tab/'?' "
                "completion could not be verified against the device's echo",
                command or "<unknown>",
            )
            return False

        # Outer spaces carry no security meaning.
        command = "".join(self._shadow).strip(" ")
        if command == "":
            # Enter on an empty line is a no-op, not a command attempt --
            # same as a real terminal, this should just move to a fresh line.
            try:
                self.device_channel.sendall(b"\r")
            except Exception:
                self._stop.set()
            return True

        allowed, reason = check_command(command, self.device_cfg.allow, self.device_cfg.mode)
        log_command(self.audit_logger, self.peer, self.username, command, allowed, reason)

        if allowed:
            try:
                self.device_channel.sendall(b"\r")
            except Exception:
                self._stop.set()
            return True

        self._cancel_and_reject(reason, command)
        return False

    def _cancel_and_reject(self, reason: str, command: str) -> None:
        try:
            self.device_channel.sendall(_CANCEL_LINE)
        except Exception:
            self._stop.set()
            return
        self._wait_for_device_quiet()  # let the device's erase-echo reach the agent first
        message = (
            command.encode("utf-8", errors="replace")
            + b"\r\n*** blocked by proxy policy: "
            + reason.encode("utf-8", errors="replace")
            + b" ***\r\n"
            + self._prompt_prefix
        )
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

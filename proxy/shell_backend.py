"""Relay logic for 'shell-line' mode devices (network-appliance CLIs such as
PAN-OS that only speak an interactive PTY shell, never a bare exec channel).

Every byte the agent sends is forwarded to the device live, *except* the
Enter keystroke (CR or LF) — that one is held back until we've checked what
command it would submit. If allowed, the held-back Enter is forwarded so
the command actually runs. If not, the Enter is never forwarded — instead
we send Ctrl+U to clear the device's own pending input line (verified
empirically: it fully erases the line and prevents it from executing) and
tell the agent why.

The pending command is tracked with simple local keystroke shadowing:
append on a printable character, pop on backspace. This is fully
deterministic and needs no information from the device at all.

Tab completion and "?" context help are deliberately NOT supported.
Both can change the device's own buffer in ways local shadowing can't
predict, and the only way to know what they actually did is to wait for
the device to echo back its new state and parse it -- which was tried and
dropped: PAN-OS's redraw conventions are inconsistent enough (a full "\\r"
+ reprint for some edits, a bare backspace/space/backspace or an ANSI
cursor-move+erase for others) to make that fragile, and the device can
have multi-second internal processing pauses that make "has it settled
yet?" a genuine guess. Getting that guess wrong in either direction is bad:
trust stale content and Enter can submit something different from what was
checked, or wait indefinitely and every keystroke gets slower. Rather than
carry that tradeoff, both keys simply poison the current line (Enter will
be refused) without being forwarded, so using them is a clear, instant,
always-consistent "not supported" rather than a sometimes-works guess.

Anything else the terminal sends that isn't plain typing/backspace --
escape sequences (arrow keys, etc.) and other control bytes -- also
poisons the line and is not forwarded, for the same reason: forwarding
something we can't account for risks the device's real buffer diverging
from what's being tracked.
"""
from __future__ import annotations

import threading
import time

from .allowlist import check_command
from .audit import log_command
from .config import DeviceConfig

_TAIL_KEEP = 4096  # bounds memory retained for prompt-string parsing
_MAX_SHADOW_LEN = 4096  # bounds memory for the locally-tracked pending line
_CANCEL_LINE = b"\x15"  # Ctrl+U: verified against the real device to fully clear
                         # the pending input line and prevent it from executing.
                         # Ctrl+C was tried first and rejected: it did NOT reliably
                         # stop a recognized command from running.
_UNSUPPORTED_KEY_REASON = (
    "Tab completion and \"?\" help are not supported through this proxy -- "
    "type the full command and press Enter"
)
_UNSUPPORTED_INPUT_REASON = "input contained an unsupported control sequence or byte"


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

        # The prompt text as it looked with nothing typed yet. Only used
        # cosmetically, to make a rejection message look like a continued
        # session (see _cancel_and_reject) -- re-derived fresh there each
        # time, so it tracks a changing prompt correctly (e.g.
        # "admin@PA-VM> " vs "admin@PA-VM# " after entering config mode)
        # without needing to be maintained on every keystroke.
        self._prompt_prefix = initial_tail[-_TAIL_KEEP:]

        # Locally-tracked pending command text, built from keystrokes we
        # know how to interpret deterministically (see module docstring).
        self._shadow: list[str] = []
        self._poison_reason: str | None = None
        self._escape_buf = b""  # non-empty while mid-escape-sequence
        self._just_saw_cr = False

    def _update_tail(self, data: bytes) -> None:
        with self._tail_lock:
            self._tail = (self._tail + data)[-_TAIL_KEEP:]
        self._last_device_activity = time.time()

    def _wait_for_device_quiet(self, idle_seconds: float = 0.3, max_seconds: float = 20.0) -> None:
        """Passive wait only -- never touches device_channel directly, so it
        can't race the pump thread's recv() calls. Used only when cancelling
        a blocked line, so the device's erase-echo reaches the agent before
        our own rejection message, and so the freshly-read prompt reflects
        the device's actual current state rather than a mid-redraw snapshot."""
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
            if self._escape_buf[1:2] == b"[":
                # CSI: terminates on a byte in the 0x40-0x7E final-byte range.
                if len(self._escape_buf) >= 3 and 0x40 <= b <= 0x7E:
                    self._escape_buf = b""
            else:
                # Non-CSI (e.g. SS3 "ESC O <char>", sent for F1-F4 / cursor
                # keys by terminals in application-cursor-keys mode): the
                # prefix byte is not itself the final byte, so this must
                # consume a third byte too -- ending it after only two bytes
                # would let that real final byte fall through untouched on
                # the next call and be treated (and forwarded/shadowed) as
                # ordinary literal input, which is exactly what this whole
                # branch exists to prevent.
                if len(self._escape_buf) >= 3:
                    self._escape_buf = b""
            if len(self._escape_buf) > 16:
                self._escape_buf = b""
            return

        if ch in (b"\r", b"\n"):
            if self._just_saw_cr and ch == b"\n":
                # second half of a CRLF pair the agent sent for one Enter
                self._just_saw_cr = False
                return
            self._just_saw_cr = ch == b"\r"
            self._handle_enter()
            self._shadow = []
            self._poison_reason = None
            return

        self._just_saw_cr = False

        if ch in (b"\x7f", b"\x08"):  # backspace/DEL
            if self._shadow:
                self._shadow.pop()
            self._forward(ch)
            return

        if b in (0x09, 0x3f):  # Tab, '?': not supported -- see module docstring
            self._poison_reason = _UNSUPPORTED_KEY_REASON
            return  # not forwarded: pressing it visibly does nothing

        if ch == b"\x1b":
            self._escape_buf = ch
            self._poison_reason = _UNSUPPORTED_INPUT_REASON
            return

        if 0x20 <= b <= 0x7E:  # other printable ASCII
            if len(self._shadow) >= _MAX_SHADOW_LEN:
                # Already doomed to be rejected -- stop forwarding too, so a
                # deliberate flood can't keep growing the device's own
                # buffer unbounded once we've detected it.
                self._poison_reason = "command too long"
                return
            self._shadow.append(chr(b))
            self._forward(ch)
            return

        # Any other control byte or high-bit byte: don't trust it, don't
        # forward it, fail the line closed at Enter.
        self._poison_reason = _UNSUPPORTED_INPUT_REASON

    def _handle_enter(self) -> None:
        if self._poison_reason is not None:
            command = "".join(self._shadow)
            self._cancel_and_reject(self._poison_reason, command or "<unknown>")
            return

        # Outer spaces carry no security meaning.
        command = "".join(self._shadow).strip(" ")
        if command == "":
            # Enter on an empty line is a no-op, not a command attempt --
            # same as a real terminal, this should just move to a fresh line.
            try:
                self.device_channel.sendall(b"\r")
            except Exception:
                self._stop.set()
            return

        allowed, reason = check_command(command, self.device_cfg.allow, self.device_cfg.mode)
        log_command(self.audit_logger, self.peer, self.username, command, allowed, reason)

        if allowed:
            try:
                self.device_channel.sendall(b"\r")
            except Exception:
                self._stop.set()
            return

        self._cancel_and_reject(reason, command)

    def _cancel_and_reject(self, reason: str, command: str) -> None:
        try:
            self.device_channel.sendall(_CANCEL_LINE)
        except Exception:
            self._stop.set()
            return
        self._wait_for_device_quiet()  # let the device's erase-echo reach the agent first
        # Re-derive the prompt now rather than relying on a value frozen
        # earlier: it may have changed (e.g. after entering config mode via
        # a legitimately allowed command earlier in the session).
        self._prompt_prefix = self._tail_since_last_lf()
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
    try:
        transport = downstream_client.get_transport()
        if transport is None:
            raise OSError("downstream connection is no longer available")
        device_channel = transport.open_session(timeout=device_cfg.connect_timeout)
        device_channel.get_pty(term=term or "vt100", width=width or 200, height=height or 1000)
        device_channel.invoke_shell()
        initial_tail = run_init_sequence(device_channel, device_cfg.init_commands)
    except Exception as exc:
        try:
            agent_channel.sendall(f"\r\nproxy: failed to start shell on device: {exc}\r\n".encode())
        except Exception:
            pass
        try:
            agent_channel.close()
        except Exception:
            pass
        return

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

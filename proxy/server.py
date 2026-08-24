"""The proxy's SSH server side: one paramiko Transport per agent connection,
one TCP listener per configured device.

Everything not explicitly needed is refused: only 'session' channels, only
password auth, no publickey/gssapi, no SFTP, no X11, no agent/port
forwarding, no global requests. What's allowed inside a session depends on
the device's mode (exec vs shell-line), enforced in check_channel_*_request.
"""
from __future__ import annotations

import os
import socket
import threading
import time

import paramiko

from .audit import get_audit_logger, log_auth
from .config import DeviceConfig
from .exec_backend import handle_exec
from .legacy_kex import enable_for as enable_legacy_kex
from .shell_backend import handle_shell


def _host_key_lookup_name(host: str, port: int) -> str:
    # Matches paramiko.SSHClient's own convention exactly, so files pinned
    # before/without legacy-KEX support (or by a different code path) still
    # load correctly: bracket-notation only kicks in for a non-default port.
    return host if port == 22 else f"[{host}]:{port}"


# paramiko sends the CHANNEL_SUCCESS reply for a channel request (exec/shell)
# on the transport's single reader thread, immediately *after*
# check_channel_*_request returns True -- but that send and the handler thread
# we spawn below both race for the same transport write path. Almost always
# the reply wins (it's a few bytecodes away vs. a fresh OS thread start), but
# under load a freshly-started thread can occasionally write channel
# data/close *before* the reply, which the client sees as a corrupted/closed
# channel (paramiko raises "Channel closed.") instead of getting our clean
# response. This grace period gives the reply an overwhelming head start
# before the worker touches the channel at all. Confirmed reproducible
# without it: rapid back-to-back exec requests for blocked commands (whose
# handling is instant, all in-process, no device I/O) hit this within a
# handful of iterations.
_CHANNEL_REQUEST_ACK_GRACE = 0.1


def _pinned_host_key_path(device_cfg: DeviceConfig) -> str:
    return os.path.join("hostkeys", "downstream", f"{device_cfg.name}.known_host")


def _after_ack(target, args):
    def _run():
        time.sleep(_CHANNEL_REQUEST_ACK_GRACE)
        target(*args)

    return _run


class DeviceServerInterface(paramiko.ServerInterface):
    def __init__(self, device_cfg: DeviceConfig, peer: str):
        super().__init__()
        self.device_cfg = device_cfg
        self.peer = peer
        self.audit_logger = get_audit_logger(device_cfg.name, device_cfg.log_file)
        self.username: str | None = None
        self.downstream_client: paramiko.SSHClient | None = None
        self._pty: tuple[str, int, int] | None = None
        # Every exec/shell handler thread we spawn, so _handle_connection can
        # wait for them before closing downstream_client -- otherwise, if the
        # agent disconnects fast enough after requesting a channel, the close
        # can land before a still-starting (_CHANNEL_REQUEST_ACK_GRACE-
        # delayed) handler ever gets to use it. Only ever appended to from
        # paramiko's own transport thread (one at a time, never concurrent
        # with itself), and only ever read after transport.join() confirms
        # that thread is done, so no lock is needed.
        self._handler_threads: list[threading.Thread] = []

    def _spawn_handler(self, target, args) -> None:
        thread = threading.Thread(target=_after_ack(target, args), daemon=True)
        self._handler_threads.append(thread)
        thread.start()

    # --- auth ---

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        pinned_path = _pinned_host_key_path(self.device_cfg)
        first_trust = not os.path.exists(pinned_path)
        lookup_name = _host_key_lookup_name(self.device_cfg.remote_host, self.device_cfg.remote_port)

        expected_key = None
        if not first_trust:
            # Every subsequent connection must present exactly the pinned key.
            pinned = paramiko.HostKeys(pinned_path)
            entries = pinned.lookup(lookup_name)
            if entries:
                expected_key = next(iter(entries.values()))

        # Built manually (rather than via SSHClient.connect()) because
        # enabling legacy KEX support requires touching this specific
        # Transport's security options before the handshake starts, which
        # SSHClient's connect() doesn't expose a hook for.
        sock = None
        transport = None
        remote_key = None
        try:
            sock = socket.create_connection(
                (self.device_cfg.remote_host, self.device_cfg.remote_port),
                timeout=self.device_cfg.connect_timeout,
            )
            transport = paramiko.Transport(sock)
            transport.banner_timeout = self.device_cfg.connect_timeout
            transport.auth_timeout = self.device_cfg.connect_timeout
            if self.device_cfg.allow_legacy_kex:
                enable_legacy_kex(transport)
            transport.start_client(timeout=self.device_cfg.connect_timeout)

            remote_key = transport.get_remote_server_key()
            if expected_key is not None and (
                remote_key.get_name() != expected_key.get_name()
                or remote_key.asbytes() != expected_key.asbytes()
            ):
                raise paramiko.BadHostKeyException(self.device_cfg.remote_host, remote_key, expected_key)

            transport.auth_password(username, password)
        except paramiko.AuthenticationException as exc:
            log_auth(self.audit_logger, self.peer, username, False, f"downstream rejected credentials: {exc}")
            self._close_quietly(transport, sock)
            return paramiko.AUTH_FAILED
        except paramiko.SSHException as exc:
            # Covers host key mismatches (paramiko.BadHostKeyException is a
            # subclass of this) as well as other protocol-level failures,
            # including "no acceptable kex algorithm" for devices that need
            # allow_legacy_kex and don't have it set.
            log_auth(self.audit_logger, self.peer, username, False, f"downstream host key rejected or protocol error: {exc}")
            self._close_quietly(transport, sock)
            return paramiko.AUTH_FAILED
        except Exception as exc:
            log_auth(self.audit_logger, self.peer, username, False, f"downstream unreachable/error: {exc}")
            self._close_quietly(transport, sock)
            return paramiko.AUTH_FAILED

        if first_trust:
            os.makedirs(os.path.dirname(pinned_path), exist_ok=True)
            pinned = paramiko.HostKeys()
            pinned.add(lookup_name, remote_key.get_name(), remote_key)
            pinned.save(pinned_path)
            self.audit_logger.warning(
                "TRUST ESTABLISHED: pinned host key for device=%s (%s:%d) on first connection -- "
                "verify this out-of-band if you have any doubt, then delete %s to re-pin if it's wrong",
                self.device_cfg.name, self.device_cfg.remote_host, self.device_cfg.remote_port, pinned_path,
            )

        # Wrapped in an SSHClient so the rest of the codebase (exec_backend,
        # shell_backend) keeps working against the same downstream_client
        # API regardless of which path built the underlying transport.
        client = paramiko.SSHClient()
        client._transport = transport

        self.username = username
        self.downstream_client = client
        log_auth(self.audit_logger, self.peer, username, True)
        return paramiko.AUTH_SUCCESSFUL

    @staticmethod
    def _close_quietly(transport, sock) -> None:
        try:
            if transport is not None:
                transport.close()
            elif sock is not None:
                sock.close()
        except Exception:
            pass

    # --- channel setup ---

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        if self.device_cfg.mode != "exec":
            return False
        command_str = command.decode("utf-8", errors="replace")
        self._spawn_handler(
            handle_exec,
            (channel, self.device_cfg, self.downstream_client, command_str, self.audit_logger, self.peer, self.username),
        )
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        if self.device_cfg.mode != "shell-line":
            return False
        term_str = term.decode() if isinstance(term, bytes) else term
        self._pty = (term_str or "vt100", width, height)
        return True

    def check_channel_shell_request(self, channel):
        if self.device_cfg.mode != "shell-line":
            return False
        term, width, height = self._pty or ("vt100", 200, 1000)
        self._spawn_handler(
            handle_shell,
            (channel, self.device_cfg, self.downstream_client, self.audit_logger, self.peer, self.username, term, width, height),
        )
        return True

    # --- everything else: refused ---

    def check_channel_subsystem_request(self, channel, name):
        return False

    def check_channel_x11_request(self, channel, single_connection, auth_protocol, auth_cookie, screen_number):
        return False

    def check_channel_forward_agent_request(self, channel):
        return False

    def check_port_forward_request(self, address, port):
        return False

    def check_global_request(self, kind, msg):
        return False

    def check_channel_env_request(self, channel, name, value):
        return False

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True  # cosmetic; agent's terminal resize doesn't affect enforcement


def _load_or_create_host_key(path: str) -> paramiko.RSAKey:
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(3072)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    key.write_private_key_file(path)
    return key


def _handle_connection(client_sock: socket.socket, addr, device_cfg: DeviceConfig, host_key: paramiko.RSAKey) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    server = DeviceServerInterface(device_cfg, peer)

    try:
        transport.start_server(server=server)
    except Exception:
        transport.close()
        return

    try:
        channel = transport.accept(30)  # keep a live reference: paramiko GC-closes an unreferenced Channel
    except Exception:
        channel = None

    transport.join()
    del channel

    for handler_thread in server._handler_threads:
        handler_thread.join(timeout=30)

    if server.downstream_client is not None:
        try:
            server.downstream_client.close()
        except Exception:
            pass


def serve_device(device_cfg: DeviceConfig, host_key: paramiko.RSAKey) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((device_cfg.listen_host, device_cfg.listen_port))
    sock.listen(100)

    logger = get_audit_logger(device_cfg.name, device_cfg.log_file)
    logger.info(
        "listening device=%s on %s:%d -> %s:%d mode=%s",
        device_cfg.name, device_cfg.listen_host, device_cfg.listen_port,
        device_cfg.remote_host, device_cfg.remote_port, device_cfg.mode,
    )

    while True:
        client_sock, addr = sock.accept()
        threading.Thread(target=_handle_connection, args=(client_sock, addr, device_cfg, host_key), daemon=True).start()


def run(devices: list[DeviceConfig], host_key_path: str = "hostkeys/proxy_host_key") -> None:
    host_key = _load_or_create_host_key(host_key_path)
    threads = []
    for device_cfg in devices:
        t = threading.Thread(target=serve_device, args=(device_cfg, host_key), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

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
from .shell_backend import handle_shell


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

    # --- auth ---

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.device_cfg.remote_host,
                port=self.device_cfg.remote_port,
                username=username,
                password=password,
                timeout=self.device_cfg.connect_timeout,
                banner_timeout=self.device_cfg.connect_timeout,
                auth_timeout=self.device_cfg.connect_timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException as exc:
            log_auth(self.audit_logger, self.peer, username, False, f"downstream rejected credentials: {exc}")
            return paramiko.AUTH_FAILED
        except Exception as exc:
            log_auth(self.audit_logger, self.peer, username, False, f"downstream unreachable/error: {exc}")
            return paramiko.AUTH_FAILED

        self.username = username
        self.downstream_client = client
        log_auth(self.audit_logger, self.peer, username, True)
        return paramiko.AUTH_SUCCESSFUL

    # --- channel setup ---

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        if self.device_cfg.mode != "exec":
            return False
        command_str = command.decode("utf-8", errors="replace")
        threading.Thread(
            target=_after_ack(
                handle_exec,
                (channel, self.device_cfg, self.downstream_client, command_str, self.audit_logger, self.peer, self.username),
            ),
            daemon=True,
        ).start()
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
        threading.Thread(
            target=_after_ack(
                handle_shell,
                (channel, self.device_cfg, self.downstream_client, self.audit_logger, self.peer, self.username, term, width, height),
            ),
            daemon=True,
        ).start()
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

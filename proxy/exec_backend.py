"""Relay logic for 'exec' mode devices (plain Unix/Linux boxes).

Each SSH exec request carries one complete command string. We check it
against the allowlist before ever opening a channel to the real device.
"""
from __future__ import annotations

import threading

from .allowlist import check_command
from .audit import log_command
from .config import DeviceConfig


def _pump(read_call, write_call):
    while True:
        data = read_call(4096)
        if not data:
            return
        write_call(data)


def handle_exec(agent_channel, device_cfg: DeviceConfig, downstream_client, command: str, audit_logger, peer: str, username: str) -> None:
    allowed, reason = check_command(command, device_cfg.allow, device_cfg.mode)
    log_command(audit_logger, peer, username, command, allowed, reason)

    if not allowed:
        try:
            agent_channel.send_stderr(f"blocked by proxy policy: {reason}\n".encode())
            agent_channel.send_exit_status(1)
        finally:
            agent_channel.close()
        return

    try:
        transport = downstream_client.get_transport()
        device_channel = transport.open_session(timeout=device_cfg.connect_timeout)
        device_channel.exec_command(command)
    except Exception as exc:
        try:
            agent_channel.send_stderr(f"proxy: failed to run command on device: {exc}\n".encode())
            agent_channel.send_exit_status(1)
        finally:
            agent_channel.close()
        return

    threads = [
        threading.Thread(target=_pump, args=(device_channel.recv, agent_channel.sendall), daemon=True),
        threading.Thread(target=_pump, args=(device_channel.recv_stderr, agent_channel.sendall_stderr), daemon=True),
        threading.Thread(target=_pump, args=(agent_channel.recv, device_channel.sendall), daemon=True),
    ]
    for t in threads:
        t.start()
    threads[0].join()
    threads[1].join()

    status = device_channel.recv_exit_status()
    try:
        agent_channel.send_exit_status(status)
    finally:
        agent_channel.close()
        device_channel.close()

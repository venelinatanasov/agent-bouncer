"""Config loading for agent-bouncer.

The allowlist is data the human owns. This module only *reads* it; nothing
in the runtime path is able to write back to it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import yaml

VALID_MODES = {"exec", "shell-line"}


@dataclass(frozen=True)
class AllowRule:
    pattern: str
    allow_metachars: bool = False


@dataclass(frozen=True)
class DeviceConfig:
    name: str
    listen_host: str
    listen_port: int
    remote_host: str
    remote_port: int
    mode: str  # "exec" or "shell-line"
    allow: list[AllowRule]
    init_commands: list[str] = field(default_factory=list)
    log_file: str | None = None
    connect_timeout: float = 10.0
    # Off by default: only for devices that genuinely can't speak anything
    # newer (older Cisco IOS is the common case) -- see proxy/legacy_kex.py.
    # Weakens only the proxy's connection to *this* device, nothing else.
    allow_legacy_kex: bool = False


def _parse_allow_entry(entry) -> AllowRule:
    if isinstance(entry, str):
        return AllowRule(pattern=entry)
    if isinstance(entry, dict):
        pattern = entry["pattern"]
        allow_metachars = bool(entry.get("allow_metachars", False))
        return AllowRule(pattern=pattern, allow_metachars=allow_metachars)
    raise ValueError(f"Invalid allow entry: {entry!r}")


def _parse_device(raw: dict) -> DeviceConfig:
    name = raw["name"]
    mode = raw.get("mode", "exec")
    if mode not in VALID_MODES:
        raise ValueError(f"Device {name!r}: invalid mode {mode!r}, must be one of {VALID_MODES}")

    listen = raw["listen"]
    remote = raw["remote"]
    allow_raw = raw.get("allow", [])
    if not allow_raw:
        raise ValueError(f"Device {name!r}: allowlist is empty — refusing to run a device with no allowed commands")

    init_commands = raw.get("init_commands", [])
    if init_commands and mode != "shell-line":
        raise ValueError(f"Device {name!r}: init_commands only valid for mode 'shell-line'")

    return DeviceConfig(
        name=name,
        listen_host=listen.get("host", "127.0.0.1"),
        listen_port=int(listen["port"]),
        remote_host=remote["host"],
        remote_port=int(remote.get("port", 22)),
        mode=mode,
        allow=[_parse_allow_entry(e) for e in allow_raw],
        init_commands=list(init_commands),
        log_file=raw.get("log_file"),
        connect_timeout=float(raw.get("connect_timeout", 10.0)),
        allow_legacy_kex=bool(raw.get("allow_legacy_kex", False)),
    )


def load_config(path: str) -> list[DeviceConfig]:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    devices_raw = raw.get("devices", [])
    if not devices_raw:
        raise ValueError("Config has no devices defined")

    devices = [_parse_device(d) for d in devices_raw]

    seen_ports = set()
    for d in devices:
        key = (d.listen_host, d.listen_port)
        if key in seen_ports:
            raise ValueError(f"Duplicate listen address {key} across devices")
        seen_ports.add(key)

    return devices

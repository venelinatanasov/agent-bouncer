# ssh-proxy-guard

A rudimentary SSH proxy that sits between an AI agent and a real device. It terminates the agent's
SSH session, re-authenticates to the real device with the same credentials, and only forwards
commands that match a human-owned allowlist. SFTP/SCP and port/agent/X11 forwarding are refused
outright, so the only thing an agent can do through the proxy is run an allowlisted command.

Supports two device modes: `exec` for plain Linux/Unix boxes, and `shell-line` for network-appliance
CLIs (Palo Alto PAN-OS and similar) that only speak an interactive PTY shell rather than SSH's
`exec` mechanism.

See [docs/USER_MANUAL.md](docs/USER_MANUAL.md) for configuration, the allowlist format, and how to
use AI to help draft (never edit) an allowlist. Prebuilt Windows executables are on the
[Releases](../../releases) page.

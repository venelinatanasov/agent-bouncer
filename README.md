# agent-bouncer

An SSH proxy that stands between an AI agent and a real device, and only lets through commands
on a list you wrote. Not the agent. Not the AI. You.

AI agents are great at troubleshooting network gear and servers — until one decides `configure`
or `request restart system` is a reasonable next step. agent-bouncer terminates the agent's SSH
session, re-authenticates to the real device with whatever credentials the agent supplied, and
checks every single command against a plain-YAML allowlist before it's ever allowed to reach the
device. Nothing else gets through — no SFTP, no port forwarding, no X11, no agent forwarding, no
way for the agent to talk to the device except by running an allowed command.

```
AI agent  --SSH-->  agent-bouncer  --SSH-->  real device
                     (checks every command
                      against your allowlist,
                      fails closed on anything
                      it isn't sure about)
```

## Why this exists

Giving an agent SSH access to production infrastructure is either "no access" or "full shell,
hope for the best" — there's rarely a middle ground. agent-bouncer is that middle ground: the
agent gets to run real commands against a real device and see real output, but only the commands
you decided are safe, and it can't argue its way past that.

## Features

- **Human-owned allowlist, not AI-editable.** The allowlist is a YAML file the proxy only ever
  reads. Nothing in the runtime path — including the agent it's proxying — can write to it.
- **No credential storage.** Password auth is passed straight through to the real device; nothing
  is cached, logged in the clear, or written to disk. The real device's own account lockout policy
  still applies, exactly as if the agent had connected to it directly.
- **Fail-closed on anything ambiguous.** Unparseable input, control characters, escape sequences,
  and command-smuggling attempts via shell metacharacters are all rejected by default rather than
  guessed at. When in doubt, the proxy says no.
- **Guarded metacharacters.** A broad pattern like `show interface *` can't be used to smuggle a
  second command through (`show interface all; delete config`) — `;`, `&`, backticks, and `$(...)`
  are blocked even inside an otherwise-matching command, unless a specific pattern explicitly opts
  in.
- **Two device modes.** `exec` for plain Linux/Unix boxes that support SSH's one-shot exec
  channel; `shell-line` for network-appliance CLIs (Palo Alto PAN-OS, Cisco IOS, and similar) that
  only speak an interactive PTY shell. shell-line mode tracks the pending command from the agent's
  own keystrokes in real time — it doesn't need or trust the device's echo.
- **No Tab completion, no `?` help, by design.** Both are common ways an interactive CLI leaks
  ambiguity into what's about to run. Neither is forwarded to the device; both cleanly poison and
  reject the current line instead of guessing what was meant.
- **Downstream host-key pinning.** The proxy verifies the real device's identity too, not just its
  own. Trust-on-first-use, pinned to a local file, checked byte-for-byte on every connection after
  that — a swapped device or a MITM attempt gets refused and logged, not silently accepted.
  Optional per-device `allow_legacy_kex` for older gear that only speaks SSH key-exchange
  algorithms modern SSH libraries have dropped.
- **Full audit trail.** Every login attempt and every command — allowed or blocked, including
  poisoned/rejected input — is logged with the peer, the username, and the reason, one log file
  per device.
- **Nothing else works.** SFTP, SCP, X11 forwarding, agent forwarding, and port forwarding are
  refused outright for every device, in every mode. There's no config flag to turn any of it on.

## Installing

**Compiled executable (Windows, no Python needed):** download `agent-bouncer.exe` from the
[Releases](../../releases) page and run it:

```
agent-bouncer.exe --config config\mydevice.yaml
```

**From source:**

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python.exe -m proxy.main --config config\mydevice.yaml
```

## Configuration

One YAML file, one `devices:` entry per device you want to expose — each gets its own listener,
its own allowlist, its own log file:

```yaml
devices:
  - name: my-firewall
    listen:
      host: 127.0.0.1
      port: 2201
    remote:
      host: 203.0.113.120
      port: 22
    mode: shell-line              # "exec" or "shell-line"
    allow:
      - "show system info"        # exact command
      - "show interface *"        # glob
      - "exit"
    log_file: "logs/my-firewall.log"
```

Point your agent's SSH client at `127.0.0.1:2201` with the real device's credentials, and it can
run `show system info` and any `show interface ...` variant — nothing else.

See [docs/USER_MANUAL.md](docs/USER_MANUAL.md) for the full configuration reference, the allowlist
pattern syntax, guarded-metacharacter details, host-key pinning behavior, and how to use AI to
*draft* (never edit) an allowlist for a new device.

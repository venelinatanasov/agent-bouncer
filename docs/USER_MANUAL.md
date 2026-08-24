# ssh-proxy-guard — User Manual

## What this is

ssh-proxy-guard sits between an AI agent and a real device's SSH server. The
agent never talks to the device directly — it talks to this proxy, which
authenticates to the real device with the agent's own credentials and then
only lets through commands that appear on an allowlist you control. Anything
not on the allowlist is refused before it ever reaches the device.

The proxy does not remember passwords, does not cache credentials, and has
no way to modify its own allowlist at runtime. The allowlist is a plain YAML
file. You are the only thing that can change it.

## How it works

```
AI agent  --SSH-->  ssh-proxy-guard  --SSH-->  real device
                     (checks each
                      command against
                      the allowlist)
```

For each command the agent tries to run, the proxy either forwards it
unchanged to the device and relays the real output back, or blocks it and
tells the agent it was refused. The device's own output is never modified or
filtered — only what runs is gated, not what comes back.

## Installing

**Option A — the compiled executable.** Download `ssh-proxy-guard.exe` from
the project's GitHub Releases page. No Python installation needed. Run it
from a terminal:

```
ssh-proxy-guard.exe --config config\mydevice.yaml
```

**Option B — from source.**

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python.exe -m proxy.main --config config\mydevice.yaml
```

**Building the exe yourself**, instead of downloading a release:

```
.venv\Scripts\pip install pyinstaller
.venv\Scripts\python.exe -m PyInstaller --onefile --name ssh-proxy-guard run_proxy.py
```

The result lands in `dist\ssh-proxy-guard.exe`.

## The two device modes

Not every device speaks SSH the same way, and the proxy needs to know which
kind it's talking to.

- **`exec` mode** — for plain Linux/Unix boxes. Each command the agent runs
  arrives as one discrete SSH "exec" request (this is what `ssh host 'cmd'`
  does, and what almost every SSH automation library uses by default). The
  proxy checks the whole command string before ever opening a channel to the
  device.
- **`shell-line` mode** — for network-appliance CLIs (Palo Alto PAN-OS,
  and most router/firewall/switch CLIs behave the same way). These devices
  don't implement the "exec" mechanism at all — they only work over an
  interactive terminal session. The proxy keeps one such session open to the
  device and treats each line the agent sends (up to the next newline) as
  one command, checked before it's written to the device.

Pick wrong and the device simply won't do anything through the proxy — if a
device only supports an interactive CLI over SSH (true of most network
appliances), it must be configured as `shell-line`.

## Configuration file

One YAML file, one `devices:` list. Each entry:

```yaml
devices:
  - name: my-firewall              # used for the log filename and in log lines
    listen:
      host: 127.0.0.1              # where the agent connects
      port: 2201
    remote:
      host: 203.0.113.120           # the real device
      port: 22
    mode: shell-line                # "exec" or "shell-line" — see above
    init_commands:                  # shell-line only: run silently before
      - "set cli pager off"         # the agent gets control (e.g. disabling
                                     # a pager so output doesn't paginate)
    allow:
      - "show system info"          # exact command
      - "show interface *"          # glob — matches any argument after it
      - pattern: "journalctl -u * --no-pager"
        allow_metachars: false      # default; see "Guarded characters" below
    log_file: "logs/my-firewall.log"
```

Run one proxy process pointed at a config with as many devices as you like —
each gets its own listener, its own allowlist, its own log file.

### Allowlist patterns

Patterns are glob-style (`*` matches anything, `?` matches one character),
matched against the exact, complete command text. There is no partial
matching — `show interface *` matches `show interface all` but not
`show interfaces all`.

### Guarded characters

A command can match a wildcard pattern and still be rejected if it contains
a shell metacharacter — `;`, `&`, `` ` ``, `$(...)`, and (in `exec` mode
only) `|`. This exists so that a broad pattern like `show interface *` can't
be used to smuggle a second command through, e.g.
`show interface all; delete config`. If you genuinely need one of these
characters in an allowed command, mark that specific pattern with
`allow_metachars: true` — but do this narrowly, on the one pattern that
needs it, not as a blanket setting.

`|` is treated differently by mode: in `exec` mode it's guarded (on a real
Unix shell it pipes into another process), but in `shell-line` mode it's
allowed by default, because PAN-OS-style CLIs use `|` as a built-in output
filter (`show system info | match hostname`), not a shell pipe.

Anything containing control characters or escape sequences — not just
metacharacters — is rejected outright regardless of the allowlist. This is
a deliberate fail-closed choice: if the proxy can't tell what a command
actually is, it refuses it rather than guessing.

### What's always refused, regardless of config

SFTP/SCP, X11 forwarding, agent forwarding, and local/remote port
forwarding are refused for every device, in every mode. There's no config
option to turn these on — if you need file transfer, that's a deliberately
separate decision outside this tool's scope, not a checkbox here.

## Authentication

The proxy only supports password authentication, and only passes through
whatever the agent supplies — it never stores a password anywhere. When the
agent tries to log in, the proxy immediately attempts that same
username/password against the *real* device. If the real device rejects the
credentials (or is unreachable), the agent's login fails the same way. There
is no separate lockout logic in the proxy — the real device's own account
lockout policy is what governs, exactly as if the agent had connected to it
directly.

## Building the allowlist — using AI to draft it

Writing a good allowlist by hand means knowing the target device's full
command syntax, which is tedious for anything beyond a handful of commands.
A practical way to build one:

1. Give an AI assistant the device's CLI/command reference (vendor docs, a
   `man` page, `--help` output, or just "this is a PAN-OS firewall, generate
   read-only diagnostic commands") and ask it to propose a candidate list of
   glob patterns for the `allow:` section — steering it explicitly toward
   read-only / non-destructive commands for whatever task you have in mind.
2. **Read every line it proposes before it goes in the file.** Check each
   pattern actually matches what you think it matches, and nothing broader.
   A pattern like `show *` is technically "read-only" on many devices but
   is far wider than you probably intended — you want `show interface *`,
   not `show *`.
3. Save the reviewed list into the YAML file yourself.

This is intentionally a one-way street: an AI can help you *draft* the
allowlist, but nothing — AI or otherwise — can edit it once the proxy is
running. The proxy only ever reads this file at startup; there is no code
path anywhere in this tool that writes to it. If you want to change what's
allowed, you edit the YAML file yourself and restart the proxy. Treat
AI-drafted patterns as a first draft from an intern, not as a decision.

## Running it

Point your agent's SSH client at the proxy's listen host/port instead of the
real device, using the same username/password it would normally use against
the real device:

```
ssh -p 2201 admin@127.0.0.1
```

The proxy handles the rest — authenticating downstream, gating commands,
and relaying output.

## Logs

Every device gets its own log file (`log_file` in config, defaulting to
`logs/<device-name>.log`), plus the same lines are echoed to the console the
proxy is running in. Each line records: the peer address, the username,
and either an auth verdict (`AUTH_OK`/`AUTH_FAIL`) or a command verdict
(`ALLOWED`/`BLOCKED`) with the exact command text and the reason. This is
your audit trail — review it periodically, especially the `BLOCKED` lines,
since a pattern of blocked attempts may mean your allowlist is too narrow
for legitimate use, or that something is trying commands it shouldn't.

## Limitations — read this

This is a rudimentary safeguard, not a hardened security boundary:

- It trusts the allowlist you write. A dangerously broad pattern (`show *`,
  or worse, `*`) provides no protection at all.
- `shell-line` mode's "one command per newline" model assumes the agent
  sends complete lines, not live human keystrokes with editing — it does
  not implement a real terminal line-editor. Anything that looks like
  keystroke-level editing is rejected as malformed rather than
  interpreted, which is safe but means this mode isn't meant for a human
  typing interactively through it.
- Command matching operates on plain ASCII/printable text; anything with
  non-printable or non-ASCII bytes is rejected outright rather than
  matched, which is a safe default but can surprise you if a legitimate
  command genuinely needs non-ASCII input.
- The proxy protects against *which commands run*, not what their output
  contains — it does not redact or filter anything a device sends back.

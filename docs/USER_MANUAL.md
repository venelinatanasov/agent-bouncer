# agent-bouncer — User Manual

## What this is

agent-bouncer sits between an AI agent and a real device's SSH server. The
agent never talks to the device directly — it talks to this proxy, which
authenticates to the real device with the agent's own credentials and then
only lets through commands that appear on an allowlist you control. Anything
not on the allowlist is refused before it ever reaches the device.

The proxy does not remember passwords, does not cache credentials, and has
no way to modify its own allowlist at runtime. The allowlist is a plain YAML
file. You are the only thing that can change it.

## How it works

```
AI agent  --SSH-->  agent-bouncer  --SSH-->  real device
                     (checks each
                      command against
                      the allowlist)
```

For each command the agent tries to run, the proxy either forwards it
unchanged to the device and relays the real output back, or blocks it and
tells the agent it was refused. The device's own output is never modified or
filtered — only what runs is gated, not what comes back.

## Installing

**Option A — the compiled executable.** Download `agent-bouncer.exe` from
the project's GitHub Releases page. No Python installation needed. Run it
from a terminal:

```
agent-bouncer.exe --config config\mydevice.yaml
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
.venv\Scripts\python.exe -m PyInstaller --onefile --name agent-bouncer run_proxy.py
```

The result lands in `dist\agent-bouncer.exe`.

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
      - "exit"                      # see note below
    log_file: "logs/my-firewall.log"
```

Run one proxy process pointed at a config with as many devices as you like —
each gets its own listener, its own allowlist, its own log file.

**For `shell-line` devices, consider allowing `exit`.** It's a generic CLI
convention (not specific to any one vendor) that just ends the session —
it doesn't perform any state-changing action. Without it, a well-behaved
agent that wants to leave cleanly has no way to do so and is forced into
an abrupt disconnect instead. It's not a magic fix for anything else —
testing against a real device found no evidence it makes the device clean
up its own session bookkeeping any faster than an abrupt disconnect does
— but giving agents a graceful way to end a session is worth it on its
own.

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

### Downstream host-key pinning

The proxy verifies the real device's identity, not just its own. The first
time it ever connects to a given device, it trusts whatever SSH host key
that device presents and pins it to `hostkeys/downstream/<device-name>.known_host`,
logging a `TRUST ESTABLISHED` line so you notice. Every connection after
that must present exactly that same key — if it doesn't (a swapped device,
a misconfigured IP now pointing somewhere else, or someone actively
intercepting the connection), the login is refused and logged clearly,
exactly like a bad password would be.

If a device's key legitimately changes (e.g. after a reinstall), delete its
pinned file and the next connection will re-establish trust the same way
the first one did. If you want zero exposure even on that very first
connection, verify the device's host key fingerprint out-of-band beforehand
and write the pinned file yourself before ever starting the proxy against
that device — the format is one line, `<remote-host> <key-type> <base64-key>`,
the same as an OpenSSH `known_hosts` entry.

### Legacy devices and `allow_legacy_kex`

Some older network gear — older Cisco IOS is the common case — only offers
key-exchange algorithms (`diffie-hellman-group14-sha1`,
`diffie-hellman-group-exchange-sha1`) that the underlying SSH library has
removed for being SHA-1 based. Connecting to one of these without special
handling fails before authentication is even attempted, with an error like
`Incompatible ssh peer (no acceptable kex algorithm)` — logged as a generic
downstream auth failure, which can look confusingly like a bad password.

If you hit this, add `allow_legacy_kex: true` to that device's entry:

```yaml
    remote:
      host: 203.0.113.2
      port: 22
    allow_legacy_kex: true   # only for devices that genuinely can't speak anything newer
```

This weakens only the proxy's connection to *that one device* — every other
device, and the agent-facing side of the proxy, is unaffected. It's off by
default; only turn it on for a device you've confirmed needs it (the
"Incompatible ssh peer" error above is the tell).

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
and relaying output. For `shell-line` devices this works fine for a human
sitting at a terminal too, not just a scripted agent: you'll see your own
typing, and a blocked command tells you why without killing the session.
Tab completion and `?` help are not supported (see Limitations) — using
either one gets that line refused, on purpose.

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

- **The proxy only protects traffic that actually flows through it.**
  Nothing in this tool stops an agent from connecting *directly* to the real
  device instead, if it can reach that device's SSH port on the network.
  This is the single most important thing to get right operationally: use a
  firewall rule, network segmentation, or an ACL on the device itself to
  ensure the agent's only path to the device is through the proxy. Without
  that, the proxy is a convenience, not a control.
- It trusts the allowlist you write. A dangerously broad pattern (`show *`,
  or worse, `*`) provides no protection at all.
- Host-key pinning (see Authentication above) closes the MITM gap on every
  connection *after* the first, but the very first connection to a device
  is trust-on-first-use — if you need a guarantee on that first connection
  too, pre-seed the pinned key file yourself from an out-of-band-verified
  fingerprint before starting the proxy.
- `shell-line` mode forwards every keystroke to the device live *except*
  Enter — that's the one held back and checked. What's actually pending is
  tracked locally as you type (append on a character, remove on backspace),
  not by reading it back off the device, so this is fast and doesn't depend
  on the device being responsive. A lone CR (a real terminal's Enter), a
  lone LF (what a scripted client typically sends), and CRLF are all
  accepted as "submit this line." If a command is blocked, the device's own
  pending input is cleared (Ctrl+U) before Enter ever reaches it, so it
  never runs — you'll see why, and the session stays usable.
  **Tab completion and `?` help are not supported, on purpose.** Both can
  change the device's buffer in ways local tracking can't predict, and the
  only way to know what they actually did is to wait for the device to
  echo back its new state — which ties correctness to how responsive the
  device happens to be at that moment, and got unreliable on a loaded
  device. Rather than a feature that sometimes silently does the wrong
  thing, pressing Tab or `?` simply does nothing visible and guarantees
  that line gets refused, every time, regardless of what you typed before
  or after. Arrow-key editing and other terminal control sequences beyond
  plain typing/backspace aren't interpreted either, for the same reason —
  a line containing one is rejected rather than guessed at. A single line
  is also capped at 4096 bytes (rejected past that, session stays alive)
  so a runaway or malicious stream can't grow the proxy's memory unbounded.
- Command matching operates on plain ASCII/printable text; anything with
  non-printable or non-ASCII bytes is rejected outright rather than
  matched, which is a safe default but can surprise you if a legitimate
  command genuinely needs non-ASCII input. Incidental leading/trailing
  spaces are trimmed before matching, but nothing else is normalized.
- The proxy protects against *which commands run*, not what their output
  contains — it does not redact or filter anything a device sends back.
- Passwords are never written to disk or logged, but like any process
  handling plaintext credentials in memory, a memory dump of a running
  proxy process could in principle recover a password used in an active
  session. There's no secure-memory handling here — treat the host running
  the proxy with the same care you'd give any machine that briefly holds
  real device credentials.

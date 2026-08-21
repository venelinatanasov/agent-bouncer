# ssh-proxy-guard

A rudimentary SSH proxy that sits between an AI agent and a real device. It terminates the agent's
SSH session, re-authenticates to the real device with the same credentials, and only forwards
`exec` commands that match a human-owned allowlist. PTY/shell sessions, SFTP/SCP, and port/agent/X11
forwarding are refused outright, so the only thing an agent can do through the proxy is run an
allowlisted command.

Design decisions are settled; implementation is in progress.

"""Optional support for SSH key-exchange algorithms paramiko has removed.

paramiko dropped diffie-hellman-group14-sha1 and diffie-hellman-group-
exchange-sha1 outright in a past major version (the implementing classes
are gone, not just deprioritized) because SHA-1 is weaker than the SHA-2
algorithms modern SSH servers use. Plenty of real, still-in-service network
gear -- older Cisco IOS in particular -- only offers these, so connecting
to it with a stock modern paramiko fails with "Incompatible ssh peer (no
acceptable kex algorithm)" before authentication is even attempted.

The DH group-14 math and the group-exchange protocol are completely
independent of which hash function is used for the exchange hash, so this
just re-adds paramiko's own still-present SHA-256 implementations under
the SHA-1 name with the hash swapped -- not a reimplementation of any
cryptographic primitive, just the missing name/hash pairing.

Registering these makes the *implementations* available process-wide, but
that alone changes nothing: paramiko only ever offers what's listed in a
given Transport's preferred/security-option algorithm list, which this
module does not touch. A connection only ends up offering these if code
explicitly opts a specific Transport instance in (see `enable_for`) --
every other connection this proxy makes, including the agent-facing side,
is completely unaffected.
"""
from __future__ import annotations

from hashlib import sha1

import paramiko
from paramiko.kex_gex import KexGexSHA256
from paramiko.kex_group14 import KexGroup14SHA256

LEGACY_KEX_NAMES = ("diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")

_registered = False


class _KexGroup14SHA1(KexGroup14SHA256):
    name = "diffie-hellman-group14-sha1"
    hash_algo = sha1


class _KexGexSHA1(KexGexSHA256):
    name = "diffie-hellman-group-exchange-sha1"
    hash_algo = sha1


def _register() -> None:
    global _registered
    if _registered:
        return
    paramiko.Transport._kex_info[_KexGroup14SHA1.name] = _KexGroup14SHA1
    paramiko.Transport._kex_info[_KexGexSHA1.name] = _KexGexSHA1
    _registered = True


def enable_for(transport: paramiko.Transport) -> None:
    """Let this one Transport instance offer the legacy algorithms, lowest
    priority so a device that also speaks something modern still gets it."""
    _register()
    opts = transport.get_security_options()
    opts.kex = tuple(opts.kex) + LEGACY_KEX_NAMES

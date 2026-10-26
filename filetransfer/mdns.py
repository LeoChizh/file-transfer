"""The .local name this machine is reachable at.

The server has no interest in addresses: it serves one name, that name goes
in the certificate, and the phone resolves it over mDNS. iOS does that
natively, and Avahi (Linux) or Bonjour (macOS, Windows) already answer for
the machine's own hostname, so there is nothing to publish and nothing to
install.
"""
import socket
import threading

RESOLVE_TIMEOUT = 3.0


def default_name(hostname=None):
    """'<this machine's short hostname>.local'."""
    host = (hostname or socket.gethostname()).split(".")[0]
    return f"{host.lower()}.local"


def is_local(ip):
    """True if ip belongs to this machine.

    Binding is the question asked of the kernel directly: an address this
    machine does not hold cannot be bound. It beats listing the interfaces,
    which is what this used to do, and needs no judgement about which of
    them counts.
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        # the wildcard always binds, but is no address of ours to point at
        if ip in ("0.0.0.0", "::"):
            return False
        s.bind((ip, 0))
        return True
    except (OSError, UnicodeError):
        return False
    finally:
        s.close()


def _lookup(name, timeout):
    """Addresses name resolves to, or None. Gives up after timeout seconds:
    an unanswered .local query otherwise stalls startup for several."""
    result = []

    def run():
        try:
            result.append({a[4][0] for a in socket.getaddrinfo(name, None)
                           if a[0] in (socket.AF_INET, socket.AF_INET6)})
        except OSError:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    return result[0] if result else None


def resolves_here(name, timeout=RESOLVE_TIMEOUT):
    """True if every address name resolves to belongs to this machine.

    A name that answers with someone else's address is worse than no name:
    it would hand the phone to a namesake on the same LAN. So one foreign
    answer among our own is enough to refuse it.
    """
    answers = _lookup(name, timeout)
    return bool(answers) and all(is_local(ip) for ip in answers)

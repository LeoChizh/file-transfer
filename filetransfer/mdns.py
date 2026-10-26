"""The .local name this machine is reachable at.

The server has no interest in addresses: it serves one name, that name goes
in the certificate, and the phone resolves it over mDNS. iOS does that
natively, and Avahi (Linux) or Bonjour (macOS, Windows) already answer for
the machine's own hostname, so usually there is nothing to publish and
nothing to install.

Publishing some other name needs the optional `zeroconf` package.
"""
import socket

SERVICE = "_https._tcp.local."


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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


def resolves_here(name):
    """True if name already resolves to this machine.

    A name that answers with someone else's address is worse than no name:
    it would hand the phone to a namesake on the same LAN.
    """
    try:
        answers = {a[4][0] for a in
                   socket.getaddrinfo(name, None, socket.AF_INET)}
    except OSError:
        return False
    return any(is_local(ip) for ip in answers)


def _announce_addresses():
    """Addresses to put in the mDNS record when publishing a name."""
    try:
        info = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        return []
    return [a[4][0] for a in info if not a[4][0].startswith("127.")]


def advertise(name, port):
    """Publish name over mDNS ourselves. Returns a stop callable, or None.

    None means it could not be done: no zeroconf installed, no address to
    announce, or something on the LAN already claims the name.
    """
    try:
        from zeroconf import NonUniqueNameException, ServiceInfo, Zeroconf
    except ImportError:
        return None

    ips = _announce_addresses()
    if not ips:
        return None
    short = name[:-len(".local")] if name.endswith(".local") else name
    info = ServiceInfo(SERVICE, f"{short}.{SERVICE}",
                       addresses=[socket.inet_aton(ip) for ip in ips],
                       port=port, server=f"{name}.")
    try:
        zc = Zeroconf()
    except OSError:
        return None
    try:
        zc.register_service(info, allow_name_change=False)
    except (NonUniqueNameException, OSError):
        zc.close()
        return None
    return zc.close


def ensure_name(name, port, publish=True):
    """Make name usable. Returns (resolved, stop).

    resolved says whether the phone can be expected to find it; stop is a
    callable when we published it ourselves, None otherwise.
    """
    if resolves_here(name):
        return True, None
    if not publish:
        return False, None
    stop = advertise(name, port)
    return bool(stop), stop

"""Serve under a .local name instead of a bare address.

A name is worth more than the best-guessed IP: it survives a new DHCP lease,
a different Wi-Fi and a VPN, so the certificate that carries it never has to
be replaced -- and iOS trusts one certificate at a time, so never replacing
it is the whole game.

Most systems already answer for their own hostname (Avahi on Linux, Bonjour
on macOS and Windows), in which case there is nothing to publish and no
dependency to install. Publishing a different name needs the optional
`zeroconf` package.
"""
import socket

SERVICE = "_https._tcp.local."


def default_name(hostname=None):
    """'<this machine's short hostname>.local'."""
    host = (hostname or socket.gethostname()).split(".")[0]
    return f"{host.lower()}.local"


def resolves_to(name, ips):
    """True if name already answers with one of ips over IPv4."""
    try:
        answers = {a[4][0] for a in
                   socket.getaddrinfo(name, None, socket.AF_INET)}
    except OSError:
        return False
    # it has to point at *us*: a stale cache or a namesake on the same LAN
    # would send the phone to a stranger's machine, which is worse than an IP
    return bool(answers & set(ips))


def advertise(name, port, ip):
    """Publish name over mDNS ourselves. Returns a stop callable, or None.

    None means it could not be done -- no zeroconf installed, or something
    else on the LAN already claims the name.
    """
    try:
        from zeroconf import (NonUniqueNameException, ServiceInfo, Zeroconf)
    except ImportError:
        return None

    short = name[:-len(".local")] if name.endswith(".local") else name
    info = ServiceInfo(SERVICE, f"{short}.{SERVICE}",
                       addresses=[socket.inet_aton(ip)], port=port,
                       server=f"{name}.")
    try:
        zc = Zeroconf(interfaces=[ip])  # the LAN only, never the tunnel
    except OSError:
        return None
    try:
        zc.register_service(info, allow_name_change=False)
    except (NonUniqueNameException, OSError):
        zc.close()
        return None
    return zc.close


def ensure_name(name, port, ip, publish=True):
    """Get a .local name that resolves to ip. Returns (name, stop).

    (None, None) if there is no usable name. stop is None when the system
    was already answering for it and we published nothing.
    """
    if resolves_to(name, [ip]):
        return name, None
    if not publish:
        return None, None
    stop = advertise(name, port, ip)
    return (name, stop) if stop else (None, None)

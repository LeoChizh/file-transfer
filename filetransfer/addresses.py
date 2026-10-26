"""Work out which address of this machine a phone on the LAN should open.

The obvious trick -- connect a UDP socket somewhere and read back the source
address -- reports whatever the routing table prefers, which is the tunnel
address as soon as a VPN is up. So the addresses are read off the interfaces
instead and ranked, and tunnels are kept out of the way.
"""
import ipaddress
import os
import socket
import subprocess


# Interface names that never carry the LAN, by prefix.
VPN_IFACES = ("tun", "tap", "wg", "ppp", "utun", "ipsec", "nordlynx",
              "proton", "tailscale", "zt", "vpn", "gpd", "awdl", "llw")
VIRTUAL_IFACES = ("docker", "br-", "virbr", "vmnet", "vboxnet", "veth",
                  "lxc", "podman", "hyperv", "wsl")
HOST_ENV = "FILE_TRANSFER_HOST"
UNKNOWN = "<this-machine-ip>"   # printed when no address could be found
VPN_PENALTY = 20       # a tunnel address: last resort, and kept out of the SAN
VIRTUAL_PENALTY = 10   # docker and friends: reachable, but rarely the way in
CGNAT = ipaddress.ip_network("100.64.0.0/10")
PRIVATE_TIERS = (
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("10.0.0.0/8"),
)


def _parse_ip_addr(text):
    """Parse `ip -o -4 addr show`: '3: wlan0   inet 192.168.0.10/24 ...'."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and f[2] == "inet":
            out.append((f[1].rstrip(":"), f[3].split("/")[0]))
    return out


def _parse_ifconfig(text):
    """Parse `ifconfig -a` (BSD/macOS, and older Linux 'inet addr:1.2.3.4')."""
    out, iface = [], ""
    for line in text.splitlines():
        if line.strip() and not line[:1].isspace():
            iface = line.split(":")[0].split()[0]
        f = line.split()
        if "inet" in f:
            i = f.index("inet")
            if i + 1 < len(f):
                out.append((iface, f[i + 1].split(":")[-1]))
    return out


def _from_hostname():
    """Every address the resolver knows for this host (used on Windows)."""
    try:
        info = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        return []
    return [("", i[4][0]) for i in info]


def _from_probe():
    """Source address for outbound traffic; no packets are sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return [("", s.getsockname()[0])]
    except OSError:
        return []
    finally:
        s.close()


def _interface_addrs():
    """[(interface, ipv4)] for this machine, interface '' when unknown."""
    if os.name != "nt":
        for cmd, parse in ((["ip", "-o", "-4", "addr", "show"],
                            _parse_ip_addr),
                           (["ifconfig", "-a"], _parse_ifconfig)):
            try:
                done = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=5)
            except (OSError, subprocess.SubprocessError):
                continue
            if done.returncode == 0 and parse(done.stdout):
                return parse(done.stdout)
    return _from_hostname() or _from_probe()


def _rank(iface, ip):
    """Sort key for one candidate, or None if it cannot serve the LAN."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    if (addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_unspecified or addr.is_reserved or addr in CGNAT):
        return None
    tier = next((i for i, net in enumerate(PRIVATE_TIERS) if addr in net),
                len(PRIVATE_TIERS))  # a routable address is the last resort
    name = iface.lower()
    if name.startswith(VPN_IFACES):
        tier += VPN_PENALTY
    elif name.startswith(VIRTUAL_IFACES):
        tier += VIRTUAL_PENALTY
    return (tier, addr.packed)


def _candidates():
    """{ip: sort key} for every address that could serve the LAN."""
    ranked = {}
    for iface, ip in _interface_addrs():
        key = _rank(iface, ip)
        if key and ip not in ranked:
            ranked[ip] = key
    return ranked


def lan_ips(include_tunnels=False, override=None):
    """This machine's usable IPv4 addresses, the most LAN-like one first.

    Tunnel addresses are left out: they come and go with the VPN, and every
    change to this list rewrites the certificate, which means reinstalling it
    on the phone. They are included anyway if nothing else is left, so a
    machine reachable only over the VPN still gets a URL.

    An explicit override -- --host, or $FILE_TRANSFER_HOST -- replaces the
    guess entirely, which is also how a skipped tunnel gets served.
    """
    override = (override or os.environ.get(HOST_ENV, "")).strip()
    if override:
        return [override]
    ranked = _candidates()
    if not include_tunnels:
        stable = {ip: k for ip, k in ranked.items() if k[0] < VPN_PENALTY}
        ranked = stable or ranked
    return sorted(ranked, key=ranked.get)


def tunnel_ips(override=None):
    """Addresses skipped as VPN tunnels, so callers can mention them."""
    if (override or os.environ.get(HOST_ENV, "")).strip():
        return []  # the override is served as given; nothing was skipped
    stable = set(lan_ips())
    return [ip for ip in lan_ips(include_tunnels=True) if ip not in stable]


def lan_ip(override=None):
    """Address an iPhone on the same LAN should open, VPN routes ignored."""
    ips = lan_ips(override=override)
    return ips[0] if ips else UNKNOWN

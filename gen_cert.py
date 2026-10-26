#!/usr/bin/env python3
"""Generate cert.pem / key.pem with a subjectAltName for this machine's IP.

iOS only trusts a certificate for an IP address if the IP is in the SAN.
Usage: python gen_cert.py [--force] [extra-ip-or-hostname ...]

recv.py calls ensure_cert() on startup, which only regenerates when the
cert is missing, expires within 30 days, or lacks one of this machine's
addresses. Set $FILE_TRANSFER_HOST to pin the address by hand.
"""
import datetime
import ipaddress
import os
import socket
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "cert.pem")
KEY = os.path.join(HERE, "key.pem")
RENEW_BEFORE = datetime.timedelta(days=30)


# Interfaces that never carry the LAN: VPN tunnels first, then virtual ones.
# A VPN typically installs a route that beats the default one, so asking the
# kernel which source address it would use for outbound traffic reports the
# tunnel address -- which no phone on the LAN can reach.
VPN_IFACES = ("tun", "tap", "wg", "ppp", "utun", "ipsec", "nordlynx",
              "proton", "tailscale", "zt", "vpn", "gpd", "awdl", "llw")
VIRTUAL_IFACES = ("docker", "br-", "virbr", "vmnet", "vboxnet", "veth",
                  "lxc", "podman", "hyperv", "wsl")
HOST_ENV = "FILE_TRANSFER_HOST"
VPN_PENALTY = 20       # a tunnel address: last resort, and kept out of the SAN
VIRTUAL_PENALTY = 10   # docker and friends: reachable, but rarely the way in
CGNAT = ipaddress.ip_network("100.64.0.0/10")
PRIVATE_TIERS = (
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("10.0.0.0/8"),
)


def _parse_ip_addr(text):
    """Parse `ip -o -4 addr show`: '3: wlan0    inet 192.168.0.10/24 ...'."""
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


def lan_ips(include_tunnels=False):
    """This machine's usable IPv4 addresses, the most LAN-like one first.

    Tunnel addresses are left out: they come and go with the VPN, and every
    change to this list rewrites the certificate, which means reinstalling it
    on the phone. They are included anyway if nothing else is left, so a
    machine reachable only over the VPN still gets a URL.

    $FILE_TRANSFER_HOST overrides the guess when the ranking picks wrong.
    """
    override = os.environ.get(HOST_ENV, "").strip()
    if override:
        return [override]
    ranked = _candidates()
    if not include_tunnels:
        stable = {ip: k for ip, k in ranked.items() if k[0] < VPN_PENALTY}
        ranked = stable or ranked
    return sorted(ranked, key=ranked.get)


def tunnel_ips():
    """Addresses skipped as VPN tunnels, so callers can mention them."""
    stable = set(lan_ips())
    return [ip for ip in lan_ips(include_tunnels=True) if ip not in stable]


def lan_ip():
    """Address an iPhone on the same LAN should open, VPN routes ignored."""
    ips = lan_ips()
    return ips[0] if ips else "<this-machine-ip>"


def _needs_regen(cert_path, key_path, ips):
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        return True
    try:
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except (ValueError, x509.ExtensionNotFound):
        return True
    now = datetime.datetime.now(datetime.timezone.utc)
    if cert.not_valid_after_utc - now < RENEW_BEFORE:
        return True
    have = san.get_values_for_type(x509.IPAddress)
    addrs = []
    for ip in ips:
        try:
            addrs.append(ipaddress.ip_address(ip))
        except ValueError:
            pass  # a hostname, or no usable IP at all
    if not addrs:
        return False  # nothing to check against; keep what we have
    return any(addr not in have for addr in addrs)


def ensure_cert(cert_path=CERT, key_path=KEY, extra=(), force=False):
    """Create the cert/key pair if needed. Returns True if it was (re)made."""
    ips = lan_ips()
    if not force and not _needs_regen(cert_path, key_path, ips):
        return False

    # Every stable address goes in the SAN, so the cert is valid whichever
    # one the phone ends up using. Tunnel addresses are excluded on purpose:
    # see lan_ips().
    names = [*ips, "127.0.0.1", *extra]
    sans = []
    for n in dict.fromkeys(names):
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            if n.startswith("<"):
                continue
            sans.append(x509.DNSName(n))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "filetransfer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    print("[*] generated cert.pem / key.pem for:", ", ".join(map(str, names)),
          flush=True)
    return True


def main():
    args = sys.argv[1:]
    force = "--force" in args
    extra = [a for a in args if a != "--force"]
    if not ensure_cert(extra=extra, force=force):
        print("cert.pem / key.pem are up to date (use --force to replace)")


if __name__ == "__main__":
    main()

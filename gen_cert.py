#!/usr/bin/env python3
"""Generate cert.pem / key.pem with a subjectAltName for this machine's IP.

iOS only trusts a certificate for an IP address if the IP is in the SAN.
Usage: python gen_cert.py [--force] [extra-ip-or-hostname ...]

recv.py calls ensure_cert() on startup, which only regenerates when the
cert is missing, expires within 30 days, or lacks the current LAN IP.
"""
import datetime
import ipaddress
import os
import socket
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "cert.pem")
KEY = os.path.join(HERE, "key.pem")
RENEW_BEFORE = datetime.timedelta(days=30)


def lan_ip():
    """Address of the interface used for outbound traffic (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "<this-machine-ip>"
    finally:
        s.close()


def _needs_regen(cert_path, key_path, ip):
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
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False  # no usable IP detected; keep what we have
    return addr not in san.get_values_for_type(x509.IPAddress)


def ensure_cert(cert_path=CERT, key_path=KEY, extra=(), force=False):
    """Create the cert/key pair if needed. Returns True if it was (re)made."""
    ip = lan_ip()
    if not force and not _needs_regen(cert_path, key_path, ip):
        return False

    names = [ip, "127.0.0.1", *extra]
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

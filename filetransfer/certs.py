"""Generate cert.pem / key.pem with a subjectAltName for this machine.

iOS only trusts a certificate for an IP address if the IP is in the SAN, and
it trusts one specific certificate, so a new one means reinstalling it on the
phone. Hence ensure_cert() replaces as little as it can get away with.

Usage: python -m filetransfer.certs [--force] [extra-ip-or-hostname ...]
"""
import argparse
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .addresses import lan_ips

CERT = "cert.pem"
KEY = "key.pem"
RENEW_BEFORE = datetime.timedelta(days=30)


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


def ensure_cert(cert_path=CERT, key_path=KEY, extra=(), force=False,
                ips=None):
    """Create the cert/key pair if needed. Returns True if it was (re)made.

    ips defaults to the addresses this machine would serve; the caller passes
    its own when it has already resolved them (--host, say).
    """
    ips = list(ips) if ips is not None else lan_ips()
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
                continue  # the "no address found" placeholder
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
    print(f"[*] generated {cert_path} / {key_path} for:",
          ", ".join(map(str, names)), flush=True)
    return True


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="python -m filetransfer.certs",
        description="Create cert.pem / key.pem for this machine.")
    p.add_argument("extra", nargs="*", metavar="NAME",
                   help="extra IP or hostname to put in the SAN")
    p.add_argument("--force", action="store_true",
                   help="replace a certificate that is still valid")
    p.add_argument("--cert", default=CERT)
    p.add_argument("--key", default=KEY)
    args = p.parse_args(argv)
    if not ensure_cert(args.cert, args.key, extra=args.extra,
                       force=args.force):
        print(f"{args.cert} / {args.key} are up to date"
              " (use --force to replace)")


if __name__ == "__main__":
    main()

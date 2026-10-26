"""A local certificate authority, and a server certificate signed by it.

iOS is strict about TLS server certificates, and silently so: since iOS 13
one without an extendedKeyUsage of id-kp-serverAuth is refused even after
the profile is installed and fully trusted. It also wants the name in the
subjectAltName, never the common name, and a lifetime under 398 days.

So there are two certificates, the way mkcert does it:

  ca.pem    the authority. This is the one installed on the phone, and it
            never changes, which is the point -- trust it once and every
            certificate below it is trusted too. It is named after the
            machine and the day it was made, so it can be recognised in the
            phone's trust settings.
  cert.pem  the server certificate, signed by the CA. Regenerated whenever
            the names change, which costs the phone nothing.
"""
import datetime
import ipaddress
import os
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CERT = "ca.pem"
CA_KEY = "ca-key.pem"
CERT = "cert.pem"
KEY = "key.pem"
CA_YEARS = 10
LEAF_DAYS = 397          # Apple rejects server certificates valid for more
RENEW_BEFORE = datetime.timedelta(days=30)
DAY = datetime.timedelta(days=1)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def ca_name(hostname=None, when=None):
    """What the authority is called in the phone's trust settings.

    The machine and the day it was made, because that list shows the common
    name and nothing else: several machines, or one machine's old authority
    still sitting there, are otherwise impossible to tell apart.
    """
    day = (when or _now()).strftime("%Y-%m-%d")
    suffix = f" file-transfer CA {day}"
    host = (hostname or socket.gethostname()).split(".")[0]
    # the common name holds 64 characters; the date is worth more than the
    # tail of a long hostname, so that is what gives way
    return host[:64 - len(suffix)] + suffix


def _write(path, data, private=False):
    """Write the file, keeping a private key unreadable by anyone else."""
    if private:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    else:
        with open(path, "wb") as fh:
            fh.write(data)


def _key_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def _load(cert_path, key_path):
    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    with open(key_path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    return cert, key


def _expiring(cert):
    return cert.not_valid_after_utc - _now() < RENEW_BEFORE


def ensure_ca(ca_cert=CA_CERT, ca_key=CA_KEY):
    """Create the authority if needed. Returns True if it was (re)made.

    True means the phone has to install the new ca.pem; that is the only
    thing in here the phone ever cares about, so it should stay False for
    years at a time.
    """
    if os.path.exists(ca_cert) and os.path.exists(ca_key):
        try:
            cert, _ = _load(ca_cert, ca_key)
            if not _expiring(cert):
                return False
        except (ValueError, TypeError):
            pass  # unreadable: make a new one

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _now()
    common_name = ca_name(when=now)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "file-transfer"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - DAY)
        .not_valid_after(now + datetime.timedelta(days=365 * CA_YEARS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(
            key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write(ca_key, _key_bytes(key), private=True)
    _write(ca_cert, cert.public_bytes(serialization.Encoding.PEM))
    print(f'[*] generated {ca_cert} as "{common_name}":'
          " install this one on the phone", flush=True)
    return True


def _sans(names):
    """SAN entries for a mix of addresses and hostnames."""
    out = []
    for n in dict.fromkeys(names):
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))
    return out


def _covers(cert, names):
    """True if the certificate's SAN already covers everything in names."""
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    return set(_sans(names)) <= set(san)


def _needs_regen(cert_path, key_path, names):
    """True if the server certificate has to be rebuilt."""
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        return True
    try:
        cert, _ = _load(cert_path, key_path)
    except (ValueError, TypeError):
        return True
    return _expiring(cert) or not _covers(cert, names)


def ensure_cert(cert_path=CERT, key_path=KEY, names=(),
                ca_cert=CA_CERT, ca_key=CA_KEY):
    """Make sure a CA and a server certificate exist. Returns (ca, leaf).

    Both are booleans saying whether that file was (re)made. Only a new ca
    needs anything from the phone.

    names are the .local (or other) names to serve under; loopback is
    always included so the machine can reach itself. Re-signing the leaf is
    cheap, the CA being what the phone trusts, so this never has to leave
    anything out.
    """
    new_ca = ensure_ca(ca_cert, ca_key)
    wanted = [*names, "127.0.0.1", "localhost"]
    if not (new_ca or _needs_regen(cert_path, key_path, names)):
        return new_ca, False

    ca, ca_signing_key = _load(ca_cert, ca_key)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "file-transfer")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - DAY)
        .not_valid_after(now + datetime.timedelta(days=LEAF_DAYS))
        .add_extension(x509.SubjectAlternativeName(_sans(wanted)),
                       critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        # iOS 13 and later reject a server certificate without this
        .add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(
            key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier
                       .from_issuer_public_key(ca.public_key()),
                       critical=False)
        .sign(ca_signing_key, hashes.SHA256())
    )
    _write(key_path, _key_bytes(key), private=True)
    _write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    print(f"[*] signed {cert_path} for:",
          ", ".join(str(n) for n in dict.fromkeys(wanted)), flush=True)
    return new_ca, True

"""Command line: find the name, fit the certificate to it, serve."""
import argparse
import errno
import os
import sys

from . import mdns
from .certs import CA_CERT, CERT, KEY, ensure_cert
from .server import DEFAULT_PORT, make_server
from .tokens import new_token


def print_qr(url, out=None):
    """Draw url as a QR code in the terminal. Returns False if unavailable."""
    try:
        import qrcode
    except ImportError:
        return False
    out = out or sys.stdout
    qr = qrcode.QRCode(border=2)
    qr.add_data(url)
    qr.make()
    try:
        qr.print_ascii(out=out, invert=True)  # half-block characters
    except UnicodeEncodeError:  # legacy Windows code page
        return False
    return True


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="file-transfer",
        description="Drop files onto this machine from a phone on the LAN.")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"port to listen on (default {DEFAULT_PORT})")
    p.add_argument("--dir", dest="upload_dir", default="uploads",
                   metavar="PATH", help="where files land (default ./uploads)")
    return p.parse_args(argv)


def announce(url, upload_dir, out=None, ca_url=None, unresolved=None):
    """Print the QR code, the URL, and what the phone needs once."""
    out = out or sys.stdout
    lines = [f"[*] {url}"]
    if ca_url:
        lines.append(f"[*] first time on this phone? install {ca_url}")
    if unresolved:
        lines.append(f"[!] nothing answers for {unresolved} here, so the"
                     " phone probably cannot reach it either: check that Bonjour"
                     " (Windows) or Avahi (Linux) is running")
    lines.append(f"[*] saving into {upload_dir}")

    print_qr(url, out=out)
    # the URL is the first thing anyone waits for, so do not leave it sitting
    # in a pipe buffer when stdout is not a terminal
    print("\n".join(lines), file=out, flush=True)


def main(argv=None):
    args = parse_args(argv)
    upload_dir = os.path.abspath(args.upload_dir)
    os.makedirs(upload_dir, exist_ok=True)

    name = mdns.default_name()
    resolved = mdns.resolves_here(name)

    # The phone trusts the authority, not this certificate, so the
    # certificate can be re-signed for a new name as often as needed.
    new_ca, _ = ensure_cert(names=[name])
    if new_ca:
        print(f"[!] new authority {CA_CERT}: the phone has to trust this"
              " one (once)", flush=True)

    token = new_token()
    try:
        httpd = make_server(upload_dir, token, port=args.port,
                            cert=CERT, key=KEY, ca_cert=CA_CERT)
    except OSError as e:
        if e.errno != errno.EADDRINUSE:
            raise
        print(f"[!] port {args.port} is already in use;"
              " stop the other server or pass --port", flush=True)
        return 1

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    url = f"https://{name}:{args.port}/{token}/"
    announce(url, upload_dir, ca_url=url + "ca.pem",
             unresolved=None if resolved else name)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    sys.exit(main() or 0)

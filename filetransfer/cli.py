"""Command line: find the name, fit the certificate to it, serve."""
import argparse
import errno
import os
import sys

from . import mdns
from .certs import CA_CERT, CA_KEY, CERT, KEY, ensure_cert
from .server import DEFAULT_PORT, make_server
from .tokens import TOKEN_FILE, new_token, write_token


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
    p.add_argument("--name", metavar="NAME",
                   help="the name to serve under, default this machine's"
                        " .local name; publishing one the network does not"
                        " already answer for needs the mdns extra")
    p.add_argument("--no-publish", dest="publish", action="store_false",
                   help="never try to publish the name, only use it if"
                        " something already answers for it")
    p.add_argument("--cert", default=CERT, metavar="PATH")
    p.add_argument("--key", default=KEY, metavar="PATH")
    p.add_argument("--ca", default=CA_CERT, metavar="PATH",
                   help="the local authority the phone trusts")
    p.add_argument("--ca-key", dest="ca_key", default=CA_KEY, metavar="PATH")
    p.add_argument("--token-file", dest="token_file", default=TOKEN_FILE,
                   metavar="PATH", help="where to write the current secret")
    return p.parse_args(argv)


def announce(url, upload_dir, out=None, ca_url=None, unresolved=None):
    """Print the QR code, the URL, and what the phone needs once."""
    out = out or sys.stdout
    lines = [f"[*] {url}"]
    if ca_url:
        lines.append(f"[*] first time on this phone? install {ca_url}")
    if unresolved:
        lines.append(f"[!] nothing answers for {unresolved} here, so the"
                     " phone probably cannot reach it either: install the"
                     " mdns extra to publish it, or pass --name")
    lines.append(f"[*] saving into {upload_dir}")

    print_qr(url, out=out)
    # the URL is the first thing anyone waits for, so do not leave it sitting
    # in a pipe buffer when stdout is not a terminal
    print("\n".join(lines), file=out, flush=True)


def main(argv=None):
    args = parse_args(argv)
    upload_dir = os.path.abspath(args.upload_dir)
    os.makedirs(upload_dir, exist_ok=True)

    name = args.name or mdns.default_name()
    resolved, stop_mdns = mdns.ensure_name(name, args.port,
                                           publish=args.publish)

    # The phone trusts the authority, not this certificate, so the
    # certificate can be re-signed for a new name as often as needed.
    new_ca, _ = ensure_cert(args.cert, args.key, names=[name],
                            ca_cert=args.ca, ca_key=args.ca_key)
    if new_ca:
        print(f"[!] new authority {args.ca}: the phone has to trust this"
              " one (once)", flush=True)

    token = new_token()
    write_token(args.token_file, token)
    try:
        httpd = make_server(upload_dir, token, port=args.port,
                            cert=args.cert, key=args.key, ca_cert=args.ca)
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
        if stop_mdns:
            stop_mdns()


if __name__ == "__main__":
    sys.exit(main() or 0)

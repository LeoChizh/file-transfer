"""Command line: work out the URL, make sure the cert fits it, serve."""
import argparse
import os
import sys

from . import mdns
from .addresses import HOST_ENV, UNKNOWN, lan_ips, tunnel_ips
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
    p.add_argument("--host", metavar="ADDRESS",
                   help="address to put in the URL and the certificate,"
                        " instead of guessing it; a skipped VPN tunnel"
                        f" is served this way (or set ${HOST_ENV})")
    p.add_argument("--cert", default=CERT, metavar="PATH")
    p.add_argument("--key", default=KEY, metavar="PATH")
    p.add_argument("--ca", default=CA_CERT, metavar="PATH",
                   help="the local authority the phone trusts")
    p.add_argument("--ca-key", dest="ca_key", default=CA_KEY,
                   metavar="PATH")
    p.add_argument("--token-file", dest="token_file", default=TOKEN_FILE,
                   metavar="PATH", help="where to write the current secret")
    p.add_argument("--name", metavar="NAME",
                   help="serve as NAME.local instead of this machine's"
                        " hostname; needs the mdns extra to publish one")
    p.add_argument("--no-mdns", dest="mdns", action="store_false",
                   help="ignore .local names and use addresses")
    return p.parse_args(argv)


def announce(urls, skipped, upload_dir, out=None, host_hint=False,
             ca_url=None):
    """Print the QR code, the URLs, and what the phone needs once.

    host_hint is for when several *addresses* were found and the first may
    be the wrong one; a .local name ahead of one address is not that case.
    """
    out = out or sys.stdout
    lines = [f"[*] {urls[0]}"]
    lines += [f"[*] or {url}" for url in urls[1:]]
    if ca_url:
        lines.append(f"[*] first time on this phone? install {ca_url}")
    if host_hint:
        lines.append(f"[*] wrong one first? set {HOST_ENV}=<ip>")
    if skipped:
        lines.append(f"[*] not serving tunnel {', '.join(skipped)}"
                     f" (no phone on the LAN can reach it; --host or"
                     f" ${HOST_ENV} overrides)")
    lines.append(f"[*] saving into {upload_dir}")

    print_qr(urls[0], out=out)
    # the URL is the first thing anyone waits for, so do not leave it sitting
    # in a pipe buffer when stdout is not a terminal
    print("\n".join(lines), file=out, flush=True)


def resolve_name(args, ip):
    """The .local name to serve under, and how to stop advertising it."""
    if not args.mdns or ip == UNKNOWN:
        return None, None
    return mdns.ensure_name(args.name or mdns.default_name(), args.port, ip)


def main(argv=None):
    args = parse_args(argv)
    upload_dir = os.path.abspath(args.upload_dir)
    os.makedirs(upload_dir, exist_ok=True)

    ips = lan_ips(override=args.host) or [UNKNOWN]
    name, stop_mdns = resolve_name(args, ips[0])

    # The phone trusts the authority, not this certificate, so the
    # certificate can carry every name and address and be re-signed as
    # often as they change.
    new_ca, _ = ensure_cert(args.cert, args.key, ips=ips,
                            extra=[name] if name else [],
                            ca_cert=args.ca, ca_key=args.ca_key)
    if new_ca:
        print(f"[!] new authority {args.ca}: the phone has to trust this"
              " one (once)", flush=True)

    token = new_token()
    write_token(args.token_file, token)
    httpd = make_server(upload_dir, token, port=args.port,
                        cert=args.cert, key=args.key, ca_cert=args.ca)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    hosts = ([name] if name else []) + ips
    urls = [f"https://{h}:{args.port}/{token}/" for h in hosts]
    announce(urls, tunnel_ips(override=args.host), upload_dir,
             host_hint=len(ips) > 1, ca_url=urls[0] + "ca.pem")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye")
    finally:
        httpd.server_close()
        if stop_mdns:
            stop_mdns()


if __name__ == "__main__":
    main()

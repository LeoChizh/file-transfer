"""Command line: work out the URL, make sure the cert fits it, serve."""
import argparse
import os
import sys

from .addresses import HOST_ENV, UNKNOWN, lan_ips, tunnel_ips
from .certs import CERT, KEY, ensure_cert
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
    p.add_argument("--token-file", dest="token_file", default=TOKEN_FILE,
                   metavar="PATH", help="where to write the current secret")
    return p.parse_args(argv)


def announce(urls, skipped, upload_dir, out=None):
    """Print the QR code, the URLs, and what was deliberately left out."""
    out = out or sys.stdout
    lines = [f"[*] {urls[0]}"]
    lines += [f"[*] or {url}" for url in urls[1:]]
    if len(urls) > 1:
        lines.append(f"[*] wrong one first? set {HOST_ENV}=<ip>")
    if skipped:
        lines.append(f"[*] not serving tunnel {', '.join(skipped)}"
                     f" (keeps the cert stable; {HOST_ENV} overrides)")
    lines.append(f"[*] saving into {upload_dir}")

    print_qr(urls[0], out=out)
    # the URL is the first thing anyone waits for, so do not leave it sitting
    # in a pipe buffer when stdout is not a terminal
    print("\n".join(lines), file=out, flush=True)


def main(argv=None):
    args = parse_args(argv)
    upload_dir = os.path.abspath(args.upload_dir)
    os.makedirs(upload_dir, exist_ok=True)

    ips = lan_ips(override=args.host) or [UNKNOWN]
    if ensure_cert(args.cert, args.key, ips=ips):
        print("[!] new certificate: reinstall/trust it on the iPhone",
              flush=True)

    token = new_token()
    write_token(args.token_file, token)
    httpd = make_server(upload_dir, token, port=args.port,
                        cert=args.cert, key=args.key)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    announce([f"https://{ip}:{args.port}/{token}/" for ip in ips],
             tunnel_ips(override=args.host), upload_dir)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

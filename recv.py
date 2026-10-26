#!/usr/bin/env python3
import hmac
import html
import os
import secrets
import ssl
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from gen_cert import ensure_cert, lan_ip
from multipart import parse_form_data

HERE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(HERE, "uploads")
CERT = os.path.join(HERE, "cert.pem")
KEY = os.path.join(HERE, "key.pem")
TOKEN_FILE = os.path.join(HERE, "token.txt")
PORT = 8443

os.makedirs(UPLOAD_DIR, exist_ok=True)


def load_token():
    """Shared secret that prefixes every URL. Created on first run."""
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as fh:
            token = fh.read().strip()
        if token:
            return token
    token = secrets.token_urlsafe(16)
    with open(TOKEN_FILE, "w") as fh:
        fh.write(token + "\n")
    return token


TOKEN = load_token()

FORM_HTML = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Upload</title>
<style>
  body{font-family:-apple-system,sans-serif;margin:2em;max-width:32em}
  button{padding:.6em 1.2em;font-size:1em}
  li{margin:.2em 0}
</style></head>
<body>
<h2>Send files</h2>
<form method="POST" action="upload" enctype="multipart/form-data">
  <input type="file" name="file" multiple required><br><br>
  <button type="submit">Upload</button>
</form>
<hr>
<h3>Files</h3>
<ul>__LISTING__</ul>
</body></html>"""


def unique_path(name):
    """Atomically reserve UPLOAD_DIR/name, adding ' (n)' if it is taken."""
    stem, ext = os.path.splitext(name)
    candidate, n = name, 0
    while True:
        path = os.path.join(UPLOAD_DIR, candidate)
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            return candidate, path
        except FileExistsError:
            n += 1
            candidate = f"{stem} ({n}){ext}"


def clean_name(raw):
    # browsers (and old IE) may send either separator, whatever the server OS
    name = raw.replace("\\", "/").split("/")[-1]
    name = "".join(c for c in name if c >= " " and c not in '<>:"|?*')
    name = name.strip(" .")
    return name or "upload"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=UPLOAD_DIR, **kwargs)

    def _route(self):
        """Return the path below /<token>/, or None if the token is wrong."""
        path = urllib.parse.urlsplit(self.path).path
        parts = path.split("/", 2)  # ['', token, rest]
        if len(parts) < 2 or not hmac.compare_digest(
                parts[1].encode(), TOKEN.encode()):
            return None
        return "/" + (parts[2] if len(parts) > 2 else "")

    def do_POST(self):
        inner = self._route()
        if inner != "/upload":
            self.send_error(404)
            return
        try:
            environ = {
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
                "wsgi.input": self.rfile,
            }
            forms, files = parse_form_data(environ)

            uploads = [f for f in files.getall("file")
                       if getattr(f, "filename", None)]
            if not uploads:
                self.send_error(400, "no file field")
                return

            for f in uploads:
                name, dest = unique_path(clean_name(f.filename))
                f.save_as(dest)
                print(f"[+] saved {name}", flush=True)

            self.send_response(303)
            self.send_header("Location", "./")
            self.end_headers()
        except Exception as e:
            print(f"[!] error: {e!r}", flush=True)
            self.send_error(500, "upload failed")

    def do_GET(self):
        self._serve(head=False)

    def do_HEAD(self):
        self._serve(head=True)

    def _serve(self, head):
        inner = self._route()
        if inner is None:
            self.send_error(404)
            return
        if inner == "/":
            if not urllib.parse.urlsplit(self.path).path.endswith("/"):
                self.send_response(301)  # relative links need the slash
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return
            files = sorted(os.listdir(UPLOAD_DIR))
            files = [f for f in files if f != ".gitkeep"]
            if files:
                listing = "".join(
                    f'<li><a href="{urllib.parse.quote(f)}">'
                    f'{html.escape(f)}</a></li>' for f in files
                )
            else:
                listing = "<li><em>empty</em></li>"
            body = FORM_HTML.replace("__LISTING__", listing).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head:
                self.wfile.write(body)
        else:
            self.path = inner  # parent class resolves it inside UPLOAD_DIR
            if head:
                super().do_HEAD()
            else:
                super().do_GET()


def main():
    if ensure_cert(CERT, KEY):
        print("[!] new certificate: reinstall/trust it on the iPhone",
              flush=True)

    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"[*] https://{lan_ip()}:{PORT}/{TOKEN}/")
    print(f"[*] saving into {UPLOAD_DIR}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye")


if __name__ == "__main__":
    main()

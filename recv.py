#!/usr/bin/env python3
import os
import ssl
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler

from multipart import parse_form_data

HERE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(HERE, "uploads")
CERT = os.path.join(HERE, "cert.pem")
KEY = os.path.join(HERE, "key.pem")
PORT = 8443

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.chdir(UPLOAD_DIR)  # serve + save in uploads/

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
<h2>Send a file</h2>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file" required><br><br>
  <button type="submit">Upload</button>
</form>
<hr>
<h3>Files</h3>
<ul>__LISTING__</ul>
</body></html>"""

class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/upload":
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

            if "file" not in files:
                self.send_error(400, "no file field")
                return

            item = files["file"]
            items = item if isinstance(item, list) else [item]

            for f in items:
                if not getattr(f, "filename", None):
                    continue
                name = os.path.basename(f.filename)
                dest = os.path.join(UPLOAD_DIR, name)
                f.save_as(dest)
                print(f"[+] saved {name}", flush=True)

            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        except Exception as e:
            print(f"[!] error: {e}", flush=True)
            self.send_error(500, str(e))

    def do_GET(self):
        if self.path == "/":
            files = sorted(os.listdir(UPLOAD_DIR))
            if files:
                listing = "".join(
                    f'<li><a href="/{f}">{f}</a></li>' for f in files
                )
            else:
                listing = "<li><em>empty</em></li>"
            html = FORM_HTML.replace("__LISTING__", listing).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
        else:
            super().do_GET()


def main():
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        sys.exit(f"missing cert/key. generate with:\n"
                 f"  openssl req -x509 -newkey rsa:2048 -nodes "
                 f"-keyout key.pem -out cert.pem -days 365 "
                 f"-subj '/CN=filetransfer'")

    httpd = HTTPServer(("0.0.0.0", PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    try:
        ips = os.popen("hostname -I").read().split()
    except Exception:
        ips = []
    ip = ips[0] if ips else "<linux-ip>"

    print(f"[*] https://{ip}:{PORT}/")
    print(f"[*] saving into {UPLOAD_DIR}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye")


if __name__ == "__main__":
    main()

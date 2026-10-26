"""The HTTPS server: one token-gated upload form, one listing, one folder."""
import functools
import hmac
import os
import ssl
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from multipart import parse_form_data

from . import page
from .names import clean_name, unique_path

DEFAULT_PORT = 8443
HIDDEN = {".gitkeep"}


class Handler(SimpleHTTPRequestHandler):
    """Serves one upload folder below /<token>/.

    upload_dir and token arrive as arguments rather than module state, so a
    test can run a server without patching anything. Build one with
    make_handler(); the attributes must be set before the base class runs,
    because it handles the whole request inside __init__.
    """

    def __init__(self, *args, upload_dir, token, **kwargs):
        self.upload_dir = upload_dir
        self.token = token
        super().__init__(*args, directory=upload_dir, **kwargs)

    def _route(self):
        """Return the path below /<token>/, or None if the token is wrong."""
        path = urllib.parse.urlsplit(self.path).path
        parts = path.split("/", 2)  # ['', token, rest]
        if len(parts) < 2 or not hmac.compare_digest(
                parts[1].encode(), self.token.encode()):
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
                name, dest = unique_path(self.upload_dir,
                                         clean_name(f.filename))
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
        if inner != "/":
            self.path = inner  # the base class resolves it inside upload_dir
            if head:
                super().do_HEAD()
            else:
                super().do_GET()
            return
        if not urllib.parse.urlsplit(self.path).path.endswith("/"):
            self.send_response(301)  # relative links need the slash
            self.send_header("Location", self.path + "/")
            self.end_headers()
            return
        names = [f for f in sorted(os.listdir(self.upload_dir))
                 if f not in HIDDEN]
        body = page.render(names)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)


def make_handler(upload_dir, token):
    """A handler class bound to this folder and secret."""
    return functools.partial(Handler, upload_dir=upload_dir, token=token)


def make_server(upload_dir, token, port=DEFAULT_PORT, cert=None, key=None,
                host="0.0.0.0"):
    """A server listening on every interface, wrapped in TLS if a cert given.

    The caller owns serve_forever(), so a test can drive it in a thread.
    """
    httpd = ThreadingHTTPServer((host, port), make_handler(upload_dir, token))
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd

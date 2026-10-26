import http.client
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

import recv

TOKEN = "testtoken"


def multipart(files):
    """files: [(filename, bytes)] -> (content_type, body)"""
    b = "XXboundaryXX"
    parts = []
    for name, data in files:
        parts.append(
            f'--{b}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="{name}"\r\nContent-Type: application/octet-stream'
            f"\r\n\r\n".encode() + data + b"\r\n")
    parts.append(f"--{b}--\r\n".encode())
    return f"multipart/form-data; boundary={b}", b"".join(parts)


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        for p in (mock.patch.object(recv, "UPLOAD_DIR", self.tmp.name),
                  mock.patch.object(recv, "TOKEN", TOKEN)):
            p.start()
            self.addCleanup(p.stop)
        quiet = mock.patch.object(recv.Handler, "log_message")
        quiet.start()
        self.addCleanup(quiet.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), recv.Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def req(self, method, path, files=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers, body = {}, None
        if files is not None:
            ctype, body = multipart(files)
            headers["Content-Type"] = ctype
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, r.getheader("Location"), data

    def upload(self, *files):
        return self.req("POST", f"/{TOKEN}/upload", files=list(files))

    def saved(self):
        return sorted(os.listdir(self.tmp.name))

    def test_wrong_or_missing_token_is_404(self):
        for path in ("/", "/nope/", "/nope/x.txt", f"/{TOKEN}x/"):
            self.assertEqual(self.req("GET", path)[0], 404, path)
        status = self.req("POST", "/upload", files=[("a", b"x")])[0]
        self.assertEqual(status, 404)
        self.assertEqual(self.saved(), [])

    def test_missing_trailing_slash_redirects(self):
        status, loc, _ = self.req("GET", f"/{TOKEN}")
        self.assertEqual((status, loc), (301, f"/{TOKEN}/"))

    def test_upload_and_download(self):
        status, loc, _ = self.upload(("a.txt", b"hello"))
        self.assertEqual((status, loc), (303, "./"))
        self.assertEqual(self.req("GET", f"/{TOKEN}/a.txt")[2], b"hello")

    def test_multiple_files(self):
        self.upload(("a.txt", b"1"), ("b.txt", b"2"))
        self.assertEqual(self.saved(), ["a.txt", "b.txt"])

    def test_duplicate_name_not_overwritten(self):
        self.upload(("IMG_0001.jpg", b"one"))
        self.upload(("IMG_0001.jpg", b"two"))
        self.assertEqual(self.saved(), ["IMG_0001 (1).jpg", "IMG_0001.jpg"])
        with open(os.path.join(self.tmp.name, "IMG_0001.jpg"), "rb") as fh:
            self.assertEqual(fh.read(), b"one")

    def test_path_traversal_is_flattened(self):
        self.upload(("../../evil.txt", b"x"), ("..\\..\\evil2.txt", b"x"))
        self.assertEqual(self.saved(), ["evil.txt", "evil2.txt"])

    def test_listing_escapes_html(self):
        self.upload(('"><script>alert(1)</script>.txt', b"x"))
        page = self.req("GET", f"/{TOKEN}/")[2].decode()
        self.assertNotIn("<script>", page)

    def test_listing_escapes_special_chars(self):
        with open(os.path.join(self.tmp.name, "a&b 'x'.txt"), "w") as fh:
            fh.write("x")
        page = self.req("GET", f"/{TOKEN}/")[2].decode()
        self.assertIn("a&amp;b &#x27;x&#x27;.txt", page)
        self.assertIn('href="a%26b%20%27x%27.txt"', page)

    def test_no_file_is_400(self):
        self.assertEqual(
            self.req("POST", f"/{TOKEN}/upload", files=[])[0], 400)

    def test_error_does_not_leak_details(self):
        with mock.patch.object(recv, "unique_path",
                               side_effect=RuntimeError("SECRET-PATH")):
            status, _, body = self.upload(("a.txt", b"x"))
        self.assertEqual(status, 500)
        self.assertNotIn(b"SECRET-PATH", body)


class CleanNameTest(unittest.TestCase):
    def test_cases(self):
        c = recv.clean_name
        self.assertEqual(c("a/b/c.txt"), "c.txt")
        self.assertEqual(c("C:\\x\\y.txt"), "y.txt")
        self.assertEqual(c("a:b?.txt"), "ab.txt")
        self.assertEqual(c(".."), "upload")
        self.assertEqual(c("name. "), "name")


class QrTest(unittest.TestCase):
    def test_qr_printed(self):
        import io
        buf = io.StringIO()
        self.assertTrue(recv.print_qr("https://1.2.3.4:8443/tok/", out=buf))
        self.assertGreater(len(buf.getvalue().splitlines()), 10)

    def test_qr_skipped_without_library(self):
        with mock.patch.dict("sys.modules", {"qrcode": None}):
            self.assertFalse(recv.print_qr("https://x/"))


class TokenTest(unittest.TestCase):
    def test_token_is_random_per_process(self):
        import subprocess
        import sys
        code = "import recv; print(recv.TOKEN)"
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out = {subprocess.run([sys.executable, "-c", code], cwd=root,
                              capture_output=True, text=True).stdout.strip()
               for _ in range(2)}
        self.assertEqual(len(out), 2)
        self.assertTrue(all(len(t) >= 16 for t in out))

    def test_write_token_overwrites_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "token.txt")
            with mock.patch.object(recv, "TOKEN_FILE", path):
                recv.write_token("one")
                recv.write_token("two")
            with open(path) as fh:
                self.assertEqual(fh.read().strip(), "two")


if __name__ == "__main__":
    unittest.main()

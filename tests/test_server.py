import http.client
import os
import socket
import tempfile
import threading
import unittest
from unittest import mock

from filetransfer import names, page, server

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
        quiet = mock.patch.object(server.Handler, "log_message")
        quiet.start()
        self.addCleanup(quiet.stop)
        # the folder and the secret are arguments, so there is no module
        # state to patch here
        self.ca = os.path.join(self.tmp.name, "..", "ca-for-test.pem")
        self.ca = os.path.abspath(self.ca)
        with open(self.ca, "wb") as fh:
            fh.write(b"-----BEGIN CERTIFICATE-----\nnot-a-real-ca\n")
        self.addCleanup(os.remove, self.ca)
        self.httpd = server.make_server(self.tmp.name, TOKEN, port=0,
                                        host="127.0.0.1", ca_cert=self.ca)
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

    def test_head_on_the_form_has_no_body(self):
        status, _, body = self.req("HEAD", f"/{TOKEN}/")
        self.assertEqual((status, body), (200, b""))

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

    def test_gitkeep_is_hidden_from_the_listing(self):
        open(os.path.join(self.tmp.name, ".gitkeep"), "w").close()
        page = self.req("GET", f"/{TOKEN}/")[2].decode()
        self.assertNotIn(".gitkeep", page)
        self.assertIn("<em>empty</em>", page)

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
        with mock.patch.object(server, "unique_path",
                               side_effect=RuntimeError("SECRET-PATH")):
            status, _, body = self.upload(("a.txt", b"x"))
        self.assertEqual(status, 500)
        self.assertNotIn(b"SECRET-PATH", body)

    def test_two_servers_do_not_share_a_token_or_folder(self):
        """State lives on the handler, so a second server is independent."""
        with tempfile.TemporaryDirectory() as other_dir:
            other = server.make_server(other_dir, "othertoken", port=0,
                                       host="127.0.0.1")
            port = other.server_address[1]
            threading.Thread(target=other.serve_forever,
                             daemon=True).start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port,
                                                  timeout=5)
                conn.request("GET", f"/{TOKEN}/")  # this server's token
                self.assertEqual(conn.getresponse().status, 404)
                conn.close()
                self.upload(("mine.txt", b"x"))
                self.assertEqual(os.listdir(other_dir), [])
            finally:
                other.shutdown()
                other.server_close()


class CaDownloadTest(unittest.TestCase):
    """The phone installs the authority from the page it is already on."""

    def setUp(self):
        quiet = mock.patch.object(server.Handler, "log_message")
        quiet.start()
        self.addCleanup(quiet.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def serve(self, ca_cert):
        httpd = server.make_server(self.tmp.name, TOKEN, port=0,
                                   host="127.0.0.1", ca_cert=ca_cert)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return port

    def get(self, port, path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", path)
        r = conn.getresponse()
        out = (r.status, r.getheader("Content-Type"), r.read())
        conn.close()
        return out

    def test_served_with_the_type_ios_needs(self):
        ca = os.path.join(self.tmp.name, "ca.pem")
        with open(ca, "wb") as fh:
            fh.write(b"PEMDATA")
        port = self.serve(ca)
        status, ctype, body = self.get(port, f"/{TOKEN}/ca.pem")
        self.assertEqual((status, body), (200, b"PEMDATA"))
        self.assertEqual(ctype, server.CA_TYPE)

    def test_needs_the_token_like_everything_else(self):
        ca = os.path.join(self.tmp.name, "ca.pem")
        with open(ca, "wb") as fh:
            fh.write(b"PEMDATA")
        port = self.serve(ca)
        self.assertEqual(self.get(port, "/nope/ca.pem")[0], 404)

    def test_missing_file_is_404_not_a_crash(self):
        port = self.serve(os.path.join(self.tmp.name, "gone.pem"))
        self.assertEqual(self.get(port, f"/{TOKEN}/ca.pem")[0], 404)

    def test_not_offered_when_there_is_no_ca(self):
        port = self.serve(None)
        self.assertEqual(self.get(port, f"/{TOKEN}/ca.pem")[0], 404)
        page_body = self.get(port, f"/{TOKEN}/")[2]
        self.assertNotIn(b'href="ca.pem"', page_body)


class PageTest(unittest.TestCase):
    def test_install_link_only_when_a_ca_is_served(self):
        self.assertIn(b'href="ca.pem"', page.render([], ca=True))
        self.assertNotIn(b'href="ca.pem"', page.render([], ca=False))

    def test_listing_is_rendered_either_way(self):
        for ca in (True, False):
            self.assertIn(b"a.txt", page.render(["a.txt"], ca=ca))
            self.assertNotIn(b"__CA__", page.render(["a.txt"], ca=ca))


class DualStackTest(unittest.TestCase):
    """A .local name can resolve to a link-local AAAA, so serve both."""

    def setUp(self):
        quiet = mock.patch.object(server.Handler, "log_message")
        quiet.start()
        self.addCleanup(quiet.stop)

    def test_one_socket_answers_ipv4_and_ipv6(self):
        with tempfile.TemporaryDirectory() as d:
            httpd = server.make_server(d, TOKEN, port=0)   # host=None
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                for host in ("127.0.0.1", "::1"):
                    conn = http.client.HTTPConnection(host, port, timeout=5)
                    conn.request("GET", f"/{TOKEN}/")
                    self.assertEqual(conn.getresponse().status, 200, host)
                    conn.close()
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_falls_back_to_ipv4_without_ipv6(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(server, "DualStackServer",
                                   side_effect=OSError("no IPv6")):
                httpd = server.make_server(d, TOKEN, port=0)
            try:
                self.assertEqual(httpd.socket.family, socket.AF_INET)
            finally:
                httpd.server_close()


class UniquePathTest(unittest.TestCase):
    def test_suffixes_until_free(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(names.unique_path(d, "a.txt")[0], "a.txt")
            self.assertEqual(names.unique_path(d, "a.txt")[0], "a (1).txt")
            self.assertEqual(names.unique_path(d, "a.txt")[0], "a (2).txt")


class CleanNameTest(unittest.TestCase):
    def test_cases(self):
        c = names.clean_name
        self.assertEqual(c("a/b/c.txt"), "c.txt")
        self.assertEqual(c("C:\\x\\y.txt"), "y.txt")
        self.assertEqual(c("a:b?.txt"), "ab.txt")
        self.assertEqual(c(".."), "upload")
        self.assertEqual(c("name. "), "name")


if __name__ == "__main__":
    unittest.main()

import io
import os
import tempfile
import unittest
from unittest import mock

from filetransfer import cli, tokens
from filetransfer.server import DEFAULT_PORT


class ParseArgsTest(unittest.TestCase):
    def test_defaults(self):
        args = cli.parse_args([])
        self.assertEqual(args.port, DEFAULT_PORT)
        self.assertEqual(args.upload_dir, "uploads")
        self.assertIsNone(args.host)

    def test_overrides(self):
        args = cli.parse_args(["--port", "9000", "--dir", "/tmp/drop",
                               "--host", "192.168.1.9"])
        self.assertEqual((args.port, args.upload_dir, args.host),
                         (9000, "/tmp/drop", "192.168.1.9"))


class AnnounceTest(unittest.TestCase):
    def say(self, urls, skipped=()):
        buf = io.StringIO()
        cli.announce(urls, list(skipped), "/tmp/uploads", out=buf)
        return buf.getvalue()

    def test_single_url_is_bare(self):
        out = self.say(["https://192.168.0.10:8443/tok/"])
        self.assertIn("[*] https://192.168.0.10:8443/tok/", out)
        self.assertNotIn(" or ", out)
        self.assertNotIn("wrong one first", out)
        self.assertIn("[*] saving into /tmp/uploads", out)

    def test_extra_urls_and_hint(self):
        out = self.say(["https://a/", "https://b/"])
        self.assertIn("[*] or https://b/", out)
        self.assertIn("wrong one first", out)

    def test_skipped_tunnel_is_explained(self):
        out = self.say(["https://a/"], skipped=["10.99.0.2"])
        self.assertIn("not serving tunnel 10.99.0.2", out)
        self.assertIn(cli.HOST_ENV, out)

    def test_qr_code_is_drawn_above_the_url(self):
        out = self.say(["https://192.168.0.10:8443/tok/"])
        self.assertGreater(len(out.splitlines()), 10)


class QrTest(unittest.TestCase):
    def test_qr_printed(self):
        buf = io.StringIO()
        self.assertTrue(cli.print_qr("https://1.2.3.4:8443/tok/", out=buf))
        self.assertGreater(len(buf.getvalue().splitlines()), 10)

    def test_qr_skipped_without_library(self):
        with mock.patch.dict("sys.modules", {"qrcode": None}):
            self.assertFalse(cli.print_qr("https://x/"))


class TokenTest(unittest.TestCase):
    def test_token_is_random_and_long_enough(self):
        made = {tokens.new_token() for _ in range(5)}
        self.assertEqual(len(made), 5)
        self.assertTrue(all(len(t) >= 16 for t in made))

    def test_write_token_overwrites_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "token.txt")
            tokens.write_token(path, "one")
            tokens.write_token(path, "two")
            with open(path) as fh:
                self.assertEqual(fh.read().strip(), "two")


if __name__ == "__main__":
    unittest.main()

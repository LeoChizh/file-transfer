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
        self.assertIsNone(args.name)
        self.assertTrue(args.publish)
        self.assertEqual(args.ca, "ca.pem")
        self.assertEqual(args.ca_key, "ca-key.pem")

    def test_overrides(self):
        args = cli.parse_args(["--port", "9000", "--dir", "/tmp/drop",
                               "--name", "drop.local", "--no-publish"])
        self.assertEqual((args.port, args.upload_dir, args.name),
                         (9000, "/tmp/drop", "drop.local"))
        self.assertFalse(args.publish)


class AnnounceTest(unittest.TestCase):
    URL = "https://pc.local:8443/tok/"

    def say(self, url=URL, **kw):
        buf = io.StringIO()
        cli.announce(url, "/tmp/uploads", out=buf, **kw)
        return buf.getvalue()

    def test_url_and_folder(self):
        out = self.say()
        self.assertIn(f"[*] {self.URL}", out)
        self.assertIn("[*] saving into /tmp/uploads", out)

    def test_qr_code_is_drawn_above_the_url(self):
        self.assertGreater(len(self.say().splitlines()), 10)

    def test_ca_install_line(self):
        out = self.say(ca_url=self.URL + "ca.pem")
        self.assertIn(f"install {self.URL}ca.pem", out)

    def test_no_ca_line_when_there_is_nothing_to_install(self):
        self.assertNotIn("install", self.say())

    def test_unresolved_name_is_called_out(self):
        """Silence here would look like success and reach nothing."""
        out = self.say(unresolved="pc.local")
        self.assertIn("[!] nothing answers for pc.local", out)
        self.assertIn("mdns extra", out)

    def test_nothing_alarming_when_the_name_resolves(self):
        self.assertNotIn("[!]", self.say())

    def test_no_addresses_anywhere_in_the_output(self):
        """Addresses are not part of this any more."""
        out = self.say(ca_url=self.URL + "ca.pem")
        self.assertNotIn("192.168", out)
        self.assertNotIn("FILE_TRANSFER_HOST", out)


class QrTest(unittest.TestCase):
    def test_qr_printed(self):
        buf = io.StringIO()
        self.assertTrue(cli.print_qr("https://pc.local:8443/tok/", out=buf))
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

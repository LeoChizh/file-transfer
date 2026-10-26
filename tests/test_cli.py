import io
import os
import tempfile
import unittest
from unittest import mock

from filetransfer import cli, mdns, tokens
from filetransfer.server import DEFAULT_PORT


class ParseArgsTest(unittest.TestCase):
    def test_defaults(self):
        args = cli.parse_args([])
        self.assertEqual(args.port, DEFAULT_PORT)
        self.assertEqual(args.upload_dir, "uploads")
        self.assertIsNone(args.host)
        self.assertIsNone(args.name)
        self.assertTrue(args.mdns)
        self.assertEqual(args.ca, "ca.pem")
        self.assertEqual(args.ca_key, "ca-key.pem")

    def test_mdns_can_be_turned_off(self):
        self.assertFalse(cli.parse_args(["--no-mdns"]).mdns)

    def test_overrides(self):
        args = cli.parse_args(["--port", "9000", "--dir", "/tmp/drop",
                               "--host", "192.168.1.9"])
        self.assertEqual((args.port, args.upload_dir, args.host),
                         (9000, "/tmp/drop", "192.168.1.9"))


class AnnounceTest(unittest.TestCase):
    def say(self, urls, skipped=(), **kw):
        buf = io.StringIO()
        cli.announce(urls, list(skipped), "/tmp/uploads", out=buf, **kw)
        return buf.getvalue()

    def test_single_url_is_bare(self):
        out = self.say(["https://192.168.0.10:8443/tok/"])
        self.assertIn("[*] https://192.168.0.10:8443/tok/", out)
        self.assertNotIn(" or ", out)
        self.assertNotIn("wrong one first", out)
        self.assertIn("[*] saving into /tmp/uploads", out)

    def test_extra_urls_and_hint(self):
        out = self.say(["https://a/", "https://b/"], host_hint=True)
        self.assertIn("[*] or https://b/", out)
        self.assertIn("wrong one first", out)

    def test_no_address_hint_when_the_extra_url_is_a_name(self):
        """One address plus a .local name is not an ambiguous address."""
        out = self.say(["https://pc.local:8443/t/",
                        "https://10.0.0.1:8443/t/"])
        self.assertIn("[*] or https://10.0.0.1:8443/t/", out)
        self.assertNotIn("wrong one first", out)

    def test_no_certificate_warnings_any_more(self):
        """Every URL is covered by the CA-signed certificate."""
        out = self.say(["https://pc.local/", "https://10.0.0.1/"])
        self.assertNotIn("warning", out)

    def test_ca_install_line(self):
        out = self.say(["https://pc.local/t/"],
                       ca_url="https://pc.local/t/ca.pem")
        self.assertIn("install https://pc.local/t/ca.pem", out)

    def test_no_ca_line_when_there_is_nothing_to_install(self):
        self.assertNotIn("install", self.say(["https://pc.local/t/"]))

    def test_skipped_tunnel_is_explained(self):
        out = self.say(["https://a/"], skipped=["10.99.0.2"])
        self.assertIn("not serving tunnel 10.99.0.2", out)
        self.assertIn(cli.HOST_ENV, out)
        self.assertNotIn("cert", out)  # the CA is what the phone trusts

    def test_qr_code_is_drawn_above_the_url(self):
        out = self.say(["https://192.168.0.10:8443/tok/"])
        self.assertGreater(len(out.splitlines()), 10)


class ResolveNameTest(unittest.TestCase):
    def args(self, **kw):
        argv = []
        for flag, value in kw.items():
            argv += [f"--{flag.replace('_', '-')}"] + (
                [value] if value is not True else [])
        return cli.parse_args(argv)

    def test_uses_the_hostname_by_default(self):
        with mock.patch.object(mdns, "ensure_name",
                               return_value=("pc.local", None)) as ensure, \
                mock.patch.object(mdns, "default_name",
                                  return_value="pc.local"):
            name, _ = cli.resolve_name(self.args(), "192.168.0.10")
        self.assertEqual(name, "pc.local")
        self.assertEqual(ensure.call_args[0][0], "pc.local")

    def test_explicit_name_wins(self):
        with mock.patch.object(mdns, "ensure_name",
                               return_value=("drop.local", None)) as ensure:
            cli.resolve_name(self.args(name="drop.local"), "192.168.0.10")
        self.assertEqual(ensure.call_args[0][0], "drop.local")

    def test_no_mdns_skips_it(self):
        with mock.patch.object(mdns, "ensure_name") as ensure:
            self.assertEqual(cli.resolve_name(self.args(no_mdns=True),
                                              "192.168.0.10"), (None, None))
        ensure.assert_not_called()

    def test_no_name_without_a_usable_address(self):
        with mock.patch.object(mdns, "ensure_name") as ensure:
            self.assertEqual(cli.resolve_name(self.args(), cli.UNKNOWN),
                             (None, None))
        ensure.assert_not_called()


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

import datetime
import ipaddress
import os
import tempfile
import unittest
from unittest import mock

from cryptography import x509

from filetransfer import addresses, certs

LAN = "192.168.0.10"
TUNNEL = "172.23.0.103"


def load(path):
    with open(path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    return cert, san


def san_ips(path):
    return sorted(str(i) for i in
                  load(path)[1].get_values_for_type(x509.IPAddress))


class EnsureCertTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cert = os.path.join(self.tmp.name, "cert.pem")
        self.key = os.path.join(self.tmp.name, "key.pem")

    def ensure(self, ips=(LAN,), **kw):
        """ensure_cert() takes the addresses, so nothing needs patching."""
        return certs.ensure_cert(self.cert, self.key, ips=ips, **kw)

    def test_creates_with_ip_san(self):
        self.assertTrue(self.ensure())
        self.assertEqual(san_ips(self.cert), ["127.0.0.1", LAN])

    def test_reuses_valid_cert(self):
        self.ensure()
        with open(self.cert, "rb") as fh:
            before = fh.read()
        self.assertFalse(self.ensure())
        with open(self.cert, "rb") as fh:
            self.assertEqual(fh.read(), before)

    def test_regenerates_when_ip_changes(self):
        self.ensure()
        self.assertTrue(self.ensure(ips=["10.0.0.7"]))
        self.assertIn("10.0.0.7", san_ips(self.cert))

    def test_every_address_given_lands_in_san(self):
        self.ensure(ips=[LAN, "192.168.0.11"])
        self.assertEqual(san_ips(self.cert),
                         ["127.0.0.1", LAN, "192.168.0.11"])

    def test_regenerates_when_expiring(self):
        self.ensure()
        soon = datetime.datetime.now(datetime.timezone.utc) + \
            datetime.timedelta(days=340)
        with mock.patch.object(certs.datetime, "datetime") as dt:
            dt.now.return_value = soon
            self.assertTrue(certs._needs_regen(self.cert, self.key, [LAN]))

    def test_regenerates_when_key_missing_or_cert_garbage(self):
        self.ensure()
        os.remove(self.key)
        self.assertTrue(self.ensure())
        with open(self.cert, "w") as fh:
            fh.write("garbage")
        self.assertTrue(self.ensure())

    def test_force_and_extra_names(self):
        self.ensure()
        self.assertTrue(self.ensure(force=True, extra=["my-pc.local"]))
        san = load(self.cert)[1]
        self.assertIn("my-pc.local", san.get_values_for_type(x509.DNSName))

    def test_no_regen_without_any_usable_ip(self):
        self.ensure()
        self.assertFalse(
            certs._needs_regen(self.cert, self.key, [addresses.UNKNOWN]))

    def test_placeholder_is_not_put_in_the_san(self):
        self.ensure(ips=[addresses.UNKNOWN])
        self.assertEqual(san_ips(self.cert), ["127.0.0.1"])
        self.assertEqual(load(self.cert)[1].get_values_for_type(x509.DNSName),
                         [])

    def test_vpn_coming_and_going_leaves_cert_alone(self):
        """The phone trusts one cert; a tunnel must not force a reinstall."""
        lan = [("lo", "127.0.0.1"), ("wlan0", LAN)]
        with mock.patch.dict(os.environ, {addresses.HOST_ENV: ""}):
            with mock.patch.object(addresses, "_interface_addrs",
                                   return_value=lan):
                self.assertTrue(certs.ensure_cert(self.cert, self.key))
                with open(self.cert, "rb") as fh:
                    before = fh.read()
            with mock.patch.object(addresses, "_interface_addrs",
                                   return_value=[*lan, ("tun0", TUNNEL)]):
                self.assertFalse(certs.ensure_cert(self.cert, self.key))
        with open(self.cert, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertNotIn(TUNNEL, san_ips(self.cert))


if __name__ == "__main__":
    unittest.main()

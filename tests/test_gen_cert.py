import datetime
import os
import tempfile
import unittest
from unittest import mock

from cryptography import x509

import gen_cert


def load(path):
    with open(path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    return cert, san


class EnsureCertTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cert = os.path.join(self.tmp.name, "cert.pem")
        self.key = os.path.join(self.tmp.name, "key.pem")
        p = mock.patch.object(gen_cert, "lan_ip", return_value="192.168.1.50")
        p.start()
        self.addCleanup(p.stop)

    def ensure(self, **kw):
        return gen_cert.ensure_cert(self.cert, self.key, **kw)

    def test_creates_with_ip_san(self):
        self.assertTrue(self.ensure())
        ips = [str(i) for i in
               load(self.cert)[1].get_values_for_type(x509.IPAddress)]
        self.assertIn("192.168.1.50", ips)
        self.assertIn("127.0.0.1", ips)

    def test_reuses_valid_cert(self):
        self.ensure()
        with open(self.cert, "rb") as fh:
            before = fh.read()
        self.assertFalse(self.ensure())
        with open(self.cert, "rb") as fh:
            self.assertEqual(fh.read(), before)

    def test_regenerates_when_ip_changes(self):
        self.ensure()
        with mock.patch.object(gen_cert, "lan_ip", return_value="10.0.0.7"):
            self.assertTrue(self.ensure())
        ips = [str(i) for i in
               load(self.cert)[1].get_values_for_type(x509.IPAddress)]
        self.assertIn("10.0.0.7", ips)

    def test_regenerates_when_expiring(self):
        self.ensure()
        soon = datetime.datetime.now(datetime.timezone.utc) + \
            datetime.timedelta(days=340)
        with mock.patch.object(gen_cert.datetime, "datetime") as dt:
            dt.now.return_value = soon
            self.assertTrue(gen_cert._needs_regen(
                self.cert, self.key, "192.168.1.50"))

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


if __name__ == "__main__":
    unittest.main()

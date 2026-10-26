import datetime
import os
import tempfile
import unittest
from unittest import mock

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from filetransfer import certs

LEAF_ALMOST_OVER = certs.LEAF_DAYS - 10
NAME = "pc.local"
OTHER = "drop.local"


def load(path):
    with open(path, "rb") as fh:
        return x509.load_pem_x509_certificate(fh.read())


def san(path):
    return load(path).extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value


def san_ips(path):
    return sorted(str(i) for i in san(path).get_values_for_type(
        x509.IPAddress))


def san_names(path):
    return sorted(san(path).get_values_for_type(x509.DNSName))


def ext(path, cls):
    return load(path).extensions.get_extension_for_class(cls)


def digest(path):
    with open(path, "rb") as fh:
        return fh.read()


class CertTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = self.tmp.name
        self.cert = os.path.join(p, "cert.pem")
        self.key = os.path.join(p, "key.pem")
        self.ca = os.path.join(p, "ca.pem")
        self.ca_key = os.path.join(p, "ca-key.pem")

    def ensure(self, names=(NAME,), **kw):
        return certs.ensure_cert(self.cert, self.key, names=names,
                                 ca_cert=self.ca, ca_key=self.ca_key, **kw)


class WhatTheIphoneChecksTest(CertTest):
    """iOS 13+ silently refuses a server certificate missing any of these."""

    def test_leaf_has_server_auth_eku(self):
        self.ensure()
        eku = ext(self.cert, x509.ExtendedKeyUsage).value
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, eku)

    def test_leaf_is_not_a_ca_and_can_sign_a_handshake(self):
        self.ensure()
        self.assertFalse(ext(self.cert, x509.BasicConstraints).value.ca)
        usage = ext(self.cert, x509.KeyUsage).value
        self.assertTrue(usage.digital_signature)
        self.assertTrue(usage.key_encipherment)
        self.assertFalse(usage.key_cert_sign)

    def test_leaf_lifetime_is_under_the_apple_limit(self):
        self.ensure()
        cert = load(self.cert)
        days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        self.assertLessEqual(days, 398)

    def test_name_is_in_the_san_not_the_common_name(self):
        self.ensure()
        self.assertIn(NAME, san_names(self.cert))
        self.assertEqual(load(self.cert).subject.rfc4514_string(),
                         "CN=file-transfer")

    def test_leaf_really_is_signed_by_the_ca(self):
        self.ensure()
        load(self.cert).verify_directly_issued_by(load(self.ca))

    def test_ca_can_sign_certificates(self):
        self.ensure()
        self.assertTrue(ext(self.ca, x509.BasicConstraints).value.ca)
        self.assertTrue(ext(self.ca, x509.KeyUsage).value.key_cert_sign)


class StabilityTest(CertTest):
    """The phone trusts the CA, so only the CA changing costs anything."""

    def test_first_run_makes_both(self):
        self.assertEqual(self.ensure(), (True, True))
        for f in (self.cert, self.key, self.ca, self.ca_key):
            self.assertTrue(os.path.exists(f), f)

    def test_second_run_changes_nothing(self):
        self.ensure()
        self.assertEqual(self.ensure(), (False, False))

    def test_name_change_re_signs_the_leaf_but_keeps_the_ca(self):
        self.ensure()
        before = digest(self.ca)
        self.assertEqual(self.ensure(names=[OTHER]), (False, True))
        self.assertEqual(digest(self.ca), before)
        self.assertIn(OTHER, san_names(self.cert))

    def test_the_certificate_does_not_care_about_addresses(self):
        """Nothing about the network can invalidate it any more."""
        self.ensure()
        self.assertEqual(san_ips(self.cert), ["127.0.0.1"])
        self.assertEqual(self.ensure(), (False, False))

    def test_losing_the_ca_rebuilds_the_chain(self):
        self.ensure()
        os.remove(self.ca)
        self.assertEqual(self.ensure(), (True, True))
        load(self.cert).verify_directly_issued_by(load(self.ca))

    def test_force_replaces_both(self):
        self.ensure()
        self.assertEqual(self.ensure(force=True), (True, True))

    def test_expiring_leaf_is_re_signed(self):
        self.ensure()
        soon = datetime.datetime.now(datetime.timezone.utc) + \
            datetime.timedelta(days=LEAF_ALMOST_OVER)
        with mock.patch.object(certs, "_now", return_value=soon):
            self.assertTrue(certs._needs_regen(self.cert, self.key, [NAME]))

    def test_unreadable_cert_is_replaced(self):
        self.ensure()
        with open(self.cert, "w") as fh:
            fh.write("garbage")
        self.assertEqual(self.ensure(), (False, True))

    def test_missing_key_is_replaced(self):
        self.ensure()
        os.remove(self.key)
        self.assertEqual(self.ensure(), (False, True))


class SanContentsTest(CertTest):
    def test_loopback_is_always_covered(self):
        """So the machine can always reach itself, whatever mDNS does."""
        self.ensure()
        self.assertIn("127.0.0.1", san_ips(self.cert))
        self.assertIn("localhost", san_names(self.cert))

    def test_several_names_are_covered(self):
        self.ensure(names=[NAME, OTHER])
        self.assertEqual(san_names(self.cert),
                         sorted([NAME, OTHER, "localhost"]))

    def test_an_address_given_as_a_name_still_works(self):
        """--name 192.168.0.9 is unusual but should not produce a DNS entry."""
        self.ensure(names=["192.168.0.9"])
        self.assertIn("192.168.0.9", san_ips(self.cert))
        self.assertEqual(san_names(self.cert), ["localhost"])


class PrivateKeyTest(CertTest):
    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_keys_are_not_world_readable(self):
        self.ensure()
        for path in (self.key, self.ca_key):
            self.assertEqual(os.stat(path).st_mode & 0o077, 0, path)


if __name__ == "__main__":
    unittest.main()

import datetime
import ipaddress
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
        self.fake_ips = mock.patch.object(gen_cert, "lan_ips",
                                          return_value=["192.168.0.10"])
        self.fake_ips.start()
        self.addCleanup(self.fake_ips.stop)

    def use_real_lan_ips(self):
        """Undo setUp's stub so the real ranking runs in this test."""
        self.fake_ips.stop()
        self.addCleanup(self.fake_ips.start)  # cleanups are LIFO

    def ensure(self, **kw):
        return gen_cert.ensure_cert(self.cert, self.key, **kw)

    def test_creates_with_ip_san(self):
        self.assertTrue(self.ensure())
        ips = [str(i) for i in
               load(self.cert)[1].get_values_for_type(x509.IPAddress)]
        self.assertIn("192.168.0.10", ips)
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
        with mock.patch.object(gen_cert, "lan_ips",
                               return_value=["10.0.0.7"]):
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
                self.cert, self.key, ["192.168.0.10"]))

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

    def test_all_stable_ips_land_in_san(self):
        with mock.patch.object(gen_cert, "lan_ips",
                               return_value=["192.168.0.10", "192.168.9.9"]):
            self.ensure()
        ips = [str(i) for i in
               load(self.cert)[1].get_values_for_type(x509.IPAddress)]
        self.assertEqual(sorted(ips),
                         ["127.0.0.1", "192.168.0.10", "192.168.9.9"])

    def test_vpn_coming_and_going_leaves_cert_alone(self):
        """The phone trusts one cert; a tunnel must not force a reinstall."""
        self.use_real_lan_ips()
        lan = [("lo", "127.0.0.1"), ("wlan0", "192.168.0.10")]
        tunnel = ("tun0", "10.99.0.2")
        with mock.patch.object(gen_cert, "_interface_addrs",
                               return_value=lan), \
                mock.patch.dict(os.environ, {gen_cert.HOST_ENV: ""}):
            self.assertTrue(self.ensure())
            with open(self.cert, "rb") as fh:
                before = fh.read()
        with mock.patch.object(gen_cert, "_interface_addrs",
                               return_value=[*lan, tunnel]), \
                mock.patch.dict(os.environ, {gen_cert.HOST_ENV: ""}):
            self.assertFalse(self.ensure())  # VPN up: same cert
        with open(self.cert, "rb") as fh:
            self.assertEqual(fh.read(), before)
        san = load(self.cert)[1].get_values_for_type(x509.IPAddress)
        self.assertNotIn(ipaddress.ip_address("10.99.0.2"), san)

    def test_no_regen_without_any_usable_ip(self):
        self.ensure()
        self.assertFalse(gen_cert._needs_regen(
            self.cert, self.key, ["<this-machine-ip>"]))


class LanIpTest(unittest.TestCase):
    """The LAN address must win over a VPN tunnel that owns the route."""

    VPN_UP = [("lo", "127.0.0.1"), ("tun0", "10.99.0.2"),
              ("wlan0", "192.168.0.10")]

    def setUp(self):
        p = mock.patch.dict(os.environ, {gen_cert.HOST_ENV: ""})
        p.start()
        self.addCleanup(p.stop)

    def addrs(self, pairs):
        return mock.patch.object(gen_cert, "_interface_addrs",
                                 return_value=pairs)

    def test_lan_beats_vpn(self):
        with self.addrs(self.VPN_UP):
            self.assertEqual(gen_cert.lan_ip(), "192.168.0.10")

    def test_lan_beats_docker_and_loopback(self):
        with self.addrs([("docker0", "172.17.0.1"), ("lo", "127.0.0.1"),
                         ("eth0", "192.168.8.2")]):
            self.assertEqual(gen_cert.lan_ip(), "192.168.8.2")

    def test_tunnels_are_left_out_unless_asked_for(self):
        with self.addrs(self.VPN_UP):
            self.assertEqual(gen_cert.lan_ips(), ["192.168.0.10"])
            self.assertEqual(gen_cert.lan_ips(include_tunnels=True),
                             ["192.168.0.10", "10.99.0.2"])
            self.assertEqual(gen_cert.tunnel_ips(), ["10.99.0.2"])

    def test_vpn_only_is_still_offered(self):
        """Nothing else to serve: better a tunnel URL than no URL at all."""
        with self.addrs([("lo", "127.0.0.1"), ("wg0", "10.8.0.6")]):
            self.assertEqual(gen_cert.lan_ip(), "10.8.0.6")
            self.assertEqual(gen_cert.tunnel_ips(), [])

    def test_skips_link_local_and_cgnat(self):
        with self.addrs([("eth0", "169.254.3.4"),
                         ("tailscale0", "100.100.1.2")]):
            self.assertEqual(gen_cert.lan_ips(), [])
            self.assertEqual(gen_cert.lan_ip(), "<this-machine-ip>")

    def test_env_override_wins(self):
        with self.addrs(self.VPN_UP), mock.patch.dict(
                os.environ, {gen_cert.HOST_ENV: "pc.local"}):
            self.assertEqual(gen_cert.lan_ips(), ["pc.local"])

    def test_parse_ip_addr(self):
        out = gen_cert._parse_ip_addr(
            "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft\n"
            "3: wlan0    inet 192.168.0.10/24 brd 192.168.0.255 scope global\n"
            "4: tun0    inet 10.99.0.2/24 brd 10.99.0.255 scope global\n")
        self.assertEqual(out, [("lo", "127.0.0.1"), ("wlan0", "192.168.0.10"),
                               ("tun0", "10.99.0.2")])

    def test_parse_ifconfig(self):
        out = gen_cert._parse_ifconfig(
            "en0: flags=8863<UP,BROADCAST>\n"
            "\tinet 192.168.0.10 netmask 0xffffff00 broadcast 192.168.0.255\n"
            "utun3: flags=8051<UP,POINTOPOINT>\n"
            "\tinet 10.9.0.2 --> 10.9.0.2 netmask 0xffffffff\n")
        self.assertEqual(out, [("en0", "192.168.0.10"),
                               ("utun3", "10.9.0.2")])


if __name__ == "__main__":
    unittest.main()

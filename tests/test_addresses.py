import os
import unittest
from unittest import mock

from filetransfer import addresses


class LanIpTest(unittest.TestCase):
    """The LAN address must win over a VPN tunnel that owns the route."""

    VPN_UP = [("lo", "127.0.0.1"), ("tun0", "10.99.0.2"),
              ("wlan0", "192.168.0.10")]

    def setUp(self):
        p = mock.patch.dict(os.environ, {addresses.HOST_ENV: ""})
        p.start()
        self.addCleanup(p.stop)

    def addrs(self, pairs):
        return mock.patch.object(addresses, "_interface_addrs",
                                 return_value=pairs)

    def test_lan_beats_vpn(self):
        with self.addrs(self.VPN_UP):
            self.assertEqual(addresses.lan_ip(), "192.168.0.10")

    def test_lan_beats_docker_and_loopback(self):
        with self.addrs([("docker0", "172.17.0.1"), ("lo", "127.0.0.1"),
                         ("eth0", "192.168.8.2")]):
            self.assertEqual(addresses.lan_ip(), "192.168.8.2")

    def test_tunnels_are_left_out_unless_asked_for(self):
        with self.addrs(self.VPN_UP):
            self.assertEqual(addresses.lan_ips(), ["192.168.0.10"])
            self.assertEqual(addresses.lan_ips(include_tunnels=True),
                             ["192.168.0.10", "10.99.0.2"])
            self.assertEqual(addresses.tunnel_ips(), ["10.99.0.2"])

    def test_vpn_only_is_still_offered(self):
        """Nothing else to serve: better a tunnel URL than no URL at all."""
        with self.addrs([("lo", "127.0.0.1"), ("wg0", "10.8.0.6")]):
            self.assertEqual(addresses.lan_ip(), "10.8.0.6")
            self.assertEqual(addresses.tunnel_ips(), [])

    def test_private_ranges_are_preferred_in_order(self):
        with self.addrs([("eth2", "10.1.2.3"), ("eth1", "172.20.0.5"),
                         ("eth0", "192.168.4.4")]):
            self.assertEqual(addresses.lan_ips(),
                             ["192.168.4.4", "172.20.0.5", "10.1.2.3"])

    def test_skips_link_local_and_cgnat(self):
        with self.addrs([("eth0", "169.254.3.4"),
                         ("tailscale0", "100.100.1.2")]):
            self.assertEqual(addresses.lan_ips(), [])
            self.assertEqual(addresses.lan_ip(), addresses.UNKNOWN)

    def test_duplicate_addresses_are_reported_once(self):
        with self.addrs([("eth0", "192.168.0.10"),
                         ("eth0:1", "192.168.0.10")]):
            self.assertEqual(addresses.lan_ips(), ["192.168.0.10"])

    def test_env_override_wins(self):
        with self.addrs(self.VPN_UP), mock.patch.dict(
                os.environ, {addresses.HOST_ENV: "pc.local"}):
            self.assertEqual(addresses.lan_ips(), ["pc.local"])
            self.assertEqual(addresses.tunnel_ips(), [])

    def test_argument_override_beats_env(self):
        with self.addrs(self.VPN_UP), mock.patch.dict(
                os.environ, {addresses.HOST_ENV: "from-env"}):
            self.assertEqual(addresses.lan_ips(override="10.99.0.2"),
                             ["10.99.0.2"])

    def test_parse_ip_addr(self):
        out = addresses._parse_ip_addr(
            "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft\n"
            "3: wlan0    inet 192.168.0.10/24 brd 192.168.0.255 scope"
            " global\n"
            "4: tun0    inet 10.99.0.2/24 brd 10.99.0.255 scope global\n")
        self.assertEqual(out, [("lo", "127.0.0.1"), ("wlan0", "192.168.0.10"),
                               ("tun0", "10.99.0.2")])

    def test_parse_ifconfig(self):
        out = addresses._parse_ifconfig(
            "en0: flags=8863<UP,BROADCAST>\n"
            "\tinet 192.168.0.10 netmask 0xffffff00 broadcast 192.168.0.255\n"
            "utun3: flags=8051<UP,POINTOPOINT>\n"
            "\tinet 10.99.0.2 --> 10.99.0.2 netmask 0xffffffff\n")
        self.assertEqual(out, [("en0", "192.168.0.10"),
                               ("utun3", "10.99.0.2")])

    def test_parse_ifconfig_old_linux_style(self):
        out = addresses._parse_ifconfig(
            "eth0      Link encap:Ethernet  HWaddr 00:11:22:33:44:55\n"
            "          inet addr:192.168.0.10  Bcast:192.168.0.255\n")
        self.assertEqual(out, [("eth0", "192.168.0.10")])


if __name__ == "__main__":
    unittest.main()

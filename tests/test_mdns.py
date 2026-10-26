import socket
import threading
import time
import unittest
from unittest import mock

from filetransfer import mdns

NAME = "filedrop.local"
OURS = "192.168.0.10"
THEIRS = "192.168.0.99"


def answers(*ips):
    """Fake getaddrinfo results for the addresses given."""
    return mock.patch.object(
        socket, "getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
                      for ip in ips])


class DefaultNameTest(unittest.TestCase):
    def test_short_hostname_lowercased(self):
        self.assertEqual(mdns.default_name("My-PC.lan"), "my-pc.local")

    def test_plain_hostname(self):
        self.assertEqual(mdns.default_name("nuc"), "nuc.local")


class IsLocalTest(unittest.TestCase):
    """Asking the kernel to bind beats listing the interfaces."""

    def test_loopback_is_ours(self):
        self.assertTrue(mdns.is_local("127.0.0.1"))

    def test_an_address_we_do_not_hold_is_not(self):
        self.assertFalse(mdns.is_local("203.0.113.7"))  # TEST-NET-3

    def test_the_wildcard_is_not_a_name_for_us(self):
        self.assertFalse(mdns.is_local("0.0.0.0"))
        self.assertFalse(mdns.is_local("::"))

    def test_ipv6_loopback_is_ours(self):
        if not socket.has_ipv6:
            self.skipTest("no IPv6")
        self.assertTrue(mdns.is_local("::1"))

    def test_nonsense_is_not(self):
        self.assertFalse(mdns.is_local("not-an-address"))


class ResolvesHereTest(unittest.TestCase):
    def test_true_when_the_name_points_at_us(self):
        with answers(OURS), mock.patch.object(mdns, "is_local",
                                              return_value=True):
            self.assertTrue(mdns.resolves_here(NAME))

    def test_false_when_it_points_at_a_namesake(self):
        """Handing the phone to someone else's machine is the worst case."""
        with answers(THEIRS), mock.patch.object(mdns, "is_local",
                                                return_value=False):
            self.assertFalse(mdns.resolves_here(NAME))

    def test_false_if_any_answer_is_not_ours(self):
        """A namesake mixed in with our own address must not pass."""
        with answers(THEIRS, OURS), mock.patch.object(
                mdns, "is_local", side_effect=lambda ip: ip == OURS):
            self.assertFalse(mdns.resolves_here(NAME))

    def test_true_when_every_answer_is_ours(self):
        with answers(OURS, "10.0.0.5"), mock.patch.object(
                mdns, "is_local", return_value=True):
            self.assertTrue(mdns.resolves_here(NAME))

    def test_ipv6_answers_count(self):
        with mock.patch.object(
                socket, "getaddrinfo",
                return_value=[(socket.AF_INET6, socket.SOCK_STREAM, 6, "",
                               ("fe80::1", 0, 0, 0))]),                 mock.patch.object(mdns, "is_local", return_value=True):
            self.assertTrue(mdns.resolves_here(NAME))

    def test_false_when_nothing_answers(self):
        with mock.patch.object(socket, "getaddrinfo",
                               side_effect=OSError("NXDOMAIN")):
            self.assertFalse(mdns.resolves_here(NAME))

    def test_false_when_the_answer_is_empty(self):
        with answers():
            self.assertFalse(mdns.resolves_here(NAME))

    def test_gives_up_instead_of_stalling(self):
        release = threading.Event()
        self.addCleanup(release.set)
        with mock.patch.object(socket, "getaddrinfo",
                               side_effect=lambda *a: release.wait(10)):
            started = time.monotonic()
            self.assertFalse(mdns.resolves_here(NAME, timeout=0.2))
        self.assertLess(time.monotonic() - started, 2)


if __name__ == "__main__":
    unittest.main()

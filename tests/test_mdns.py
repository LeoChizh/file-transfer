import socket
import sys
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

    def test_true_if_any_answer_is_ours(self):
        with answers(THEIRS, OURS), mock.patch.object(
                mdns, "is_local", side_effect=lambda ip: ip == OURS):
            self.assertTrue(mdns.resolves_here(NAME))

    def test_false_when_nothing_answers(self):
        with mock.patch.object(socket, "getaddrinfo",
                               side_effect=OSError("NXDOMAIN")):
            self.assertFalse(mdns.resolves_here(NAME))


class FakeZeroconf:
    """Stands in for the optional dependency."""

    def __init__(self, conflict=False):
        self.registered = []
        self.conflict = conflict
        self.closed = False

    def module(self):
        outer = self

        class NonUniqueNameException(Exception):
            pass

        class Zeroconf:
            def register_service(self, info, allow_name_change=True):
                if outer.conflict:
                    raise NonUniqueNameException(info)
                outer.registered.append(info)

            def close(self):
                outer.closed = True

        return mock.MagicMock(
            Zeroconf=Zeroconf,
            ServiceInfo=lambda *a, **kw: ("info", a, kw),
            NonUniqueNameException=NonUniqueNameException)


class AdvertiseTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(mdns, "_announce_addresses",
                              return_value=[OURS])
        p.start()
        self.addCleanup(p.stop)

    def test_none_without_the_optional_dependency(self):
        with mock.patch.dict(sys.modules, {"zeroconf": None}):
            self.assertIsNone(mdns.advertise(NAME, 8443))

    def test_publishes_and_returns_a_stop_callable(self):
        fake = FakeZeroconf()
        with mock.patch.dict(sys.modules, {"zeroconf": fake.module()}):
            stop = mdns.advertise(NAME, 8443)
        self.assertTrue(callable(stop))
        self.assertEqual(len(fake.registered), 1)
        stop()
        self.assertTrue(fake.closed)

    def test_gives_up_when_the_name_is_taken(self):
        fake = FakeZeroconf(conflict=True)
        with mock.patch.dict(sys.modules, {"zeroconf": fake.module()}):
            self.assertIsNone(mdns.advertise(NAME, 8443))
        self.assertTrue(fake.closed)  # no dangling responder

    def test_nothing_to_announce_means_no_publishing(self):
        fake = FakeZeroconf()
        with mock.patch.dict(sys.modules, {"zeroconf": fake.module()}), \
                mock.patch.object(mdns, "_announce_addresses",
                                  return_value=[]):
            self.assertIsNone(mdns.advertise(NAME, 8443))
        self.assertEqual(fake.registered, [])

    def test_loopback_is_never_announced(self):
        with mock.patch.object(socket, "getaddrinfo",
                               return_value=[(2, 1, 6, "", ("127.0.0.1", 0)),
                                             (2, 1, 6, "", (OURS, 0))]):
            self.assertEqual(mdns._announce_addresses(), [OURS])


class EnsureNameTest(unittest.TestCase):
    def test_existing_name_needs_no_publishing(self):
        with mock.patch.object(mdns, "resolves_here", return_value=True), \
                mock.patch.object(mdns, "advertise") as adv:
            self.assertEqual(mdns.ensure_name(NAME, 8443), (True, None))
        adv.assert_not_called()

    def test_publishes_when_nothing_answers(self):
        stop = object()
        with mock.patch.object(mdns, "resolves_here", return_value=False), \
                mock.patch.object(mdns, "advertise", return_value=stop):
            self.assertEqual(mdns.ensure_name(NAME, 8443), (True, stop))

    def test_unresolved_when_it_cannot_be_published(self):
        with mock.patch.object(mdns, "resolves_here", return_value=False), \
                mock.patch.object(mdns, "advertise", return_value=None):
            self.assertEqual(mdns.ensure_name(NAME, 8443), (False, None))

    def test_no_publish_does_not_try(self):
        with mock.patch.object(mdns, "resolves_here", return_value=False), \
                mock.patch.object(mdns, "advertise") as adv:
            self.assertEqual(mdns.ensure_name(NAME, 8443, publish=False),
                             (False, None))
        adv.assert_not_called()


if __name__ == "__main__":
    unittest.main()

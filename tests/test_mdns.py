import socket
import sys
import unittest
from unittest import mock

from filetransfer import mdns

NAME = "filedrop.local"
OUR_IP = "192.168.0.10"


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


class ResolvesToTest(unittest.TestCase):
    def test_true_when_the_name_points_at_us(self):
        with answers(OUR_IP):
            self.assertTrue(mdns.resolves_to(NAME, [OUR_IP]))

    def test_false_when_it_points_at_someone_else(self):
        """A namesake on the LAN must not capture the phone."""
        with answers("192.168.0.99"):
            self.assertFalse(mdns.resolves_to(NAME, [OUR_IP]))

    def test_false_when_it_does_not_resolve(self):
        with mock.patch.object(socket, "getaddrinfo",
                               side_effect=OSError("NXDOMAIN")):
            self.assertFalse(mdns.resolves_to(NAME, [OUR_IP]))

    def test_true_if_any_of_our_addresses_match(self):
        with answers("192.168.0.11"):
            self.assertTrue(mdns.resolves_to(NAME, [OUR_IP, "192.168.0.11"]))


class FakeZeroconf:
    """Stands in for the optional dependency."""

    def __init__(self, registered, conflict=False):
        self.registered = registered
        self.conflict = conflict
        self.closed = False

    def module(self):
        class NonUniqueNameException(Exception):
            pass

        def service_info(*a, **kw):
            return ("info", a, kw)

        outer = self

        class Zeroconf:
            def __init__(self, interfaces=None):
                outer.interfaces = interfaces

            def register_service(self, info, allow_name_change=True):
                if outer.conflict:
                    raise NonUniqueNameException(info)
                outer.registered.append(info)

            def close(self):
                outer.closed = True

        return mock.MagicMock(Zeroconf=Zeroconf, ServiceInfo=service_info,
                              NonUniqueNameException=NonUniqueNameException)


class AdvertiseTest(unittest.TestCase):
    def test_none_without_the_optional_dependency(self):
        with mock.patch.dict(sys.modules, {"zeroconf": None}):
            self.assertIsNone(mdns.advertise(NAME, 8443, OUR_IP))

    def test_publishes_and_returns_a_stop_callable(self):
        fake = FakeZeroconf(registered=[])
        with mock.patch.dict(sys.modules, {"zeroconf": fake.module()}):
            stop = mdns.advertise(NAME, 8443, OUR_IP)
        self.assertTrue(callable(stop))
        self.assertEqual(len(fake.registered), 1)
        self.assertEqual(fake.interfaces, [OUR_IP])  # not the VPN
        stop()
        self.assertTrue(fake.closed)

    def test_gives_up_when_the_name_is_taken(self):
        fake = FakeZeroconf(registered=[], conflict=True)
        with mock.patch.dict(sys.modules, {"zeroconf": fake.module()}):
            self.assertIsNone(mdns.advertise(NAME, 8443, OUR_IP))
        self.assertTrue(fake.closed)  # no dangling responder


class EnsureNameTest(unittest.TestCase):
    def test_existing_name_needs_no_publishing(self):
        with answers(OUR_IP), mock.patch.object(mdns, "advertise") as adv:
            self.assertEqual(mdns.ensure_name(NAME, 8443, OUR_IP),
                             (NAME, None))
        adv.assert_not_called()

    def test_publishes_when_nothing_answers(self):
        stop = object()
        with mock.patch.object(mdns, "resolves_to", return_value=False), \
                mock.patch.object(mdns, "advertise", return_value=stop):
            self.assertEqual(mdns.ensure_name(NAME, 8443, OUR_IP),
                             (NAME, stop))

    def test_no_name_when_it_cannot_be_published(self):
        with mock.patch.object(mdns, "resolves_to", return_value=False), \
                mock.patch.object(mdns, "advertise", return_value=None):
            self.assertEqual(mdns.ensure_name(NAME, 8443, OUR_IP),
                             (None, None))

    def test_publish_false_does_not_try(self):
        with mock.patch.object(mdns, "resolves_to", return_value=False), \
                mock.patch.object(mdns, "advertise") as adv:
            self.assertEqual(
                mdns.ensure_name(NAME, 8443, OUR_IP, publish=False),
                (None, None))
        adv.assert_not_called()


if __name__ == "__main__":
    unittest.main()

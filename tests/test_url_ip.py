"""URL validation and IP policy (SSRF input layer)."""
import unittest

from sitecheck.errors import InputRejected
from sitecheck.ippolicy import check_all, check_ip
from sitecheck.urlcheck import normalize_url


class UrlRejectTests(unittest.TestCase):
    CASES = [
        ("", "invalid_url"),
        ("ftp://example.com/", "unsupported_scheme"),
        ("file:///etc/passwd", "unsupported_scheme"),
        ("gopher://example.com/", "unsupported_scheme"),
        ("javascript:alert(1)", "unsupported_scheme"),
        ("https://user:pass@example.com/", "credentials_in_url"),
        ("https://example.com@169.254.169.254/", "credentials_in_url"),
        ("https://example.com:8443/", "unsupported_port"),
        ("http://example.com:22/", "unsupported_port"),
        ("http://127.0.0.1/", "ip_literal_not_allowed"),
        ("http://2130706433/", "ip_literal_not_allowed"),
        ("http://0x7f.1/", "ip_literal_not_allowed"),
        ("http://017700000001/", "ip_literal_not_allowed"),
        ("http://0x7f000001/", "ip_literal_not_allowed"),
        ("http://127.1/", "ip_literal_not_allowed"),
        ("http://[::1]/", "ip_literal_not_allowed"),
        ("http://[::ffff:127.0.0.1]/", "ip_literal_not_allowed"),
        ("http://169.254.169.254/latest/meta-data/", "ip_literal_not_allowed"),
        ("http://localhost/", "blocked_destination"),
        ("http://foo.localhost/", "blocked_destination"),
        ("http://printer.local/", "blocked_destination"),
        ("http://metadata.google.internal/", "blocked_destination"),
        ("http://intranet/", "blocked_destination"),
        ("http://router.home.arpa/", "blocked_destination"),
        ("https://example.com/" + "a" * 2100, "url_too_long"),
        ("https://exa mple.com/", "invalid_url"),
        ("https://example.com/\\..\\", "invalid_url"),
        ("https://-bad-.com/", "invalid_url"),
        ("https://example.123/", "ip_literal_not_allowed"),
    ]

    def test_rejections(self):
        for raw, code in self.CASES:
            with self.subTest(raw=raw[:60]):
                with self.assertRaises(InputRejected) as cm:
                    normalize_url(raw)
                self.assertEqual(cm.exception.code, code)

    def test_normalisation(self):
        n = normalize_url("HTTPS://WWW.Example.COM:443/a%20b/ü?x=1#frag")
        self.assertEqual(n.url, "https://www.example.com/a%20b/%C3%BC?x=1")
        self.assertEqual(normalize_url("http://example.com").path, "/")
        self.assertEqual(normalize_url("https://bücher.example/").host, "xn--bcher-kva.example")
        self.assertEqual(normalize_url("http://example.com.:80/").origin, "http://example.com")


class IpPolicyTests(unittest.TestCase):
    BLOCKED = [
        "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "127.255.255.254", "169.254.169.254",
        "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.10", "192.88.99.1", "192.168.1.1",
        "198.18.0.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "240.0.0.1", "255.255.255.255",
        "::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",            # NAT64 of 169.254.169.254
        "64:ff9b:1::1", "100::1", "2001::1", "2001:db8::1", "2002:7f00:1::1", "fc00::1",
        "fd00:ec2::254", "fe80::1", "fec0::1", "ff02::1",
    ]
    ALLOWED = ["93.184.215.14", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8",
               "64:ff9b::808:808"]

    def test_blocked(self):
        for ip in self.BLOCKED:
            with self.subTest(ip=ip):
                ok, why = check_ip(ip)
                self.assertFalse(ok, why)

    def test_allowed(self):
        for ip in self.ALLOWED:
            with self.subTest(ip=ip):
                ok, why = check_ip(ip)
                self.assertTrue(ok, why)

    def test_mixed_answer_rejected(self):
        ok, why = check_all(["93.184.215.14", "10.0.0.5"])
        self.assertFalse(ok)
        self.assertIn("10.0.0.5", why)
        self.assertFalse(check_all([])[0])


if __name__ == "__main__":
    unittest.main()

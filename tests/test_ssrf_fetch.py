"""SSRF, redirect and DNS-rebinding controls in the real fetch path (fake DNS + fake transport)."""
import unittest

from sitecheck.fixtures import H, IP_OTHER, IP_SITE, TEXT, ok, page, redirect, run
from sitecheck.transport import FixtureResponse

NO_ROBOTS = FixtureResponse(404, dict(TEXT), b"")


def contacted(transport):
    return [(e["host"], e["path"], e["connect_ip"]) for e in transport.log]


class BlockedBeforeContact(unittest.TestCase):
    def test_host_resolving_to_private_is_never_contacted(self):
        for ips in (["10.0.0.7"], ["127.0.0.1"], ["169.254.169.254"], ["::1"], ["fd00:ec2::254"],
                    ["::ffff:192.168.0.1"], ["93.184.215.14", "192.168.0.10"]):
            with self.subTest(ips=ips):
                report, transport, resolver, _ = run("https://www.example.com/", {H: ips},
                                                     {(H, "/"): ok(page())})
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["pages"][0]["error_code"], "blocked_destination")
                self.assertEqual(transport.log, [], "no HTTP request may be sent")
                self.assertEqual(report["coverage"]["requests_used"], 0)

    def test_redirect_to_private_ip_stops_before_target(self):
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): redirect("https://evil.example.net/admin"),
                  ("evil.example.net", "/admin"): ok(page())}
        report, transport, resolver, _ = run("https://www.example.com/",
                                             {H: [IP_SITE], "evil.example.net": ["127.0.0.1"]}, routes)
        self.assertEqual(report["pages"][0]["error_code"], "redirect_to_blocked_destination")
        self.assertNotIn("evil.example.net", [e["host"] for e in transport.log])
        self.assertIn("evil.example.net", resolver.calls, "the new hop must be re-resolved and re-checked")

    def test_redirect_to_ip_literal_and_metadata_name(self):
        for loc, code in (("http://169.254.169.254/latest/meta-data/", "ip_literal_not_allowed"),
                          ("http://metadata.google.internal/computeMetadata/v1/", "redirect_to_blocked_destination"),
                          ("http://[::1]/", "ip_literal_not_allowed"),
                          ("file:///etc/passwd", "unsupported_scheme"),
                          ("https://example.com:8080/", "unsupported_port")):
            with self.subTest(loc=loc):
                routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): redirect(loc)}
                report, transport, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
                self.assertEqual(report["pages"][0]["error_code"], code)
                self.assertEqual([e["path"] for e in transport.log], ["/robots.txt", "/"])

    def test_redirect_to_new_public_host_is_rechecked_and_robots_first(self):
        other = "www.example.org"
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): redirect(f"https://{other}/"),
                  (other, "/robots.txt"): NO_ROBOTS, (other, "/"): ok(page())}
        report, transport, resolver, _ = run("https://www.example.com/", {H: [IP_SITE], other: [IP_OTHER]}, routes)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(contacted(transport), [
            (H, "/robots.txt", IP_SITE), (H, "/", IP_SITE),
            (other, "/robots.txt", IP_OTHER), (other, "/", IP_OTHER)])
        self.assertEqual(report["coverage"]["site_host"], other)


class Rebinding(unittest.TestCase):
    def test_second_dns_answer_is_never_used(self):
        # first answer public, every later answer private: the job must stay on the first IP
        dns = {H: [[IP_SITE], ["127.0.0.1"], ["169.254.169.254"]]}
        links = tuple((f"/p{i}/", "p") for i in range(3))
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(page(links=links))}
        for i in range(3):
            routes[(H, f"/p{i}/")] = ok(page())
        report, transport, resolver, _ = run("https://www.example.com/", dns, routes)
        self.assertEqual(resolver.calls, [H], "one resolution per host per job")
        self.assertEqual({e["connect_ip"] for e in transport.log}, {IP_SITE})
        self.assertEqual(report["coverage"]["dns_lookups_used"], 1)
        self.assertEqual(report["status"], "complete")

    def test_connect_ip_is_validated_ip_for_every_hop(self):
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): redirect("/a"), (H, "/a"): redirect("/b"),
                  (H, "/b"): ok(page())}
        report, transport, _, _ = run("https://www.example.com/", {H: [IP_SITE, "2606:2800:220:1::1"]}, routes)
        self.assertEqual([e["connect_ip"] for e in transport.log], [IP_SITE] * 4)
        self.assertEqual(len(report["pages"][0]["redirect_chain"]), 3)


class MethodsOnly(unittest.TestCase):
    def test_only_get_and_head_and_form_never_submitted(self):
        body = page(body_extra='<form action="/subscribe" method="post"><input name="email"><button>Go</button></form>',
                    links=(("/subscribe", "s"),))
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(body), (H, "/subscribe"): ok(page())}
        report, transport, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
        self.assertTrue({e["method"] for e in transport.log} <= {"GET", "HEAD"})
        self.assertEqual(report["pages"][0]["measured"]["forms_found"], 1)


if __name__ == "__main__":
    unittest.main()

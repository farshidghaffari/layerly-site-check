"""R2: robots.txt before every page (no start-page bypass), and the robots result matrix."""
import unittest

from sitecheck.config import Limits
from sitecheck.errors import TransportError
from sitecheck.fixtures import H, IP_SITE, TEXT, ok, page, redirect, run
from sitecheck.robots import match, parse_robots
from sitecheck.transport import FixtureResponse


def paths(transport):
    return [e["path"] for e in transport.log]


class Parser(unittest.TestCase):
    def test_longest_match_and_allow_tie(self):
        rules = parse_robots("User-agent: *\nDisallow: /shop/\nAllow: /shop/public/\nDisallow: /*.pdf$\n"
                             "Allow: /tie\nDisallow: /tie\n")
        self.assertFalse(match(rules, "/shop/cart")[0])
        self.assertTrue(match(rules, "/shop/public/x")[0])
        self.assertFalse(match(rules, "/files/a.pdf")[0])
        self.assertTrue(match(rules, "/files/a.pdf?x=1")[0])
        self.assertTrue(match(rules, "/tie")[0])
        self.assertTrue(match(rules, "/other")[0])

    def test_own_group_beats_star_and_empty_disallow(self):
        txt = "User-agent: *\nDisallow: /\n\nUser-agent: LayerlySiteCheck\nDisallow:\n"
        self.assertTrue(match(parse_robots(txt), "/anything")[0])
        txt2 = "User-agent: otherbot\nDisallow: /\n"
        self.assertTrue(match(parse_robots(txt2), "/x")[0])

    def test_multiple_agents_in_one_group(self):
        txt = "User-agent: a\nUser-agent: *\nDisallow: /p\n"
        self.assertFalse(match(parse_robots(txt), "/p")[0])


class Matrix(unittest.TestCase):
    def check(self, robots_response, expect_state, expect_page_requested, dns_extra=None, extra_routes=None):
        routes = {(H, "/robots.txt"): robots_response, (H, "/"): ok(page())}
        routes.update(extra_routes or {})
        dns = {H: [IP_SITE]}
        dns.update(dns_extra or {})
        report, transport, _, _ = run("https://www.example.com/", dns, routes)
        self.assertEqual(report["coverage"]["robots_txt"], expect_state)
        self.assertEqual("/" in paths(transport), expect_page_requested, paths(transport))
        self.assertEqual(paths(transport)[0], "/robots.txt", "robots must be the first request")
        return report, transport

    def test_200_allows(self):
        r, _ = self.check(ok(b"User-agent: *\nDisallow: /private/\n", TEXT), "fetched", True)
        self.assertEqual(r["status"], "complete")

    def test_404_and_410_are_definite_absence(self):
        for st in (404, 410):
            with self.subTest(status=st):
                r, _ = self.check(FixtureResponse(st, dict(TEXT), b""), "absent", True)
                self.assertEqual(r["status"], "complete")

    def test_401_403_access_denied(self):
        for st in (401, 403):
            with self.subTest(status=st):
                r, _ = self.check(FixtureResponse(st, dict(TEXT), b""), "access_denied", False)
                self.assertEqual(r["status"], "failed")
                self.assertEqual(r["pages"][0]["error_code"], "robots_unavailable")

    def test_other_4xx_5xx_are_unknown_not_permission(self):
        for st in (400, 429, 500, 503):
            with self.subTest(status=st):
                r, _ = self.check(FixtureResponse(st, dict(TEXT), b""), "unknown", False)
                self.assertEqual(r["status"], "failed")
                self.assertTrue(r["pages"][0]["evidence_ids"], "unknown robots keeps its own evidence")

    def test_timeout_connection_tls_are_unknown(self):
        for code in ("fetch_timeout", "connection_failed", "tls_error"):
            with self.subTest(code=code):
                r, _ = self.check(TransportError(code, code), "unknown", False)
                self.assertEqual(r["coverage"]["robots_origins"][0]["reason"], code)

    def test_robots_too_large_is_unknown(self):
        big = b"User-agent: *\n" + b"#" * (Limits().max_robots_bytes + 10)
        self.check(ok(big, TEXT), "unknown", False)

    def test_robots_redirect_followed_checked_and_counted(self):
        r, t = self.check(redirect("https://www.example.com/robots-real.txt"), "fetched", True,
                          extra_routes={(H, "/robots-real.txt"): ok(b"User-agent: *\nAllow: /\n", TEXT)})
        self.assertEqual(paths(t), ["/robots.txt", "/robots-real.txt", "/"])
        self.assertEqual(r["coverage"]["requests_used"], 3)

    def test_robots_redirect_to_private_is_unknown(self):
        r, t = self.check(redirect("https://cdn.example.net/robots.txt"), "unknown", False,
                          dns_extra={"cdn.example.net": ["10.1.1.1"]})
        self.assertEqual(r["coverage"]["robots_origins"][0]["reason"], "redirect_to_blocked_destination")
        self.assertNotIn("cdn.example.net", [e["host"] for e in t.log])

    def test_robots_redirect_loop_is_unknown(self):
        self.check(redirect("https://www.example.com/robots.txt"), "unknown", False)

    def test_start_page_disallowed_is_not_requested(self):
        r, t = self.check(ok(b"User-agent: *\nDisallow: /\n", TEXT), "fetched", False)
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["pages"][0]["error_code"], "start_page_robots_disallowed")
        self.assertEqual(r["pages"][0]["fetch_status"], "skipped")
        f = r["findings"][0]
        self.assertEqual(f["rule_id"], "robots_txt.disallowed")
        ev = {e["evidence_id"]: e for e in r["evidence"]}[f["evidence_ids"][0]]
        self.assertEqual(ev["kind"], "robots_txt_rule")
        self.assertEqual(ev["url"], "https://www.example.com/robots.txt")
        self.assertEqual(ev["excerpt"], "Disallow: /")
        self.assertIsNone(r["pages"][0]["measured"], "no fabricated HTML data for an unrequested page")

    def test_budget_exhausted_before_robots(self):
        report, transport, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, {(H, "/"): ok(page())},
                                      limits=Limits(max_requests=0))
        self.assertEqual(report["coverage"]["robots_txt"], "not_fetched")
        self.assertEqual(transport.log, [])
        self.assertEqual(report["pages"][0]["error_code"], "request_budget_exhausted")

    def test_disallowed_inner_page_and_link_not_requested(self):
        body = page(links=(("/private/a/", "a"), ("/private/file", "f"), ("/ok/", "ok")))
        routes = {(H, "/robots.txt"): ok(b"User-agent: *\nDisallow: /private/\n", TEXT), (H, "/"): ok(body),
                  (H, "/ok/"): ok(page())}
        report, transport, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
        self.assertFalse([p for p in paths(transport) if p.startswith("/private/")])
        skipped = [p for p in report["pages"] if p["fetch_status"] == "skipped"]
        self.assertEqual(len(skipped), 2)
        self.assertTrue(all(p["error_code"] == "robots_disallowed" for p in skipped))


if __name__ == "__main__":
    unittest.main()

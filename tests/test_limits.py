"""Timeouts, redirect limits, size limits, content type, and the 5-page / 20-request / 30-DNS caps."""
import gzip
import unittest

from sitecheck.config import Limits
from sitecheck.errors import TransportError
from sitecheck.fixtures import H, HTML, IP_SITE, TEXT, ok, page, redirect, run
from sitecheck.transport import FixtureResponse

NO_ROBOTS = FixtureResponse(404, dict(TEXT), b"")


def site(start_body, extra=None):
    routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(start_body)}
    routes.update(extra or {})
    return routes


class Resources(unittest.TestCase):
    def test_timeout_inner_page_gives_partial_and_is_not_retried(self):
        routes = site(page(links=(("/slow/", "s"), ("/fast/", "f"))),
                      {(H, "/slow/"): TransportError("fetch_timeout", "t"), (H, "/fast/"): ok(page())})
        r, t, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
        self.assertEqual(r["status"], "partial")
        self.assertEqual([e["path"] for e in t.log].count("/slow/"), 1)
        self.assertEqual(r["coverage"]["checks_not_run"], [{"page_url": "https://www.example.com/slow/", "reason": "fetch_timeout"}])

    def test_start_page_timeout_is_failed(self):
        r, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]},
                         {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): TransportError("fetch_timeout", "t")})
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["errors"][0]["code"], "fetch_timeout")

    def test_connection_failed_retried_once_and_counted(self):
        r, t, _, _ = run("https://www.example.com/", {H: [IP_SITE]},
                         {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): TransportError("connection_failed", "c")})
        self.assertEqual([e["purpose"] for e in r["request_log"]], ["robots", "page", "retry"])
        self.assertEqual(r["coverage"]["requests_used"], 3)

    def test_tls_error_is_reported_not_bypassed(self):
        r, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]},
                         {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): TransportError("tls_error", "bad cert")})
        self.assertEqual(r["pages"][0]["error_code"], "tls_error")

    def test_too_many_redirects_and_loop(self):
        chain = {(H, f"/r{i}"): redirect(f"/r{i + 1}") for i in range(10)}
        chain[(H, "/")] = redirect("/r0")
        chain[(H, "/robots.txt")] = NO_ROBOTS
        r, t, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, chain)
        self.assertEqual(r["pages"][0]["error_code"], "too_many_redirects")
        self.assertEqual(len(t.log), 1 + 6, "robots + start + 5 hops, then stop")
        loop = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): redirect("/a"), (H, "/a"): redirect("/")}
        r2, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, loop)
        self.assertEqual(r2["pages"][0]["error_code"], "too_many_redirects")

    def test_large_response(self):
        big = b"<html><title>x</title>" + b"a" * (Limits().max_body_bytes + 1)
        r, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, site(big))
        self.assertEqual(r["pages"][0]["error_code"], "response_too_large")
        self.assertIsNone(r["pages"][0]["measured"])

    def test_gzip_bomb_is_cut_after_decompression(self):
        bomb = gzip.compress(b"<html>" + b"\0" * (20 * 1024 * 1024))
        self.assertLess(len(bomb), 64 * 1024)
        routes = site(b"", {(H, "/"): FixtureResponse(200, {"content-type": "text/html", "content-encoding": "gzip"}, bomb)})
        r, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
        self.assertEqual(r["pages"][0]["error_code"], "response_too_large")

    def test_gzip_normal_page_is_parsed(self):
        body = gzip.compress(page(title="Compressed page title ok"))
        routes = site(b"", {(H, "/"): FixtureResponse(200, {"content-type": "text/html", "content-encoding": "gzip"}, body)})
        r, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
        self.assertEqual(r["pages"][0]["measured"]["title"]["value"], "Compressed page title ok")

    def test_non_html_content_type(self):
        routes = site(b"", {(H, "/"): FixtureResponse(200, {"content-type": "application/pdf"}, b"%PDF")})
        r, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["pages"][0]["error_code"], "unsupported_content_type")

    def test_job_timeout(self):
        links = tuple((f"/p{i}/", "p") for i in range(4))
        routes = site(page(links=links))
        for i in range(4):
            routes[(H, f"/p{i}/")] = FixtureResponse(200, dict(HTML), page(), latency_s=25)
        r, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
        self.assertEqual(r["status"], "partial")
        self.assertEqual(r["coverage"]["stopped_reason"], "job_timeout")


class Caps(unittest.TestCase):
    def test_max_five_pages(self):
        links = tuple((f"/p{i}/", "p") for i in range(12))
        routes = site(page(links=links), {(H, f"/p{i}/"): ok(page()) for i in range(12)})
        r, t, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
        self.assertEqual(len(r["pages"]), 5)
        page_gets = [e for e in t.log if e["method"] == "GET" and e["path"] != "/robots.txt"]
        self.assertEqual(len(page_gets), 5)

    def test_twenty_request_cap_exact(self):
        links = tuple((f"/p{i}/", "p") for i in range(40))
        routes = site(page(links=links), {(H, f"/p{i}/"): ok(page()) for i in range(40)})
        r, t, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes)
        self.assertEqual(len(t.log), 20)
        self.assertEqual(r["coverage"]["requests_used"], 20)
        self.assertEqual(r["status"], "partial")
        self.assertEqual(r["coverage"]["stopped_reason"], "request_budget_exhausted")
        unchecked = [l for l in r["links"] if l["status"] == "not_checked"]
        self.assertTrue(unchecked)
        self.assertTrue(all(l["reason"] == "request_budget_exhausted" and l["http_status"] is None for l in unchecked))
        # 1 robots + 5 pages + 14 HEAD link checks
        self.assertEqual(sum(1 for l in r["links"] if l["status"] == "ok"), 14)

    def test_budget_stops_mid_redirect_chain(self):
        chain = {(H, f"/r{i}"): redirect(f"/r{i + 1}") for i in range(4)}
        chain.update({(H, "/robots.txt"): NO_ROBOTS, (H, "/"): redirect("/r0")})
        r, t, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, chain, limits=Limits(max_requests=3))
        self.assertEqual(len(t.log), 3)
        self.assertEqual(r["pages"][0]["error_code"], "request_budget_exhausted")

    def test_dns_cap_separate_and_enforced(self):
        hosts = [f"h{i}.example.com" for i in range(4)]
        routes = {(h, "/robots.txt"): NO_ROBOTS for h in hosts}
        for i, h in enumerate(hosts[:-1]):
            routes[(h, "/")] = redirect(f"https://{hosts[i + 1]}/")
        routes[(hosts[-1], "/")] = ok(page())
        dns = {h: [IP_SITE] for h in hosts}
        r, t, res, _ = run(f"https://{hosts[0]}/", dns, routes, limits=Limits(max_dns_lookups=2))
        self.assertEqual(r["coverage"]["dns_lookups_used"], 2)
        self.assertEqual(len(res.calls), 2)
        self.assertEqual(r["pages"][0]["error_code"], "dns_budget_exhausted")
        self.assertNotIn(hosts[2], [e["host"] for e in t.log])

    def test_default_dns_limit_is_30_and_http_is_20(self):
        lim = Limits()
        self.assertEqual((lim.max_pages, lim.max_requests, lim.max_dns_lookups), (5, 20, 30))


if __name__ == "__main__":
    unittest.main()

"""FIX1 regressions from the G0 review: F1 robots URI comparison and BOM, F2 malformed URLs,
F3 coverage of unchecked links, F4 version-independent evidence. All fixture-only."""
import unittest

from sitecheck.config import Limits
from sitecheck.fixtures import H, IP_SITE, TEXT, ok, page, redirect, run
from sitecheck.robots import comparison_form, match, parse_robots
from sitecheck.transport import FixtureResponse
from sitecheck.validate import validate_report

NO_ROBOTS = FixtureResponse(404, dict(TEXT), b"")


def go(url, routes, **kw):
    report, transport, _, _ = run(url, {H: [IP_SITE]}, routes, **kw)
    return report, [e["path"] for e in transport.log], transport


class F1ComparisonForm(unittest.TestCase):
    def test_comparison_form(self):
        cases = {
            "/%70rivate/": "/private/",          # unreserved letter decoded
            "/%7e%2D%5F%2e": "/~-_.",            # unreserved symbols decoded
            "/a%2fb": "/a%2Fb",                  # reserved '/' stays encoded, hex upper-cased
            "/a%3Fb%3d": "/a%3Fb%3D",            # reserved ? and = stay encoded
            "/ü/": "/%C3%BC/",                   # UTF-8 percent-encoding
            "/%c3%bc/": "/%C3%BC/",
            "/files/*.pdf$": "/files/*.pdf$",    # wildcards untouched
            "/100%": "/100%",                    # stray % kept
        }
        for raw, want in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(comparison_form(raw), want)

    def test_match_both_directions_and_reserved(self):
        r = parse_robots("User-agent: *\nDisallow: /private/\nDisallow: /%73ecret/\nDisallow: /a/b\n"
                         "Disallow: /x%2Fy\nDisallow: /ü/\n")
        self.assertFalse(match(r, "/%70rivate/x")[0])      # encoded path, plain rule
        self.assertFalse(match(r, "/%70%72ivate/")[0])
        self.assertFalse(match(r, "/secret/")[0])          # plain path, encoded rule
        self.assertTrue(match(r, "/a%2Fb")[0])             # %2F is not '/': different resource
        self.assertFalse(match(r, "/x%2fy")[0])            # same reserved encoding, case-insensitive hex
        self.assertTrue(match(r, "/x/y")[0])
        self.assertFalse(match(r, "/%c3%bc/page")[0])      # UTF-8 rule vs encoded path
        self.assertFalse(match(r, "/ü/page")[0])


class F1Enforced(unittest.TestCase):
    ROBOTS = ok(b"User-agent: *\nDisallow: /private/\n", TEXT)

    def test_encoded_start_page_not_requested(self):
        r, paths, _ = go("https://www.example.com/%70rivate/", {(H, "/robots.txt"): self.ROBOTS,
                                                                (H, "/%70rivate/"): ok(page())})
        self.assertEqual(paths, ["/robots.txt"])
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["pages"][0]["error_code"], "start_page_robots_disallowed")
        self.assertEqual(validate_report(r), [])

    def test_encoded_next_page_and_link_not_requested(self):
        links = (("/%70rivate/a/", "a"), ("/PRIVATE/ok/", "case-sensitive, allowed"), ("/%70rivate/b.pdf", "pdf"))
        routes = {(H, "/robots.txt"): self.ROBOTS, (H, "/"): ok(page(links=links)),
                  (H, "/PRIVATE/ok/"): ok(page())}
        r, paths, _ = go("https://www.example.com/", routes)
        self.assertFalse([p for p in paths if "rivate" in p.lower() and p != "/PRIVATE/ok/"], paths)
        skipped = [p for p in r["pages"] if p["fetch_status"] == "skipped"]
        self.assertEqual([p["error_code"] for p in skipped], ["robots_disallowed"])
        link = [l for l in r["links"] if l["url"].endswith("b.pdf")][0]
        self.assertEqual((link["status"], link["reason"]), ("not_checked", "robots_disallowed"))
        self.assertEqual(r["status"], "partial")
        self.assertEqual(validate_report(r), [])

    def test_redirect_to_encoded_disallowed_path_not_requested(self):
        routes = {(H, "/robots.txt"): self.ROBOTS, (H, "/"): redirect("/%70rivate/x"),
                  (H, "/%70rivate/x"): ok(page())}
        r, paths, _ = go("https://www.example.com/", routes)
        self.assertEqual(paths, ["/robots.txt", "/"])
        self.assertEqual(r["pages"][0]["error_code"], "start_page_robots_disallowed")

    def test_bom_robots_is_parsed(self):
        routes = {(H, "/robots.txt"): ok(b"\xef\xbb\xbfUser-agent: *\nDisallow: /\n", TEXT), (H, "/"): ok(page())}
        r, paths, _ = go("https://www.example.com/", routes)
        self.assertEqual(paths, ["/robots.txt"])
        self.assertEqual(r["coverage"]["robots_txt"], "fetched")
        self.assertEqual(r["status"], "failed")
        ev = {e["evidence_id"]: e for e in r["evidence"]}
        self.assertEqual(ev[r["findings"][0]["evidence_ids"][0]]["excerpt"], "Disallow: /")

    def test_bom_with_own_group(self):
        txt = b"\xef\xbb\xbfUser-agent: LayerlySiteCheck\nDisallow: /\n\nUser-agent: *\nAllow: /\n"
        _, paths, _ = go("https://www.example.com/", {(H, "/robots.txt"): ok(txt, TEXT), (H, "/"): ok(page())})
        self.assertEqual(paths, ["/robots.txt"])

    def test_non_utf8_robots_is_unknown_and_denies(self):
        routes = {(H, "/robots.txt"): ok(b"User-agent: *\nDisallow: /\xff\xfe\n", TEXT), (H, "/"): ok(page())}
        r, paths, _ = go("https://www.example.com/", routes)
        self.assertEqual(paths, ["/robots.txt"])
        self.assertEqual(r["coverage"]["robots_origins"][0]["state"], "unknown")
        self.assertEqual(r["coverage"]["robots_origins"][0]["reason"], "robots_not_utf8")
        self.assertEqual(r["pages"][0]["error_code"], "robots_unavailable")


class F2Malformed(unittest.TestCase):
    BAD = ("http://[bad", "https://[::1", "http://exa mple.com/", "http://a:99999/", "https://www.example.com:8443/x",
           "http://\x00evil/", "//[", "http://127.0.0.1/admin")

    def test_malformed_hrefs_do_not_crash_and_are_not_requested(self):
        links = tuple((b, "bad") for b in self.BAD) + (("/good/", "good"), ("/also-good", "link"))
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(page(links=links)), (H, "/good/"): ok(page()),
                  (H, "/also-good"): ok(page())}
        r, paths, t = go("https://www.example.com/", routes)
        self.assertEqual(validate_report(r), [])
        self.assertEqual(paths, ["/robots.txt", "/", "/good/", "/also-good"])
        self.assertEqual({e["host"] for e in t.log}, {H})
        bad = [l for l in r["links"] if l["status"] == "not_checked"]
        self.assertGreaterEqual(len(bad), 6)
        self.assertTrue(all(l["reason"] and l["http_status"] is None for l in bad))
        self.assertIn("invalid_url", {l["reason"] for l in bad})
        self.assertEqual(r["status"], "partial")
        self.assertEqual([p["fetch_status"] for p in r["pages"]], ["ok", "ok", "ok"])

    def test_malformed_canonical(self):
        r, _, _ = go("https://www.example.com/", {(H, "/robots.txt"): NO_ROBOTS,
                                                  (H, "/"): ok(page(canonical="http://[bad"))})
        self.assertEqual(validate_report(r), [])
        c = r["pages"][0]["measured"]["canonical"]
        self.assertEqual((c["invalid"], c["is_self"], c["target_checked"]), (1, False, False))
        self.assertIn("canonical.invalid", [f["rule_id"] for f in r["findings"]])
        self.assertNotIn("canonical.points_elsewhere", [f["rule_id"] for f in r["findings"]])

    def test_invalid_location_on_start_page(self):
        r, paths, _ = go("https://www.example.com/", {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): redirect("http://[bad")})
        self.assertEqual(validate_report(r), [])
        self.assertEqual(paths, ["/robots.txt", "/"])
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["pages"][0]["error_code"], "invalid_redirect_location")

    def test_invalid_location_on_inner_page_keeps_other_pages(self):
        links = (("/moved/", "m"), ("/fine/", "f"))
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(page(links=links)),
                  (H, "/moved/"): redirect("https://[::1"), (H, "/fine/"): ok(page())}
        r, paths, _ = go("https://www.example.com/", routes)
        self.assertEqual(validate_report(r), [])
        self.assertEqual(r["status"], "partial")
        by_url = {p["url"]: p for p in r["pages"]}
        self.assertEqual(by_url["https://www.example.com/moved/"]["error_code"], "invalid_redirect_location")
        self.assertEqual(by_url["https://www.example.com/fine/"]["fetch_status"], "ok")


class F3Coverage(unittest.TestCase):
    def test_external_only_is_partial_and_not_contacted(self):
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(page(links=(("https://other.example.net/", "x"),)))}
        r, _, t = go("https://www.example.com/", routes)
        self.assertEqual(r["status"], "partial")
        self.assertEqual(r["coverage"]["links_not_checked_by_reason"], {"external_not_checked": 1})
        self.assertNotIn("other.example.net", [e["host"] for e in t.log])
        self.assertEqual(validate_report(r), [])

    def test_mixed_internal_external(self):
        links = (("https://other.example.net/a", "x"), ("/x.pdf", "pdf"), ("https://other.example.net/b", "y"))
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(page(links=links)),
                  (H, "/x.pdf"): FixtureResponse(200, {"content-type": "application/pdf"}, b"")}
        r, paths, t = go("https://www.example.com/", routes)
        self.assertEqual(paths, ["/robots.txt", "/", "/x.pdf"])
        self.assertEqual((r["coverage"]["links_checked"], r["coverage"]["links_not_checked"]), (1, 2))
        self.assertEqual(r["status"], "partial")
        self.assertEqual({e["host"] for e in t.log}, {H})

    def test_disallowed_link_is_partial(self):
        routes = {(H, "/robots.txt"): ok(b"User-agent: *\nDisallow: /x.pdf\n", TEXT),
                  (H, "/"): ok(page(links=(("/x.pdf", "pdf"),)))}
        r, paths, _ = go("https://www.example.com/", routes)
        self.assertNotIn("/x.pdf", paths)
        self.assertEqual(r["coverage"]["links_not_checked_by_reason"], {"robots_disallowed": 1})
        self.assertEqual(r["status"], "partial")

    def test_budget_exhausted_links_are_partial(self):
        links = tuple((f"/f{i}.pdf", "f") for i in range(5))
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(page(links=links))}
        for i in range(5):
            routes[(H, f"/f{i}.pdf")] = FixtureResponse(200, {"content-type": "application/pdf"}, b"")
        r, paths, _ = go("https://www.example.com/", routes, limits=Limits(max_requests=4))
        self.assertEqual(len(paths), 4)
        self.assertEqual(r["coverage"]["links_not_checked_by_reason"], {"request_budget_exhausted": 3})
        self.assertEqual(r["status"], "partial")

    def test_complete_only_when_everything_checked(self):
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(page(links=(("/x.pdf", "pdf"),))),
                  (H, "/x.pdf"): FixtureResponse(200, {"content-type": "application/pdf"}, b"")}
        r, _, _ = go("https://www.example.com/", routes)
        self.assertEqual(r["status"], "complete")
        self.assertEqual(r["coverage"]["links_not_checked"], 0)

    def test_validator_rejects_complete_with_unchecked(self):
        routes = {(H, "/robots.txt"): NO_ROBOTS, (H, "/"): ok(page(links=(("https://other.example.net/", "x"),)))}
        r, _, _ = go("https://www.example.com/", routes)
        r["status"] = "complete"
        self.assertIn("complete report with unchecked items", validate_report(r))


class F4StableEvidence(unittest.TestCase):
    def test_invalid_jsonld_excerpt_is_version_independent(self):
        r, _, _ = go("https://www.example.com/", {(H, "/robots.txt"): NO_ROBOTS,
                                                  (H, "/"): ok(page(jsonld=('{"@type":"Thing",}',)))})
        ev = [e for e in r["evidence"] if e["kind"] == "jsonld_parse_error"][0]
        self.assertEqual(ev["excerpt"], 'Invalid JSON; block starts: {"@type":"Thing",}')
        self.assertNotIn("char", ev["excerpt"])


if __name__ == "__main__":
    unittest.main()

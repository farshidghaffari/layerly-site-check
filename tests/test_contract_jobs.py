"""Report contract, deterministic sample, GPT layer disabled, local job flow and idempotency."""
import ast
import json
import os
import pathlib
import tempfile
import unittest

from sitecheck.clock import FakeClock
from sitecheck.errors import IdempotencyConflict, InputRejected
from sitecheck.fixtures import H, IP_SITE, TEXT, SCENARIOS, ok, page, run, run_sample, sample_scenario
from sitecheck.jobs import LocalJobQueue
from sitecheck.resolver import FixtureResolver
from sitecheck.transport import FixtureResponse, FixtureTransport
from sitecheck.validate import load_schema, validate_report

PKG = pathlib.Path(__file__).resolve().parent.parent / "sitecheck"
SAMPLE_FILE = pathlib.Path(__file__).resolve().parent.parent / "examples" / "sample-report.json"

try:
    import jsonschema
except ImportError:  # optional cross-check only
    jsonschema = None


class Contract(unittest.TestCase):
    def test_all_scenarios_validate(self):
        for name, fn in SCENARIOS.items():
            with self.subTest(scenario=name):
                report = fn()
                self.assertEqual(validate_report(report), [])
                if jsonschema:
                    jsonschema.validate(report, load_schema())

    def test_sample_numbers_match_fixture(self):
        r, transport = run_sample()
        c = r["coverage"]
        self.assertEqual(r["status"], "partial")
        self.assertEqual(c["requests_used"], len(transport.log))
        self.assertEqual(c["requests_used"], 12)
        self.assertEqual(c["dns_lookups_used"], 1)
        self.assertEqual((c["pages_selected"], c["pages_fetched"], c["pages_failed"], c["pages_skipped"]), (5, 3, 1, 1))
        home = r["pages"][0]["measured"]
        self.assertEqual(home["title"], {"value": "Example Industrial Pumps | Home", "length": 31})
        self.assertTrue(r["is_sample"])
        # robots before the start page and before the https hop
        purposes = [(e["purpose"], e["url"]) for e in r["request_log"][:5]]
        self.assertEqual(purposes, [
            ("robots", "http://www.example.com/robots.txt"),
            ("redirect", "https://www.example.com/robots.txt"),
            ("page", "http://www.example.com/"),
            ("robots", "https://www.example.com/robots.txt"),
            ("redirect", "https://www.example.com/")])

    def test_sample_is_deterministic_and_matches_committed_example(self):
        a, _ = run_sample()
        b, _ = run_sample()
        self.assertEqual(a, b)
        if SAMPLE_FILE.exists():
            self.assertEqual(json.loads(SAMPLE_FILE.read_text(encoding="utf-8")), a)

    def test_explanation_states(self):
        routes = {(H, "/robots.txt"): FixtureResponse(404, dict(TEXT), b""), (H, "/"): ok(page())}
        r1, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes, explain=False)
        r2, _, _, _ = run("https://www.example.com/", {H: [IP_SITE]}, routes, explain=True)
        self.assertEqual(r1["explanation"], {"status": "disabled", "lang": "en", "items": [], "reason": None,
                                            "is_test": False})
        self.assertEqual(r2["explanation"]["status"], "not_available")

    def test_no_llm_sdk_network_or_key_in_code(self):
        allowed = {"base64", "secrets", "urllib.parse", "json", "re", "os", "tempfile", "ipaddress", "socket",
                   "hashlib", "zlib", "dataclasses", "html.parser", "http.client", "ssl", "time", "datetime",
                   "argparse", "sys", "string", "collections"}
        for f in PKG.glob("*.py"):
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module]
                else:
                    continue
                for n in names:
                    self.assertIn(n, allowed, f"unexpected import {n} in {f.name}")
            low = f.read_text(encoding="utf-8").lower()
            for word in ("openai", "anthropic", "api_key", "gpt-"):
                self.assertFalse(word in low, f"{word} in {f.name}")

    def test_invalid_report_is_caught(self):
        r, _ = run_sample()
        bad = json.loads(json.dumps(r))
        bad["findings"][0]["evidence_ids"] = ["ev_000000000000"]
        self.assertTrue(validate_report(bad))
        bad2 = json.loads(json.dumps(r))
        bad2["findings"][0]["severity"] = "critical"
        self.assertTrue(validate_report(bad2))
        bad3 = json.loads(json.dumps(r))
        bad3["coverage"]["requests_used"] = 13
        self.assertTrue(validate_report(bad3))


class Jobs(unittest.TestCase):
    def make_queue(self, store=None, dns=None):
        dns_answers, routes = sample_scenario()
        clock = FakeClock()
        ids = iter(f"chk_job_{i:04d}" for i in range(100))
        return LocalJobQueue(FixtureResolver(dns or dns_answers), FixtureTransport(routes, clock), clock,
                             store_dir=store, id_factory=lambda: next(ids))

    def test_idempotent_replay_and_conflict(self):
        q = self.make_queue()
        a = q.submit("http://www.example.com", idempotency_key="k1")
        b = q.submit("http://www.example.com/", idempotency_key="k1")   # same normalised input
        self.assertEqual(a["check_id"], b["check_id"])
        self.assertTrue(b["idempotent_replay"])
        self.assertEqual(len(q.jobs), 1)
        with self.assertRaises(IdempotencyConflict):
            q.submit("http://www.example.com/other", idempotency_key="k1")
        with self.assertRaises(IdempotencyConflict):
            q.submit("http://www.example.com", explain=False, idempotency_key="k1")
        self.assertEqual(len(q.jobs), 1)

    def test_queue_flow_and_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            q = self.make_queue(store=d)
            acc = q.submit("http://www.example.com", idempotency_key="k2")
            self.assertEqual(q.get(acc["check_id"])["status"], "queued")
            q.run_pending()
            rep = q.get(acc["check_id"])
            self.assertEqual(rep["status"], "partial")
            self.assertEqual(validate_report(rep), [])
            q2 = self.make_queue(store=d)                        # reload from disk
            self.assertEqual(q2.get(acc["check_id"]), rep)
            again = q2.submit("http://www.example.com", idempotency_key="k2")
            self.assertEqual(again["check_id"], acc["check_id"])
            self.assertEqual(len(os.listdir(os.path.join(d, "checks"))), 1)

    def test_submit_rejects_before_job_exists(self):
        q = self.make_queue(dns={H: ["10.0.0.1"]})
        with self.assertRaises(InputRejected) as cm:
            q.submit("https://www.example.com/")
        self.assertEqual(cm.exception.code, "blocked_destination")
        with self.assertRaises(InputRejected) as cm:
            q.submit("https://nonexistent.example.com/")
        self.assertEqual(cm.exception.code, "dns_resolution_failed")
        with self.assertRaises(InputRejected):
            q.submit("http://127.0.0.1/")
        self.assertEqual(q.jobs, {})
        with self.assertRaises(InputRejected) as cm:
            q.get("chk_missing")
        self.assertEqual(cm.exception.code, "check_not_found")


if __name__ == "__main__":
    unittest.main()

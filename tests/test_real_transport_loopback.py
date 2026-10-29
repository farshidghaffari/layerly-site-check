"""The real PinnedTransport against a temporary server bound to 127.0.0.1 (test harness only).
The transport is called directly, below the policy layer. A separate test shows the product
path (SafeFetcher) still refuses loopback before any connection. No external network is used."""
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sitecheck.clock import RealClock
from sitecheck.config import Limits
from sitecheck.errors import TransportError
from sitecheck.fetcher import SafeFetcher
from sitecheck.resolver import BudgetedResolver, FixtureResolver
from sitecheck.transport import PinnedTransport
from sitecheck.urlcheck import NormalizedURL


class Handler(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Handler.hits.append({"path": self.path, "host": self.headers.get("Host"),
                             "ua": self.headers.get("User-Agent")})
        if self.path == "/slow":
            time.sleep(2)
        body = b"x" * 100_000 if self.path == "/big" else b"<title>ok</title>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_HEAD = do_GET


def serve(context=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if context:
        srv.socket = context.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def url(scheme, host, port, path="/"):
    return NormalizedURL(scheme, host, port, path, f"{scheme}://{host}:{port}{path}")


class PlainHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Handler.hits.clear()

    def test_connects_to_pinned_ip_with_original_host_header(self):
        r = PinnedTransport().send("GET", url("http", "site.example", self.port), "127.0.0.1", 5, 1_000_000)
        self.assertEqual(r.status, 200)
        self.assertEqual(Handler.hits[0]["host"], f"site.example:{self.port}")
        self.assertTrue(Handler.hits[0]["ua"].startswith("LayerlySiteCheck/"))

    def test_environment_proxy_is_ignored(self):
        old = {k: os.environ.get(k) for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy")}
        try:
            for k in old:
                os.environ.pop(k, None)
            os.environ["HTTP_PROXY"] = os.environ["http_proxy"] = "http://127.0.0.1:9"   # nothing listens here
            r = PinnedTransport().send("GET", url("http", "site.example", self.port), "127.0.0.1", 5, 1_000_000)
            self.assertEqual(r.status, 200)
        finally:
            for k, v in old.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v

    def test_timeout(self):
        t0 = time.monotonic()
        with self.assertRaises(TransportError) as cm:
            PinnedTransport().send("GET", url("http", "site.example", self.port, "/slow"), "127.0.0.1", 0.5, 1_000_000)
        self.assertEqual(cm.exception.code, "fetch_timeout")
        self.assertLess(time.monotonic() - t0, 1.8)

    def test_read_cap(self):
        r = PinnedTransport().send("GET", url("http", "site.example", self.port, "/big"), "127.0.0.1", 5, 10_000)
        self.assertTrue(r.truncated)
        self.assertLessEqual(len(r.body), 10_001)

    def test_connection_refused(self):
        with self.assertRaises(TransportError) as cm:
            PinnedTransport().send("GET", url("http", "site.example", 9), "127.0.0.1", 2, 1000)
        self.assertEqual(cm.exception.code, "connection_failed")

    def test_product_path_refuses_loopback_before_connecting(self):
        clock = RealClock()
        dns = BudgetedResolver(FixtureResolver({"site.example": ["127.0.0.1"]}), 30)
        f = SafeFetcher(dns, PinnedTransport(), clock, Limits())
        res = f.fetch("http://site.example/")
        self.assertEqual(res.error_code, "blocked_destination")
        self.assertEqual(Handler.hits, [])
        self.assertEqual(f.budget.used, 0)


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class Tls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.cert, cls.key = os.path.join(cls.dir, "c.pem"), os.path.join(cls.dir, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", cls.key, "-out", cls.cert, "-subj", "/CN=site.example",
                        "-addext", "subjectAltName=DNS:site.example"],
                       check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.cert, cls.key)
        cls.srv = serve(ctx)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.dir)

    def test_untrusted_certificate_is_tls_error(self):
        with self.assertRaises(TransportError) as cm:
            PinnedTransport().send("GET", url("https", "site.example", self.port), "127.0.0.1", 5, 1000)
        self.assertEqual(cm.exception.code, "tls_error")

    def test_trusted_certificate_uses_host_name_for_sni_and_verification(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        r = PinnedTransport(ssl_context=ctx).send("GET", url("https", "site.example", self.port), "127.0.0.1", 5, 1000)
        self.assertEqual(r.status, 200)
        with self.assertRaises(TransportError) as cm:   # same IP, wrong name -> verification fails
            PinnedTransport(ssl_context=ctx).send("GET", url("https", "other.example", self.port), "127.0.0.1", 5, 1000)
        self.assertEqual(cm.exception.code, "tls_error")


if __name__ == "__main__":
    unittest.main()

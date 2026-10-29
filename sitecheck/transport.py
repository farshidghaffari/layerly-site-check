"""Transports. A transport only moves bytes to an already-approved IP; all policy
lives in fetcher.SafeFetcher. PinnedTransport is the real one; FixtureTransport is for tests."""
import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field

from .config import USER_AGENT
from .errors import TransportError


@dataclass
class RawResponse:
    status: int
    headers: list            # [(lower-case name, value)]
    body: bytes = b""
    truncated: bool = False  # raw body exceeded the read cap

    def header(self, name):
        name = name.lower()
        for k, v in reversed(self.headers):
            if k == name:
                return v
        return None


def request_headers():
    return {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,text/plain;q=0.8,*/*;q=0.1",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, ip, connect_timeout, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip, self._connect_timeout = ip, connect_timeout

    def connect(self):
        # Connect to the validated IP; Host header still carries the original name.
        self.sock = socket.create_connection((self._ip, self.port), timeout=self._connect_timeout)
        self.sock.settimeout(self.timeout)


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    def __init__(self, host, port, ip, connect_timeout, timeout, context):
        super().__init__(host, port, ip, connect_timeout, timeout)
        self._context = context

    def connect(self):
        super().connect()
        # SNI and certificate check use the original host name, never the IP.
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class PinnedTransport:
    """Real HTTP(S) over a socket opened to the pinned IP. No environment proxies
    (http.client never reads HTTP_PROXY), full TLS verification, capped reads."""

    def __init__(self, connect_timeout=5.0, ssl_context=None):
        self.connect_timeout = connect_timeout
        self.ssl_context = ssl_context or ssl.create_default_context()

    def send(self, method, nurl, connect_ip, timeout, max_raw_bytes):
        deadline = time.monotonic() + timeout
        if nurl.scheme == "https":
            conn = _PinnedHTTPSConnection(nurl.host, nurl.port, connect_ip, self.connect_timeout, timeout, self.ssl_context)
        else:
            conn = _PinnedHTTPConnection(nurl.host, nurl.port, connect_ip, self.connect_timeout, timeout)
        try:
            conn.request(method, nurl.path, headers=request_headers())
            resp = conn.getresponse()
            headers = [(k.lower(), v) for k, v in resp.getheaders()]
            body, truncated = b"", False
            if method != "HEAD":
                chunks, size = [], 0
                while True:
                    if time.monotonic() > deadline:
                        raise TransportError("fetch_timeout", "Response took too long.")
                    chunk = resp.read(min(65536, max_raw_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > max_raw_bytes:
                        truncated = True
                        break
                body = b"".join(chunks)
            return RawResponse(resp.status, headers, body, truncated)
        except TransportError:
            raise
        except (socket.timeout, TimeoutError):
            raise TransportError("fetch_timeout", "No response within the time limit.")
        except (ssl.SSLError, ssl.CertificateError) as e:
            raise TransportError("tls_error", f"TLS error: {type(e).__name__}")
        except (OSError, http.client.HTTPException) as e:
            raise TransportError("connection_failed", f"Connection failed: {type(e).__name__}")
        finally:
            conn.close()


@dataclass
class FixtureResponse:
    status: int = 200
    headers: dict = field(default_factory=lambda: {"content-type": "text/html; charset=utf-8"})
    body: bytes = b""
    latency_s: float = 0.05


class FixtureTransport:
    """routes: {(host, path) or (scheme, host, path): FixtureResponse | TransportError |
    callable(method)->either}. The scheme-specific key wins when present.
    Every call is recorded in .log, so tests can prove what was (not) contacted."""

    def __init__(self, routes, clock, request_timeout=10.0):
        self.routes = routes
        self.clock = clock
        self.request_timeout = request_timeout
        self.log = []

    def send(self, method, nurl, connect_ip, timeout, max_raw_bytes):
        self.log.append({"method": method, "host": nurl.host, "path": nurl.path,
                         "scheme": nurl.scheme, "connect_ip": connect_ip})
        r = self.routes.get((nurl.scheme, nurl.host, nurl.path), self.routes.get((nurl.host, nurl.path)))
        if callable(r) and not isinstance(r, (FixtureResponse, TransportError)):
            r = r(method)
        if r is None:
            r = FixtureResponse(404, {"content-type": "text/html"}, b"<title>Not found</title>")
        if isinstance(r, TransportError):
            self.clock.sleep(timeout if r.code == "fetch_timeout" else 0.01)
            raise TransportError(r.code, r.message)
        self.clock.sleep(r.latency_s)
        body = b"" if method == "HEAD" else r.body
        truncated = len(body) > max_raw_bytes
        return RawResponse(r.status, [(k.lower(), v) for k, v in r.headers.items()],
                           body[:max_raw_bytes + 1] if truncated else body, truncated)

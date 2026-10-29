"""SafeFetcher (architecture component [4]): every hop is validated, resolved within
the DNS budget, checked against the IP policy, gated by robots (for pages), rate
limited, counted against the HTTP budget, and only then sent to the pinned IP."""
import zlib
from dataclasses import dataclass, field
from urllib.parse import urljoin

from .config import Limits
from .errors import BudgetExhausted, CheckError, FetchError, InputRejected, JobTimeout, TransportError
from .ippolicy import check_all
from .urlcheck import normalize_url


class HttpBudget:
    def __init__(self, limit):
        self.limit = limit
        self.used = 0

    def take(self):
        if self.used >= self.limit:
            raise BudgetExhausted("request_budget_exhausted", "HTTP request limit reached.")
        self.used += 1


@dataclass
class FetchResult:
    requested_url: str
    final_url: str = None
    status: int = None
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    redirect_chain: list = field(default_factory=list)
    error_code: str = None
    error_message: str = None
    raw_bytes: int = None
    fetch_ms: int = None
    final_nurl: object = None
    robots_block: object = None   # robots decision object when a hop was refused by robots

    @property
    def ok(self):
        return self.error_code is None

    def header(self, name):
        return self.headers.get(name.lower())


def _decompress(body, encoding, cap):
    """Bounded decompression; returns (bytes, too_large)."""
    encoding = (encoding or "identity").strip().lower()
    if encoding in ("", "identity"):
        return body, len(body) > cap
    if encoding not in ("gzip", "deflate", "x-gzip"):
        raise FetchError("unsupported_content_encoding", f"Unsupported encoding {encoding}.")
    wbits = 16 + zlib.MAX_WBITS if encoding in ("gzip", "x-gzip") else zlib.MAX_WBITS
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(body, cap + 1)
    except zlib.error:
        raise FetchError("decode_error", "Compressed body is corrupt.")
    return out, len(out) > cap or bool(d.unconsumed_tail)


class SafeFetcher:
    def __init__(self, resolver, transport, clock, limits=Limits(), budget=None):
        self.resolver = resolver          # BudgetedResolver
        self.transport = transport
        self.clock = clock
        self.limits = limits
        self.budget = budget or HttpBudget(limits.max_requests)
        self.request_log = []
        self._last_by_host = {}
        self._job_start = clock.monotonic()
        self.pinned = {}                  # host -> ip actually used

    # -- policy -------------------------------------------------------------
    def approve(self, url):
        """Validate URL, resolve within budget, check every address. Returns (nurl, ip)."""
        nurl = normalize_url(url, self.limits.max_url_length)
        addrs = self.resolver.resolve(nurl.host)
        ok, why = check_all(addrs)
        if not ok:
            raise InputRejected("blocked_destination", "This address cannot be checked.", reason=why)
        ip = self.pinned.setdefault(nurl.host, addrs[0])
        return nurl, ip

    def _respect_rate(self, host):
        last = self._last_by_host.get(host)
        if last is not None:
            wait = self.limits.min_host_interval_s - (self.clock.monotonic() - last)
            self.clock.sleep(wait)
        if self.clock.monotonic() - self._job_start >= self.limits.job_timeout_s:
            raise JobTimeout("job_timeout", "Job time limit reached.")

    # -- fetch --------------------------------------------------------------
    def fetch(self, url, method="GET", purpose="page", follow_redirects=True,
              max_bytes=None, robots_gate=None, allowed_hosts=None):
        """robots_gate(nurl) -> decision with .allowed; None for robots.txt itself.
        allowed_hosts: if set, a hop to any other host stops before DNS or any request."""
        max_bytes = max_bytes or self.limits.max_body_bytes
        res = FetchResult(requested_url=url)
        current = url
        start = self.clock.monotonic()
        for hop in range(self.limits.max_redirects + 1):
            if allowed_hosts is not None:
                try:
                    host = normalize_url(current, self.limits.max_url_length).host
                except InputRejected as e:
                    return self._fail(res, e.code, e.message)
                if host not in allowed_hosts:
                    return self._fail(res, "redirect_off_site", "Redirect leaves the checked site.")
            try:
                nurl, ip = self.approve(current)
            except InputRejected as e:
                code = "redirect_to_blocked_destination" if hop and e.code == "blocked_destination" else e.code
                return self._fail(res, code if hop else e.code, e.message)
            except CheckError as e:
                return self._fail(res, e.code, e.message)
            if robots_gate is not None:
                try:
                    decision = robots_gate(nurl)
                except CheckError as e:
                    return self._fail(res, e.code, e.message)
                if not decision.allowed:
                    res.robots_block = decision
                    res.final_nurl = nurl
                    return self._fail(res, decision.code, decision.message)
            try:
                raw = self._send(method, nurl, ip, purpose if hop == 0 else "redirect", max_bytes)
            except CheckError as e:
                return self._fail(res, e.code, e.message)
            location = raw.header("location")
            if follow_redirects and raw.status in (301, 302, 303, 307, 308) and location:
                try:
                    nxt = urljoin(nurl.url, location)
                except ValueError:  # untrusted Location such as "http://[bad"
                    res.redirect_chain.append({"url": nurl.url, "http_status": raw.status, "location": None})
                    return self._fail(res, "invalid_redirect_location", "Redirect Location is not a valid URL.")
                res.redirect_chain.append({"url": nurl.url, "http_status": raw.status, "location": nxt})
                current = nxt
                continue
            if res.redirect_chain:
                res.redirect_chain.append({"url": nurl.url, "http_status": raw.status, "location": location})
            res.final_url, res.final_nurl, res.status = nurl.url, nurl, raw.status
            res.headers = {k: v for k, v in raw.headers}
            res.raw_bytes = len(raw.body)
            res.fetch_ms = int((self.clock.monotonic() - start) * 1000)
            if raw.truncated:
                return self._fail(res, "response_too_large", "Response is larger than the limit.")
            try:
                body, too_large = _decompress(raw.body, raw.header("content-encoding"), max_bytes)
            except FetchError as e:
                return self._fail(res, e.code, e.message)
            if too_large:
                return self._fail(res, "response_too_large", "Decompressed response is larger than the limit.")
            res.body = body
            return res
        return self._fail(res, "too_many_redirects", "Too many redirects.")

    def _send(self, method, nurl, ip, purpose, max_bytes):
        attempts = 0
        while True:
            self._respect_rate(nurl.host)
            self.budget.take()
            entry = {"seq": len(self.request_log) + 1, "purpose": purpose, "method": method,
                     "url": nurl.url, "connect_ip": ip, "result": None}
            self.request_log.append(entry)
            self._last_by_host[nurl.host] = self.clock.monotonic()
            try:
                raw = self.transport.send(method, nurl, ip, self.limits.request_timeout_s, max_bytes)
                entry["result"] = raw.status
                return raw
            except TransportError as e:
                entry["result"] = e.code
                if e.code == "connection_failed" and attempts < self.limits.max_retries:
                    attempts += 1
                    purpose = "retry"
                    continue
                raise

    def _fail(self, res, code, message):
        res.error_code, res.error_message = code, message
        if res.fetch_ms is None:
            res.fetch_ms = 0
        return res

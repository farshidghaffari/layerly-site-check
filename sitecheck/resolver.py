"""DNS resolution with a per-job budget and cache. The cache is also the pin:
a host is resolved once per job, so a second (rebinding) answer is never used."""
import socket

from .errors import DnsBudgetExhausted, FetchError


class SystemResolver:
    """Real resolver. Not exercised by the C2-002 test suite (no external network)."""

    def resolve(self, host):
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise FetchError("dns_resolution_failed", f"Could not resolve {host}.")
        seen = []
        for info in infos:
            addr = info[4][0]
            if addr not in seen:
                seen.append(addr)
        return seen


class FixtureResolver:
    """Test resolver. answers: host -> list[str] or list[list[str]] (one list per call)."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []
        self._n = {}

    def resolve(self, host):
        self.calls.append(host)
        ans = self.answers.get(host)
        if ans is None:
            raise FetchError("dns_resolution_failed", f"Could not resolve {host}.")
        if ans and isinstance(ans[0], list):
            i = self._n.get(host, 0)
            self._n[host] = i + 1
            return list(ans[min(i, len(ans) - 1)])
        return list(ans)


class BudgetedResolver:
    def __init__(self, inner, limit):
        self.inner = inner
        self.limit = limit
        self.used = 0
        self.cache = {}

    def resolve(self, host):
        if host in self.cache:
            return self.cache[host]
        if self.used >= self.limit:
            raise DnsBudgetExhausted("dns_budget_exhausted", "DNS lookup limit reached.")
        self.used += 1
        addrs = self.inner.resolve(host)
        self.cache[host] = addrs
        return addrs

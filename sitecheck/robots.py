"""robots.txt (R2): fetched per origin before any page of that origin, no bypass,
unknown is never permission. Implements the RFC 9309 parts covered by tests: group
selection, longest match with Allow winning ties, * and $, and URI comparison per
section 2.2.2 (percent-encoded unreserved ASCII equals the plain character; reserved
characters keep their encoding; non-ASCII compares as UTF-8 percent-encoding).
A UTF-8 BOM is accepted; a body that is not UTF-8 makes the state unknown (deny)."""
import hashlib
import re
import string
from dataclasses import dataclass
from urllib.parse import quote

from .config import ROBOTS_PRODUCT_TOKEN


_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_PCT = re.compile(r"%([0-9A-Fa-f]{2})")
_KEEP = "".join(chr(c) for c in range(0x21, 0x7F))   # printable ASCII incl. % * $ and reserved


def comparison_form(value):
    """RFC 9309 2.2.2: one form for both rule patterns and request paths."""
    value = quote(value, safe=_KEEP)                   # non-ASCII and spaces -> UTF-8 %XX

    def fix(m):
        ch = chr(int(m.group(1), 16))
        return ch if ch in _UNRESERVED else "%" + m.group(1).upper()
    return _PCT.sub(fix, value)


@dataclass
class Rule:
    allow: bool
    pattern: str
    line_no: int
    line: str

    @property
    def norm(self):
        return comparison_form(self.pattern)

    def regex(self):
        p = re.escape(self.norm).replace(r"\*", ".*")
        if p.endswith(r"\$"):
            p = p[:-2] + "$"
        return re.compile(p)


def parse_robots(text, token=ROBOTS_PRODUCT_TOKEN):
    """Return the rule list that applies to `token` (or to '*' if no group names it)."""
    groups, current, last_was_agent = [], None, False
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, val = (s.strip() for s in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if not last_was_agent:
                current = {"agents": [], "rules": []}
                groups.append(current)
            current["agents"].append(val.lower())
            last_was_agent = True
        elif key in ("allow", "disallow"):
            last_was_agent = False
            if current is None or val == "":
                continue
            current["rules"].append(Rule(key == "allow", val, no, raw.strip()))
        else:
            last_was_agent = False
    mine = [g for g in groups if any(a == token for a in g["agents"])]
    chosen = mine or [g for g in groups if "*" in g["agents"]]
    return [r for g in chosen for r in g["rules"]]


def match(rules, path):
    """Return (allowed, rule or None)."""
    best = None
    path = comparison_form(path)
    for r in rules:
        if r.regex().match(path):
            if best is None or len(r.norm) > len(best.norm) or (
                    len(r.norm) == len(best.norm) and r.allow and not best.allow):
                best = r
    if best is None:
        return True, None
    return best.allow, best


@dataclass
class RobotsState:
    origin: str
    state: str                 # fetched | absent | access_denied | unknown | not_fetched
    http_status: int = None
    reason: str = None
    rules: list = None
    robots_url: str = None
    body_sha256: str = None
    fetched_at: str = None


@dataclass
class RobotsDecision:
    allowed: bool
    code: str = None           # robots_disallowed | robots_unavailable | request_budget_exhausted
    message: str = None
    state: RobotsState = None
    rule: Rule = None


class RobotsManager:
    def __init__(self, fetcher, limits, clock):
        self.fetcher, self.limits, self.clock = fetcher, limits, clock
        self.by_origin = {}

    def _load(self, nurl):
        origin = nurl.origin
        if origin in self.by_origin:
            return self.by_origin[origin]
        robots_url = origin + "/robots.txt"
        res = self.fetcher.fetch(robots_url, purpose="robots", max_bytes=self.limits.max_robots_bytes,
                                 robots_gate=None)
        st = RobotsState(origin=origin, state="unknown", robots_url=robots_url, fetched_at=self.clock.now_iso())
        if res.error_code == "request_budget_exhausted":
            st.state, st.reason = "not_fetched", "request_budget_exhausted"
        elif res.error_code == "dns_budget_exhausted" or res.error_code == "job_timeout":
            st.state, st.reason = "not_fetched", res.error_code
        elif res.error_code:
            st.state, st.reason = "unknown", res.error_code
        elif res.status == 200:
            st.http_status = 200
            st.body_sha256 = hashlib.sha256(res.body).hexdigest()
            try:
                text = res.body.decode("utf-8-sig")       # strips a UTF-8 BOM
            except UnicodeDecodeError:
                st.state, st.reason = "unknown", "robots_not_utf8"
            else:
                st.state, st.rules = "fetched", parse_robots(text)
        elif res.status in (404, 410):
            st.state, st.http_status = "absent", res.status
        elif res.status in (401, 403):
            st.state, st.http_status, st.reason = "access_denied", res.status, f"http_{res.status}"
        else:
            st.state, st.http_status, st.reason = "unknown", res.status, f"http_{res.status}"
        self.by_origin[origin] = st
        return st

    def gate(self, nurl):
        st = self._load(nurl)
        if st.state == "absent":
            return RobotsDecision(True, state=st)
        if st.state == "fetched":
            ok, rule = match(st.rules, nurl.path)
            if ok:
                return RobotsDecision(True, state=st, rule=rule)
            return RobotsDecision(False, "robots_disallowed", "robots.txt disallows this path.", st, rule)
        if st.state == "not_fetched":
            return RobotsDecision(False, st.reason, "robots.txt could not be requested.", st)
        return RobotsDecision(False, "robots_unavailable",
                              f"robots.txt status is {st.state} ({st.reason}); not treated as permission.", st)

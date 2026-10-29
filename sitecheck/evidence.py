"""Evidence store (architecture component [7]). Only code creates evidence."""
import hashlib
import re

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS = re.compile(r"\s+")


def clean_text(value, limit):
    """Plain, single-line, length-limited text. Consumers must still render it as text."""
    if value is None:
        return None
    s = _WS.sub(" ", _CTRL.sub("", str(value))).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class EvidenceStore:
    def __init__(self, check_id, excerpt_chars=300):
        self.check_id = check_id
        self.excerpt_chars = excerpt_chars
        self.items = {}

    def add(self, kind, url, locator, excerpt, http_status=None, fetched_at=None, body_sha256=None):
        excerpt = clean_text(excerpt, self.excerpt_chars) or ""
        key = f"{self.check_id}|{url}|{kind}|{locator}|{sha256_hex(excerpt)}"
        eid = "ev_" + sha256_hex(key)[:12]
        if eid not in self.items:
            self.items[eid] = {
                "evidence_id": eid, "kind": kind, "url": url, "locator": locator,
                "excerpt": excerpt, "http_status": http_status, "fetched_at": fetched_at,
                "body_sha256": body_sha256,
            }
        return eid

    def as_list(self):
        return list(self.items.values())

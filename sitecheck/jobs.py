"""Local job flow (stand-in for POST /checks + GET /checks/{id}): submit validates the URL,
DNS and IP policy before a job exists; Idempotency-Key never creates a second job, and the
same key with a different input is a conflict (HTTP 409 idempotency_key_conflict)."""
import json
import os
import tempfile

from .check import CheckRun, new_check_id
from .config import Limits, SCHEMA_VERSION
from .errors import FetchError, IdempotencyConflict, InputRejected
from .evidence import sha256_hex
from .ippolicy import check_all
from .resolver import BudgetedResolver
from .urlcheck import normalize_url


def _atomic_write(path, data):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


class LocalJobQueue:
    def __init__(self, resolver, transport, clock, store_dir=None, limits=Limits(), id_factory=new_check_id):
        self.resolver, self.transport, self.clock, self.limits = resolver, transport, clock, limits
        self.id_factory = id_factory
        self.store_dir = store_dir
        self.jobs, self.keys, self._dns = {}, {}, {}
        if store_dir:
            os.makedirs(os.path.join(store_dir, "checks"), exist_ok=True)
            kp = os.path.join(store_dir, "idempotency.json")
            if os.path.exists(kp):
                with open(kp, encoding="utf-8") as f:
                    self.keys = json.load(f)
            for name in os.listdir(os.path.join(store_dir, "checks")):
                with open(os.path.join(store_dir, "checks", name), encoding="utf-8") as f:
                    rec = json.load(f)
                self.jobs[rec["check_id"]] = rec

    def _save(self, rec):
        if self.store_dir:
            _atomic_write(os.path.join(self.store_dir, "checks", rec["check_id"] + ".json"), rec)
            _atomic_write(os.path.join(self.store_dir, "idempotency.json"), self.keys)

    def submit(self, url, lang="en", explain=True, idempotency_key=None):
        if lang not in ("en", "hy"):
            raise InputRejected("invalid_lang", "lang must be en or hy.")
        nurl = normalize_url(url, self.limits.max_url_length)
        fingerprint = sha256_hex(json.dumps([nurl.url, lang, bool(explain)]))
        if idempotency_key is not None:
            if not (1 <= len(idempotency_key) <= 64):
                raise InputRejected("invalid_idempotency_key", "Idempotency-Key must be 1-64 characters.")
            known = self.keys.get(idempotency_key)
            if known:
                if known["fingerprint"] != fingerprint:
                    raise IdempotencyConflict("idempotency_key_conflict",
                                              "This Idempotency-Key was already used with a different request.")
                return self._accepted(self.jobs[known["check_id"]], replay=True)
        dns = BudgetedResolver(self.resolver, self.limits.max_dns_lookups)
        try:
            addrs = dns.resolve(nurl.host)      # counted in the job's own DNS budget
        except FetchError as e:
            raise InputRejected(e.code, e.message)
        ok, why = check_all(addrs)
        if not ok:
            raise InputRejected("blocked_destination", "This address cannot be checked.", reason=why)
        check_id = self.id_factory()
        rec = {"check_id": check_id, "status": "queued", "input": {"url": url, "lang": lang, "explain": bool(explain)},
               "fingerprint": fingerprint, "created_at": self.clock.now_iso(), "report": None}
        self.jobs[check_id] = rec
        self._dns[check_id] = dns
        if idempotency_key is not None:
            self.keys[idempotency_key] = {"fingerprint": fingerprint, "check_id": check_id}
        self._save(rec)
        return self._accepted(rec, replay=False)

    def _accepted(self, rec, replay):
        return {"schema_version": SCHEMA_VERSION, "check_id": rec["check_id"], "status": rec["status"],
                "created_at": rec["created_at"], "idempotent_replay": replay}

    def run_pending(self, is_sample=False):
        for rec in list(self.jobs.values()):
            if rec["status"] != "queued":
                continue
            rec["status"] = "running"
            dns = self._dns.pop(rec["check_id"], None)
            run = CheckRun(rec["input"]["url"], resolver=self.resolver, transport=self.transport,
                           clock=self.clock, limits=self.limits, explain=rec["input"]["explain"],
                           lang=rec["input"]["lang"], check_id=rec["check_id"], is_sample=is_sample,
                           budgeted_resolver=dns)
            rec["report"] = run.run(created_at=rec["created_at"])
            rec["status"] = rec["report"]["status"]
            self._save(rec)

    def get(self, check_id):
        rec = self.jobs.get(check_id)
        if rec is None:
            raise InputRejected("check_not_found", "No check with this id.")
        if rec["report"] is not None:
            return rec["report"]
        return {"schema_version": SCHEMA_VERSION, "check_id": check_id, "status": rec["status"],
                "created_at": rec["created_at"]}

"""Report validation without third-party packages: the subset of JSON Schema used by
report.schema.json, plus integrity checks a schema cannot express."""
import json
import os
import re

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "report.schema.json")
_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def _is_type(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, _TYPES[t])


def _check(v, s, path, errs):
    types = s.get("type")
    if types is not None:
        types = types if isinstance(types, list) else [types]
        if not any(_is_type(v, t) for t in types):
            errs.append(f"{path}: expected {types}, got {type(v).__name__}")
            return
    if "enum" in s and v not in s["enum"]:
        errs.append(f"{path}: {v!r} not in {s['enum']}")
    if isinstance(v, str):
        if "pattern" in s and not re.search(s["pattern"], v):
            errs.append(f"{path}: {v!r} does not match {s['pattern']}")
        if "maxLength" in s and len(v) > s["maxLength"]:
            errs.append(f"{path}: longer than {s['maxLength']}")
    if _is_type(v, "number"):
        if "minimum" in s and v < s["minimum"]:
            errs.append(f"{path}: {v} < {s['minimum']}")
        if "maximum" in s and v > s["maximum"]:
            errs.append(f"{path}: {v} > {s['maximum']}")
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append(f"{path}: missing {k}")
        props = s.get("properties", {})
        for k, sub in v.items():
            if k in props:
                _check(sub, props[k], f"{path}.{k}", errs)
            elif s.get("additionalProperties") is False:
                errs.append(f"{path}: unexpected field {k}")
    if isinstance(v, list):
        if "minItems" in s and len(v) < s["minItems"]:
            errs.append(f"{path}: fewer than {s['minItems']} items")
        if "maxItems" in s and len(v) > s["maxItems"]:
            errs.append(f"{path}: more than {s['maxItems']} items")
        if "items" in s:
            for i, item in enumerate(v):
                _check(item, s["items"], f"{path}[{i}]", errs)


def load_schema():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


def integrity_errors(r):
    errs = []
    ev = [e["evidence_id"] for e in r["evidence"]]
    evs = set(ev)
    if len(ev) != len(evs):
        errs.append("duplicate evidence ids")
    for f in r["findings"]:
        for e in f["evidence_ids"]:
            if e not in evs:
                errs.append(f"{f['finding_id']} references missing {e}")
    for p in r["pages"]:
        for e in p["evidence_ids"]:
            if e not in evs:
                errs.append(f"page {p['url']} references missing {e}")
    for l in r["links"]:
        if l["evidence_id"] and l["evidence_id"] not in evs:
            errs.append(f"link {l['url']} references missing {l['evidence_id']}")
        if l["status"] in ("broken", "error", "blocked") and not l["evidence_id"]:
            errs.append(f"link {l['url']} is {l['status']} without evidence")
        if l["status"] == "not_checked" and (l["http_status"] is not None or not l["reason"]):
            errs.append(f"link {l['url']} not_checked must have reason and no status")
    fids = [f["finding_id"] for f in r["findings"]]
    if len(fids) != len(set(fids)):
        errs.append("duplicate finding ids")
    c = r["coverage"]
    if c["requests_used"] != len(r["request_log"]):
        errs.append("requests_used differs from request_log length")
    if c["requests_used"] > c["requests_limit"] or c["dns_lookups_used"] > c["dns_lookups_limit"]:
        errs.append("a budget was exceeded")
    if c["pages_selected"] != len(r["pages"]):
        errs.append("pages_selected differs from pages")
    if c["pages_fetched"] + c["pages_failed"] + c["pages_skipped"] != c["pages_selected"]:
        errs.append("page counts do not add up")
    if c["links_found"] != len(r["links"]) or c["links_checked"] + c["links_not_checked"] != c["links_found"]:
        errs.append("link counts do not add up")
    if sum(c["links_not_checked_by_reason"].values()) != c["links_not_checked"]:
        errs.append("links_not_checked_by_reason does not add up")
    if r["status"] == "complete" and (c["links_not_checked"] or c["checks_not_run"] or c["stopped_reason"]):
        errs.append("complete report with unchecked items")
    for p in r["pages"]:
        if p["fetch_status"] != "ok" and p["measured"] is not None:
            errs.append(f"page {p['url']} has measured data but was not fetched")
        if p["measured"]:
            m = p["measured"]
            if m["title"]["value"] is None and m["title"]["length"] != 0:
                errs.append(f"page {p['url']} title length without value")
            if m["h1"]["count"] != len(m["h1"]["values"]):
                errs.append(f"page {p['url']} h1 count mismatch")
    x = r["explanation"]
    if x["status"] != "ok" and x["items"]:
        errs.append("explanation items present although status is not ok")
    if x["status"] == "ok" and not x["items"]:
        errs.append("explanation ok without items")
    if x["is_test"] and not r["is_sample"]:
        errs.append("TEST explanation on a report that is not a sample")
    fd_ev = {f["finding_id"]: set(f["evidence_ids"]) for f in r["findings"]}
    for i, it in enumerate(x["items"]):
        linked = set()
        for fid in it["finding_ids"]:
            if fid not in fd_ev:
                errs.append(f"explanation item {i} references missing {fid}")
            linked |= fd_ev.get(fid, set())
        for e in it["evidence_ids"]:
            if e not in linked:
                errs.append(f"explanation item {i} evidence {e} is not linked to its findings")
    if r["status"] == "failed" and any(p["fetch_status"] == "ok" and p["measured"] for p in r["pages"][:1]):
        errs.append("failed report but start page was fetched")
    return errs


def validate_report(report):
    errs = []
    _check(report, load_schema(), "$", errs)
    if not errs:
        errs.extend(integrity_errors(report))
    return errs

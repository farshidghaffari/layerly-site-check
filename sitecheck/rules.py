"""Deterministic rules (architecture component [6]). Severities: info/low/medium/high.
No rule produces 'critical'. Every finding carries at least one evidence id."""


class Findings:
    def __init__(self):
        self.items = []

    def add(self, rule_id, page_url, severity, needs_context, summary, evidence_ids):
        assert severity in ("info", "low", "medium", "high")
        assert evidence_ids, "a finding without evidence is not allowed"
        self.items.append({
            "finding_id": f"fd_{len(self.items) + 1:02d}", "rule_id": rule_id, "page_url": page_url,
            "severity": severity, "needs_context": needs_context, "summary": summary,
            "evidence_ids": list(evidence_ids),
        })


def evaluate_page(page, ex, ev, fd, limits):
    """page: report page dict (fetched); ex: htmlparse.Extracted; ev: EvidenceStore."""
    url, at, sha, st = page["final_url"], page["fetched_at"], page["body_sha256"], page["http_status"]
    m = page["measured"]

    if st >= 400:
        e = ev.add("http_status", url, "status-line", f"HTTP {st}", st, at, sha)
        fd.add("http.status", url, "high", False, f"Page returned HTTP {st}.", [e])

    chain = page["redirect_chain"]
    if chain:
        hops = len(chain) - 1
        text = "; ".join(f"{h['http_status']} {h['url']} -> {h['location']}" for h in chain[:-1])
        e = ev.add("http_redirect", page["url"], "header:Location", text, chain[0]["http_status"], at, None)
        temporary = any(h["http_status"] in (302, 303, 307) for h in chain[:-1])
        if hops >= 3:
            fd.add("http.redirect_chain", page["url"], "low", False, f"Redirect chain has {hops} hops.", [e])
        elif temporary:
            fd.add("http.redirect_chain", page["url"], "info", True, "Redirect uses a temporary status code.", [e])
        else:
            fd.add("http.redirect_chain", page["url"], "info", False, f"Redirect chain has {hops} permanent hop(s).", [e])

    if not m["title"]["value"]:
        e = ev.add("html_absent", url, "head > title", "(no non-empty title element)", st, at, sha)
        fd.add("title.missing", url, "medium", False, "No title found in raw HTML.", [e])
    elif not (limits.title_min_chars <= m["title"]["length"] <= limits.title_max_chars):
        line = ex.titles[0][1]
        e = ev.add("html_element", url, f"title (line {line})", m["title"]["value"], st, at, sha)
        fd.add("title.length", url, "info", True, f"Title is {m['title']['length']} characters long.", [e])

    if not m["meta_description"]["value"]:
        e = ev.add("html_absent", url, "head > meta[name=description]", "(no non-empty meta description)", st, at, sha)
        fd.add("meta_description.missing", url, "low", False, "No meta description found in raw HTML.", [e])

    h1 = m["h1"]
    if h1["count"] == 0:
        e = ev.add("html_absent", url, "h1", "(no h1 element)", st, at, sha)
        fd.add("h1.count", url, "low", False, "Page has no H1 element.", [e])
    elif h1["count"] > 1:
        e = ev.add("html_element", url, f"h1 ({h1['count']} matches)", " | ".join(h1["values"]), st, at, sha)
        fd.add("h1.count", url, "info", True, f"Page has {h1['count']} H1 elements.", [e])

    can = m["canonical"]
    if not can["values"]:
        e = ev.add("html_absent", url, "head > link[rel=canonical]", "(no canonical link)", st, at, sha)
        fd.add("canonical.missing", url, "info", True, "No canonical link found.", [e])
    else:
        lines = ", ".join(str(l) for _, l in ex.canonicals)
        e = ev.add("html_element", url, f"link[rel=canonical] (line {lines})", " | ".join(can["values"]), st, at, sha)
        if can["invalid"]:
            fd.add("canonical.invalid", url, "medium", False, "A canonical link is not a valid http(s) URL.", [e])
        elif len(can["values"]) > 1:
            fd.add("canonical.multiple", url, "medium", False, f"{len(can['values'])} canonical links found.", [e])
        elif not can["is_self"]:
            fd.add("canonical.points_elsewhere", url, "medium", True, "Canonical points to a different URL.", [e])
        ts = can["target_status"]
        if ts is not None and ts >= 400:
            fd.add("canonical.target_error", url, "medium", False, f"Canonical target returned HTTP {ts}.", [e])

    rb = m["robots"]
    if rb["meta"] and "noindex" in rb["meta"].lower():
        e = ev.add("html_element", url, "meta[name=robots]", rb["meta"], st, at, sha)
        fd.add("robots.noindex", url, "medium", True, "Page carries noindex in meta robots.", [e])
    if rb["x_robots_tag"] and "noindex" in rb["x_robots_tag"].lower():
        e = ev.add("http_header", url, "header:X-Robots-Tag", rb["x_robots_tag"], st, at, sha)
        fd.add("robots.noindex", url, "medium", True, "Page carries noindex in X-Robots-Tag header.", [e])

    for line, err in page["_jsonld_errors"]:
        e = ev.add("jsonld_parse_error", url, f"script[type=application/ld+json] (line {line})", err, st, at, sha)
        fd.add("jsonld.invalid", url, "medium", False, "A JSON-LD block is not valid JSON.", [e])
    if m["json_ld"]["blocks"] == 0:
        e = ev.add("html_absent", url, "script[type=application/ld+json]", "(no JSON-LD block)", st, at, sha)
        fd.add("jsonld.none", url, "info", False, "No JSON-LD block found.", [e])

    if m["text_chars"] < limits.low_text_chars:
        e = ev.add("text_stats", url, "visible text in raw HTML", f"{m['text_chars']} characters", st, at, sha)
        fd.add("content.low_text", url, "info", True,
               f"Raw HTML has {m['text_chars']} visible text characters; this alone does not prove the page is broken or JS-only.", [e])

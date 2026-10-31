"""One check job: robots-gated fetch of up to five pages, internal link checks,
rules with evidence, and JSON matching the bundled report schema."""
import base64
import secrets
from collections import deque
from urllib.parse import urljoin, urlsplit, parse_qsl, urlencode

from .config import Limits, NON_HTML_EXTENSIONS, PAGE_CONTENT_TYPES, SCHEMA_VERSION, EXTENDED_SCHEMA_VERSION, TRACKING_PARAMS
from .errors import InputRejected
from .evidence import EvidenceStore, clean_text, sha256_hex
from .fetcher import SafeFetcher
from .htmlparse import jsonld_summary, parse_html
from .resolver import BudgetedResolver
from .robots import RobotsManager
from .rules import Findings, evaluate_page
from .urlcheck import normalize_url

PARTIAL_REASONS = {"request_budget_exhausted", "dns_budget_exhausted", "job_timeout"}
DISCLAIMER = ("Automated check of raw HTML for up to 5 pages of one site. Not a ranking, traffic or "
              "backlink measurement. Items not checked are listed in coverage.")
REPORT_RETENTION_S = 7 * 24 * 3600


def new_check_id():
    return "chk_" + base64.b32encode(secrets.token_bytes(16)).decode().rstrip("=").lower()


def _content_type(headers):
    return (headers.get("content-type") or "").split(";")[0].strip().lower()


def _charset(headers):
    for part in (headers.get("content-type") or "").split(";")[1:]:
        k, _, v = part.strip().partition("=")
        if k.lower() == "charset" and v:
            try:
                "".encode(v.strip('"'))
                return v.strip('"')
            except LookupError:
                return None
    return None


def _clean_link(base, href):
    """(url, None) for a requestable absolute http(s) URL without fragment and tracking
    params; (text, reason) for a link that must not be requested (malformed or refused
    by URL validation); None for non-web links such as mailto: or a bare fragment."""
    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    try:
        absolute = urljoin(base, href).split("#", 1)[0]
        parts = urlsplit(absolute)
        if parts.scheme not in ("http", "https"):
            return None
        q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if not k.lower().startswith(TRACKING_PARAMS)]
        absolute = parts._replace(query=urlencode(q)).geturl()
    except ValueError:      # untrusted href such as "http://[bad"
        return clean_text(href, 300), "invalid_url"
    try:
        return normalize_url(absolute).url, None
    except InputRejected as e:
        return clean_text(absolute, 300), e.code


def _is_html_path(url):
    path = urlsplit(url).path.lower()
    return not path.endswith(NON_HTML_EXTENSIONS)


class CheckRun:
    def __init__(self, url, *, resolver, transport, clock, limits=Limits(), explain=True, lang="en",
                 check_id=None, is_sample=False, budgeted_resolver=None, recursive=False):
        self.input_url, self.limits, self.clock = url, limits, clock
        if recursive and (not 1 <= limits.max_pages <= 100 or not 1 <= limits.max_requests <= 400):
            raise ValueError('Recursive checks require 1..100 pages and 1..400 HTTP attempts.')
        self.recursive = recursive
        self.explain, self.lang, self.is_sample = explain, lang, is_sample
        self.check_id = check_id or new_check_id()
        self.dns = budgeted_resolver or BudgetedResolver(resolver, limits.max_dns_lookups)
        self.fetcher = SafeFetcher(self.dns, transport, clock, limits)
        self.robots = RobotsManager(self.fetcher, limits, clock)
        self.ev = EvidenceStore(self.check_id, limits.excerpt_chars)
        self.fd = Findings()
        self.pages, self.links, self.errors, self.not_run = [], [], [], []
        self.stop_reasons = []
        self.observed = {}    # url -> http status actually observed in this check

    # ------------------------------------------------------------------
    def run(self, created_at=None):
        created_at = created_at or self.clock.now_iso()
        started_at = self.clock.now_iso()
        nurl = normalize_url(self.input_url, self.limits.max_url_length)   # raises InputRejected
        status, site_host = "failed", None

        start = self._fetch_page(nurl.url, allowed_hosts=None, is_start=True)
        start_page, start_ex = start
        if start_ex is not None:
            site_host = urlsplit(start_page["final_url"]).hostname
            status = "complete"
            candidates = []
            for href, _ in start_ex.links:
                c = _clean_link(start_page["final_url"], href)
                if not c or c[1] or urlsplit(c[0]).hostname != site_host or not _is_html_path(c[0]):
                    continue
                u = c[0]
                if u in (start_page["url"], start_page["final_url"]) or u in candidates:
                    continue
                candidates.append(u)
            selected = candidates[: self.limits.max_pages - 1]
            parsed = [start]
            for u in selected:
                parsed.append(self._fetch_page(u, allowed_hosts={site_host}, is_start=False))
            if self.recursive:
                # Reuse fetched first-level pages, then discover deeper pages breadth-first.
                parsed = self._crawl_recursive(parsed, site_host)
            self._check_links(parsed, site_host)
            for page, ex in parsed:
                if ex is not None:
                    self._finish_page(page, ex)
        finished_at = self.clock.now_iso()
        if status != "failed" and (self.not_run or self.stop_reasons or
                                   any(p["fetch_status"] == "error" for p in self.pages) or
                                   any(l["status"] == "not_checked" for l in self.links)):
            status = "partial"
        return self._report(status, nurl, site_host, created_at, started_at, finished_at)

    def _crawl_recursive(self, parsed, site_host):
        pending = deque()
        seen = {u for p, _ in parsed for u in (p['url'], p['final_url']) if u}
        scanned = 0
        excluded = False
        while scanned < len(parsed) or pending:
            while scanned < len(parsed):
                p, ex = parsed[scanned]
                scanned += 1
                if ex is None:
                    continue
                for href, _ in ex.links:
                    c = _clean_link(p['final_url'], href)
                    if not c or c[1] or urlsplit(c[0]).hostname != site_host or not _is_html_path(c[0]) or c[0] in seen:
                        continue
                    # Bound the frontier as well as actual page attempts.
                    if len(parsed) + len(pending) >= self.limits.max_pages:
                        excluded = True
                        continue
                    seen.add(c[0])
                    pending.append(c[0])
            if self.stop_reasons:
                for u in pending:
                    self.not_run.append({'page_url':u,'reason':self.stop_reasons[0]})
                break
            if not pending:
                break
            u = pending.popleft()
            if any(u in (p['url'], p['final_url']) for p, _ in parsed):
                continue
            result = self._fetch_page(u, allowed_hosts={site_host}, is_start=False)
            parsed.append(result)
            seen.update(x for x in (result[0]['url'],result[0]['final_url']) if x)
        if excluded and 'page_limit_reached' not in self.stop_reasons:
            self.stop_reasons.append('page_limit_reached')
        return parsed

    # ------------------------------------------------------------------
    def _fetch_page(self, url, allowed_hosts, is_start):
        res = self.fetcher.fetch(url, purpose="page", robots_gate=self.robots.gate, allowed_hosts=allowed_hosts)
        at = self.clock.now_iso()
        page = {"url": url, "final_url": res.final_url, "fetch_status": "ok", "http_status": res.status,
                "redirect_chain": res.redirect_chain, "content_type": None, "bytes": None,
                "fetch_ms": res.fetch_ms, "error_code": None, "measured": None, "evidence_ids": [],
                "fetched_at": at, "body_sha256": None}
        self.pages.append(page)
        if res.status is not None:
            self.observed.setdefault(res.final_url, res.status)
            self.observed.setdefault(url, res.status)
        if not res.ok:
            return self._page_failure(page, res, is_start), None
        ctype = _content_type(res.headers)
        page["content_type"] = res.headers.get("content-type")
        page["bytes"] = len(res.body)
        page["body_sha256"] = sha256_hex(res.body)
        if ctype not in PAGE_CONTENT_TYPES:
            page["fetch_status"], page["error_code"] = "error", "unsupported_content_type"
            self.errors.append({"code": "unsupported_content_type", "url": url,
                                "message": f"Content type {clean_text(ctype, 80)!r} is not HTML."})
            if not is_start:
                self.not_run.append({"page_url": url, "reason": "unsupported_content_type"})
            return page, None
        ex = parse_html(res.body, _charset(res.headers))
        page["_x_robots"] = res.headers.get("x-robots-tag")
        return page, ex

    def _page_failure(self, page, res, is_start):
        code = res.error_code
        blocked = res.robots_block
        if blocked is not None:
            page["fetch_status"] = "skipped"
            if blocked.state.state == "fetched" and blocked.rule is not None:
                st = blocked.state
                e = self.ev.add("robots_txt_rule", st.robots_url, f"robots.txt line {blocked.rule.line_no}",
                                blocked.rule.line, 200, st.fetched_at, st.body_sha256)
                page["evidence_ids"].append(e)
                self.fd.add("robots_txt.disallowed", res.final_nurl.url if res.final_nurl else page["url"],
                            "medium", True, "robots.txt disallows this page for our user agent; it was not requested.", [e])
            elif blocked.state.state in ("unknown", "access_denied"):
                st = blocked.state
                e = self.ev.add("robots_txt_status", st.robots_url, "robots.txt response",
                                f"state={st.state}; reason={st.reason}", st.http_status, st.fetched_at, None)
                page["evidence_ids"].append(e)
            if is_start and code == "robots_disallowed":
                code = "start_page_robots_disallowed"
        else:
            page["fetch_status"] = "error"
        page["error_code"] = code
        if code in PARTIAL_REASONS:
            page["fetch_status"] = "skipped"
            if code not in self.stop_reasons:
                self.stop_reasons.append(code)
        self.errors.append({"code": code, "url": page["url"], "message": clean_text(res.error_message, 200)})
        if not is_start:
            self.not_run.append({"page_url": page["url"], "reason": code})
        return page

    def _check_links(self, parsed, site_host):
        page_urls = set()
        for p, _ in parsed:
            page_urls.update(u for u in (p["url"], p["final_url"]) if u)
        seen = set()
        for page, ex in parsed:
            if ex is None:
                continue
            for href, _line in ex.links:
                c = _clean_link(page["final_url"], href)
                if not c or c[0] in page_urls or c[0] in seen:
                    continue
                u, why = c
                seen.add(u)
                link = {"url": u, "source_page": page["final_url"], "method": None, "status": "not_checked",
                        "http_status": None, "evidence_id": None, "reason": None}
                self.links.append(link)
                if why:                      # never requested
                    link["reason"] = why
                    continue
                if urlsplit(u).hostname != site_host:
                    link["reason"] = "external_not_checked"
                    continue
                self._check_one_link(link, site_host)

    def _check_one_link(self, link, site_host):
        f = self.fetcher
        res = f.fetch(link["url"], method="HEAD", purpose="link", follow_redirects=False,
                      robots_gate=self.robots.gate, allowed_hosts={site_host})
        link["method"] = "HEAD"
        if res.ok and res.status in (405, 501):
            res = f.fetch(link["url"], method="GET", purpose="link", follow_redirects=False,
                          robots_gate=self.robots.gate, allowed_hosts={site_host})
            link["method"] = "GET"
        if res.robots_block is not None:
            link["method"] = None
            link["reason"] = res.error_code
            if res.error_code in PARTIAL_REASONS and res.error_code not in self.stop_reasons:
                self.stop_reasons.append(res.error_code)
            return
        if not res.ok and res.status is None:
            if res.error_code in PARTIAL_REASONS:
                link["method"], link["reason"] = None, res.error_code
                if res.error_code not in self.stop_reasons:
                    self.stop_reasons.append(res.error_code)
                return
            link["status"], link["reason"] = "error", res.error_code
            link["evidence_id"] = self.ev.add("link_check", link["url"], f"a[href] on {link['source_page']}",
                                              f"{link['method']} -> {res.error_code}", None, self.clock.now_iso(), None)
            return
        link["http_status"] = res.status
        self.observed.setdefault(link["url"], res.status)
        if res.status >= 400:
            link["status"] = "broken"
            link["evidence_id"] = self.ev.add("link_check", link["url"], f"a[href] on {link['source_page']}",
                                              f"{link['method']} -> {res.status}", res.status, self.clock.now_iso(), None)
            self.fd.add("links.broken", link["source_page"], "medium", False,
                        f"Tested link returned HTTP {res.status}.", [link["evidence_id"]])
        elif 300 <= res.status < 400:
            link["status"] = "redirect"
        else:
            link["status"] = "ok"

    def _finish_page(self, page, ex):
        title = ex.titles[0][0] if ex.titles else None
        desc = next((c for c, _ in ex.descriptions if c.strip()), None)
        canon_norm, invalid = [], 0
        for h, _ in ex.canonicals:
            if not h:
                continue
            try:
                joined = urljoin(page["final_url"], h)
            except ValueError:      # untrusted href such as "http://[bad"
                canon_norm.append(clean_text(h, 300))
                invalid += 1
                continue
            try:
                canon_norm.append(normalize_url(joined).url)
            except InputRejected:
                canon_norm.append(clean_text(joined, 300))
                invalid += 1
        is_self = len(canon_norm) == 1 and not invalid and canon_norm[0] == page["final_url"]
        target = canon_norm[0] if len(canon_norm) == 1 and not invalid else None
        target_status = self.observed.get(target) if target else None
        jl, jl_errors = jsonld_summary(ex.jsonld)
        page["measured"] = {
            "title": {"value": clean_text(title, 300) if title else None, "length": len(title) if title else 0},
            "meta_description": {"value": clean_text(desc, 300) if desc else None, "length": len(desc) if desc else 0},
            "h1": {"count": len(ex.h1), "values": [clean_text(t, 200) for t, _ in ex.h1]},
            "canonical": {"values": canon_norm, "is_self": is_self, "invalid": invalid,
                          "target_checked": target_status is not None, "target_status": target_status},
            "robots": {"meta": ex.meta_robots[0][0] if ex.meta_robots else None,
                       "x_robots_tag": page.pop("_x_robots", None), "robots_txt_allowed": True},
            "json_ld": jl,
            "text_chars": ex.text_chars,
            "forms_found": ex.forms,
        }
        page["_jsonld_errors"] = jl_errors
        before = len(self.ev.items)
        evaluate_page(page, ex, self.ev, self.fd, self.limits)
        page["evidence_ids"] = list(self.ev.items)[before:]
        page.pop("_jsonld_errors")

    # ------------------------------------------------------------------
    def _report(self, status, nurl, site_host, created_at, started_at, finished_at):
        for p in self.pages:
            p.pop("_x_robots", None)
        robots_states = [{"origin": s.origin, "state": s.state, "http_status": s.http_status, "reason": s.reason}
                         for s in self.robots.by_origin.values()]
        start_robots = self.robots.by_origin.get(nurl.origin)
        links_checked = sum(1 for l in self.links if l["status"] != "not_checked")
        not_checked_by_reason = {}
        for l in self.links:
            if l["status"] == "not_checked":
                not_checked_by_reason[l["reason"]] = not_checked_by_reason.get(l["reason"], 0) + 1
        coverage = {
            "site_host": site_host,
            "pages_selected": len(self.pages),
            "pages_fetched": sum(1 for p in self.pages if p["fetch_status"] == "ok"),
            "pages_failed": sum(1 for p in self.pages if p["fetch_status"] == "error"),
            "pages_skipped": sum(1 for p in self.pages if p["fetch_status"] == "skipped"),
            "requests_used": self.fetcher.budget.used,
            "requests_limit": self.limits.max_requests,
            "dns_lookups_used": self.dns.used,
            "dns_lookups_limit": self.limits.max_dns_lookups,
            "links_found": len(self.links),
            "links_checked": links_checked,
            "links_not_checked": len(self.links) - links_checked,
            "links_not_checked_by_reason": not_checked_by_reason,
            "robots_txt": start_robots.state if start_robots else "not_fetched",
            "robots_origins": robots_states,
            "stopped_reason": self.stop_reasons[0] if self.stop_reasons else None,
            "checks_not_run": self.not_run,
        }
        explanation = {"status": "not_available" if self.explain else "disabled", "lang": self.lang, "items": [],
                       "reason": None, "is_test": False}
        report = {
            "schema_version": EXTENDED_SCHEMA_VERSION if self.recursive else SCHEMA_VERSION,
            "is_sample": self.is_sample,
            "check_id": self.check_id,
            "status": status,
            "input": {"url": self.input_url, "normalized_url": nurl.url, "lang": self.lang},
            "created_at": created_at, "started_at": started_at, "finished_at": finished_at,
            "expires_at": self.clock.iso_after(REPORT_RETENTION_S),
            "limits": {"max_pages": self.limits.max_pages, "max_requests": self.limits.max_requests,
                       "max_dns_lookups": self.limits.max_dns_lookups,
                       "request_timeout_ms": int(self.limits.request_timeout_s * 1000),
                       "job_timeout_ms": int(self.limits.job_timeout_s * 1000),
                       "max_body_bytes": self.limits.max_body_bytes},
            "coverage": coverage,
            "pages": self.pages,
            "links": self.links,
            "findings": self.fd.items,
            "evidence": self.ev.as_list(),
            "explanation": explanation,
            "errors": self.errors,
            "request_log": self.fetcher.request_log,
            "disclaimer": DISCLAIMER.replace('up to 5 pages', f'up to {self.limits.max_pages} pages'),
        }
        if self.is_sample:
            report["sample_note"] = "SAMPLE ONLY - generated from local fixtures with a fake resolver and transport; no real network request was made."
        return report


def run_check(url, **kw):
    return CheckRun(url, **kw).run()

"""Deterministic extraction from raw HTML (architecture component [5]).
No JavaScript runs; page text is untrusted data and is only measured, never obeyed."""
import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

_WS = re.compile(r"\s+")
_HIDDEN = {"script", "style", "noscript", "template", "head"}


@dataclass
class Extracted:
    titles: list = field(default_factory=list)          # [(text, line)]
    descriptions: list = field(default_factory=list)    # [(content, line)]
    meta_robots: list = field(default_factory=list)     # [(content, line)]
    h1: list = field(default_factory=list)              # [(text, line)]
    canonicals: list = field(default_factory=list)      # [(href, line)]
    jsonld: list = field(default_factory=list)          # [(raw, line)]
    links: list = field(default_factory=list)           # [(href, line)]
    forms: int = 0
    text_chars: int = 0


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = Extracted()
        self._stack = []
        self._capture = None      # ("title"|"h1"|"jsonld", line, [parts])
        self._text = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        line = self.getpos()[0]
        if tag not in ("meta", "link", "br", "img", "input", "hr", "base"):
            self._stack.append(tag)
        if tag == "title" and self._capture is None:
            self._capture = ("title", line, [])
        elif tag == "h1" and self._capture is None:
            self._capture = ("h1", line, [])
        elif tag == "script" and a.get("type", "").split(";")[0].strip().lower() == "application/ld+json":
            self._capture = ("jsonld", line, [])
        elif tag == "meta":
            name = a.get("name", "").strip().lower()
            if name == "description":
                self.out.descriptions.append((a.get("content", ""), line))
            elif name == "robots":
                self.out.meta_robots.append((a.get("content", ""), line))
        elif tag == "link" and "canonical" in a.get("rel", "").lower().split():
            self.out.canonicals.append((a.get("href", "").strip(), line))
        elif tag == "a" and "href" in a:
            self.out.links.append((a["href"].strip(), line))
        elif tag == "form":
            self.out.forms += 1

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()

    def handle_endtag(self, tag):
        if self._capture and self._capture[0] == ("jsonld" if tag == "script" else tag):
            kind, line, parts = self._capture
            text = "".join(parts)
            if kind == "title":
                self.out.titles.append((_WS.sub(" ", text).strip(), line))
            elif kind == "h1":
                self.out.h1.append((_WS.sub(" ", text).strip(), line))
            else:
                self.out.jsonld.append((text.strip(), line))
            self._capture = None
        if tag in self._stack:
            while self._stack and self._stack.pop() != tag:
                pass

    def handle_data(self, data):
        if self._capture:
            self._capture[2].append(data)
        if not any(t in _HIDDEN for t in self._stack):
            self._text.append(data)

    def close(self):
        super().close()
        self.out.text_chars = len(_WS.sub(" ", "".join(self._text)).strip())


def parse_html(body_bytes, charset=None):
    text = body_bytes.decode(charset or "utf-8", "replace")
    p = _Parser()
    p.feed(text)
    p.close()
    return p.out


def jsonld_summary(blocks):
    valid, invalid, types, errors = 0, 0, [], []
    for raw, line in blocks:
        try:
            data = json.loads(raw)
        except ValueError:
            # Python's own message and error position differ between versions (3.12 vs 3.13),
            # so the evidence text is version-independent: a fixed label plus the block start.
            invalid += 1
            errors.append((line, "Invalid JSON; block starts: " + " ".join(raw.split())[:120]))
            continue
        valid += 1
        stack = [data]
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                stack.extend(reversed(item))
            elif isinstance(item, dict):
                t = item.get("@type")
                for v in (t if isinstance(t, list) else [t]):
                    if isinstance(v, str) and v not in types:
                        types.append(v)
                if "@graph" in item:
                    stack.append(item["@graph"])
    return {"blocks": len(blocks), "valid": valid, "invalid": invalid, "types": types}, errors

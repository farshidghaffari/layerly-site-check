"""Local fixtures: fake DNS answers and fake HTTP responses. Nothing here touches the network.
The IP addresses are public-looking values used only as labels for the fake transport."""
import json

from .check import CheckRun
from .clock import FakeClock
from .config import Limits
from .resolver import FixtureResolver
from .transport import FixtureResponse, FixtureTransport, TransportError

IP_SITE = "93.184.215.14"
IP_OTHER = "93.184.215.15"
HTML = {"content-type": "text/html; charset=utf-8"}
TEXT = {"content-type": "text/plain"}


def page(title="Example Industrial Pumps", desc="Industrial pump supply and service.", h1=("Industrial Pumps",),
         canonical=None, links=(), jsonld=(), body_text=None, head_extra="", body_extra=""):
    parts = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"]
    if title is not None:
        parts.append(f"<title>{title}</title>")
    if desc is not None:
        parts.append(f'<meta name="description" content="{desc}">')
    if canonical:
        parts.append(f'<link rel="canonical" href="{canonical}">')
    for block in jsonld:
        parts.append(f'<script type="application/ld+json">{block}</script>')
    parts.append(head_extra + "</head><body>")
    for h in h1:
        parts.append(f"<h1>{h}</h1>")
    text = body_text if body_text is not None else (
        "We supply, install and service industrial pumps for water treatment, mining and food plants. " * 4)
    parts.append(f"<p>{text}</p><nav>")
    for href, label in links:
        parts.append(f'<a href="{href}">{label}</a>')
    parts.append("</nav>" + body_extra + "</body></html>")
    return "".join(parts).encode("utf-8")


def ok(body, headers=HTML, latency=0.05):
    return FixtureResponse(200, dict(headers), body, latency)


def redirect(location, status=301):
    return FixtureResponse(status, {"location": location, "content-type": "text/html"}, b"")


def make(dns, routes, limits=Limits()):
    clock = FakeClock()
    resolver = FixtureResolver(dns)
    transport = FixtureTransport(routes, clock, limits.request_timeout_s)
    return resolver, transport, clock


def run(url, dns, routes, limits=Limits(), check_id="chk_fixture_0001", explain=True, is_sample=True):
    resolver, transport, clock = make(dns, routes, limits)
    run_ = CheckRun(url, resolver=resolver, transport=transport, clock=clock, limits=limits,
                    explain=explain, check_id=check_id, is_sample=is_sample)
    report = run_.run()
    return report, transport, resolver, run_


ROBOTS = b"User-agent: *\nDisallow: /private/\nAllow: /\n"
H = "www.example.com"


def sample_scenario():
    """Fixture behind the sample in C2-001-API-CONTRACT v0.2."""
    home = page(
        title="Example Industrial Pumps | Home",
        h1=("Industrial Pumps", "Service Across the Region"),
        canonical="https://www.example.com/",
        jsonld=('{"@context":"https://schema.org","@type":"Organization","name":"Example Pumps"}',
                '{"@context":"https://schema.org","@type":"LocalBusiness",}'),
        links=(("/services/", "Services"), ("/contact/", "Contact"), ("/private/", "Partner area"),
               ("/about/", "About"), ("/old-catalog/", "Old catalog"), ("/privacy/", "Privacy"),
               ("/blog/", "Blog"), ("/files/catalog.pdf", "Catalog PDF"),
               ("https://example.org/partner", "Partner"), ("mailto:info@example.com", "Email")))
    services = page(title="Services | Example Industrial Pumps", desc=None, h1=("Our Services",),
                    canonical="/services", links=(("/", "Home"), ("/old-catalog/", "Old catalog")))
    about = page(title="About", h1=("About us",), canonical="https://www.example.com/about/",
                 head_extra='<meta name="robots" content="noindex, follow">',
                 body_text="Family business since 1998.",
                 body_extra='<form action="/subscribe" method="post"><input name="email"></form>')
    routes = {
        ("http", H, "/robots.txt"): redirect("https://www.example.com/robots.txt"),
        ("https", H, "/robots.txt"): ok(ROBOTS, TEXT),
        ("http", H, "/"): redirect("https://www.example.com/"),
        ("https", H, "/"): ok(home),
        ("https", H, "/services/"): ok(services),
        ("https", H, "/contact/"): TransportError("fetch_timeout", "No response within the time limit."),
        ("https", H, "/about/"): ok(about),
        ("https", H, "/old-catalog/"): FixtureResponse(404, dict(HTML), b"<title>Not found</title>"),
        ("https", H, "/privacy/"): ok(page(title="Privacy")),
        ("https", H, "/blog/"): redirect("https://www.example.com/news/"),
        ("https", H, "/files/catalog.pdf"): FixtureResponse(200, {"content-type": "application/pdf"}, b"%PDF-1.4"),
    }
    return {H: [IP_SITE]}, routes


def run_sample(check_id="chk_sample_0001"):
    dns, routes = sample_scenario()
    report, transport, _, _ = run("http://www.example.com", dns, routes, check_id=check_id)
    return report, transport


def _robots_start_disallowed():
    routes = {(H, "/robots.txt"): ok(b"User-agent: *\nDisallow: /\n", TEXT), (H, "/"): ok(page())}
    return run("https://www.example.com/", {H: [IP_SITE]}, routes)[0]


def _ssrf_redirect():
    routes = {(H, "/robots.txt"): FixtureResponse(404, dict(TEXT), b""),
              (H, "/"): redirect("http://metadata.internal.example.com/latest/")}
    return run("https://www.example.com/", {H: [IP_SITE], "metadata.internal.example.com": ["169.254.169.254"]}, routes)[0]


def _budget():
    links = tuple((f"/p{i}/", f"P{i}") for i in range(40))
    routes = {(H, "/robots.txt"): FixtureResponse(404, dict(TEXT), b""), (H, "/"): ok(page(links=links))}
    for i in range(40):
        routes[(H, f"/p{i}/")] = ok(page(title=f"Page {i} of the example site"))
    return run("https://www.example.com/", {H: [IP_SITE]}, routes)[0]


SCENARIOS = {
    "sample": lambda: run_sample()[0],
    "robots_disallow_start": _robots_start_disallowed,
    "ssrf_redirect": _ssrf_redirect,
    "budget": _budget,
}


def run_scenario(name):
    if name not in SCENARIOS:
        raise SystemExit(f"unknown scenario {name}; try: {', '.join(sorted(SCENARIOS))}")
    return SCENARIOS[name]()


if __name__ == "__main__":
    print(json.dumps(run_scenario("sample"), indent=2))

# Layerly Site Check

**A small, inspectable website checker. Five pages. Evidence behind every observation. No model API.**

[Try the hosted checker](https://layerly.net/website-check/) · [Sample report](examples/sample-report.json) · [فارسی](README.fa.md)

Layerly Site Check examines public HTML for basic technical SEO observations, with explicit crawl limits and machine-readable evidence. It is useful for developers, technical marketers and agencies who want a reproducible first look before a deeper audit.

```text
Public URL → URL/IP validation → robots gate → bounded crawl → rules → JSON evidence
```

The standalone tool runs locally. It does not send your reports to Layerly, use an AI service, require an email address or call a commercial SEO API. Live checks contact the requested website and its DNS/redirect destinations, subject to the checks below.

## Start in 30 seconds

Python 3.11–3.13; no third-party runtime dependencies. This project is distributed through GitHub, not yet published on PyPI.

```bash
git clone https://github.com/farshidghaffari/layerly-site-check.git
cd layerly-site-check
python -m sitecheck demo --out sample.json
python -m sitecheck validate sample.json
```

The demo uses synthetic fixtures and makes **no network requests**. All committed reports in `examples/` are fixture examples, not customer audits.

To check a public website you are authorised to test:

```bash
python -m sitecheck check https://your-company.example/ --live --out report.json
```

Replace the example address. Without `--live`, the command refuses to make requests. Optionally install the local package with `python -m pip install .` and use `layerly-check` instead of `python -m sitecheck`.

## Use the AI review skill

The optional [Layerly SEO Basics skill](skills/layerly-seo-basics/SKILL.md) helps an AI assistant interpret the JSON report, distinguish observations from defects, and propose fixes tied to evidence.

Start with the offline demo, then give your assistant the skill and the generated report. It can also interpret an existing report without running code. A repository link alone does not grant execution or account access. The checker still makes no model API calls; your chosen assistant's capabilities and charges are separate.

See the [step-by-step guide and copyable prompts](docs/AI-REVIEW.md). The skill does not automatically edit websites, send reports or expand the crawl.

## What it checks

- Titles, descriptions and H1s.
- Canonical links, indexing directives and JSON-LD syntax/presence.
- Internal links within the crawl budget.
- Evidence excerpts, checked pages, request counts and reasons for missing coverage.

`INFO` means an observation, not necessarily a defect. For example, a page without JSON-LD is not automatically an SEO error. Severity is a review priority, not a forecast of ranking impact.

## Limits you can see

| Boundary | Default |
|---|---:|
| Selected HTML pages | 5 |
| HTTP attempts, including robots, redirects and retries | 20 |
| DNS lookups | 30 |
| Redirect hops per chain | 5 |
| Per-request timeout | 10 seconds |
| Job timeout checked by the crawler | 60 seconds |
| Decompressed page body | 2 MiB |
| Minimum interval per host | 0.5 seconds |

The in-process job timer is not an OS-level execution deadline; the hosted service adds a subprocess deadline. The core validates URL forms and public IPs, checks redirects at each hop, pins approved DNS addresses, verifies TLS, ignores environment proxy settings, limits decompression and respects its tested robots rules. This is a set of tested controls, not a claim of complete SSRF protection or full RFC conformance. See [SECURITY.md](SECURITY.md).

## Read the result correctly

The JSON report contains `status`, `coverage`, `pages`, `findings`, `evidence`, and a disabled/unavailable explanation field retained for schema compatibility. A finding refers to explicit `evidence_ids`.

`partial` means that some coverage is missing. External links are intentionally not requested; their presence can make a report partial even when all five selected pages return 200. The tool does not render JavaScript, measure rankings, traffic, backlinks or AI citations, or guarantee a business result. A five-page check cannot establish the health of an entire site.

Reports are local files, not automatically deleted or encrypted. They can contain submitted URLs, excerpts and diagnostic connection addresses. Review/redact them before sharing. The `expires_at` metadata is a suggested report lifetime; the CLI does not run a deletion service.

## Docker

```bash
docker build -t layerly-site-check .
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m layerly-site-check demo
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --pids-limit 48 --memory 512m layerly-site-check check https://your-company.example/ --live
```

The image runs as an unprivileged user and publishes no server port. Docker resource limits are an additional boundary; use suitable network isolation if you integrate the core into a service. This repository does **not** provide a public URL-fetching API.

## Tests and contributions

```bash
python -m unittest discover -s tests -v
```

Tests use fixtures and temporary loopback servers; they do not crawl external websites. The two TLS tests need an `openssl` executable and are explicitly skipped if it is absent. `jsonschema` is an optional additional validation check; the runtime uses its own validator.

GitHub Actions is configured for Linux/Python 3.11, 3.12 and 3.13. The workflow must run successfully before a CI result can be claimed. See [CONTRIBUTING.md](CONTRIBUTING.md), [validation notes](docs/VALIDATION.md) and [changelog](CHANGELOG.md).

## Hosted service and professional help

The [Layerly website](https://layerly.net/) hosts a separately operated checker with verified email and private report links. Email delivery, customer records, credentials, site assets and production deployment configuration are excluded from this repository. Hosted request limits and retention differ from this standalone CLI.

Need someone to interpret the evidence and implement the fixes? [Request a human review](https://layerly.net/website-check/#request). Layerly works on technical SEO, search/AI discoverability and editorial outreach for industrial and technical businesses. No ranking or citation guarantees.

## License

MIT. See [LICENSE](LICENSE). Contributions are welcome; no response-time or support commitment is implied.

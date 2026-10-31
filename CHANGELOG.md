# Changelog

## 0.2.0 - 2026-10-31

- Add opt-in `--max-pages 1..100` to the standalone CLI. The default remains five pages.
- Enable breadth-first same-host HTML discovery above five pages, with scaled bounded HTTP/time budgets and a bounded discovery frontier.
- Add the extended `layerly.check.v0.5-draft` report/schema and explicit page-cap coverage; legacy reports remain compatible.
- Retain robots, public-IP, DNS pinning, rate, redirect, TLS and decompression controls; no hosted-service limit or paid model integration changes.
- Document extended mode in English, Persian and the AI review skill; add fixture regressions for depth, caps, coverage, budgets and CLI opt-in.

## 0.1.0 - 2026-10-29

- Initial standalone public core extracted from Layerly's internal checker.
- Five-page crawler with explicit HTTP/DNS budgets, robots gating, pinned transport and evidence-based JSON observations.
- Offline fixture examples, regression tests, Docker runner and English/Persian documentation.
- Model integrations, mock cost ledger, hosted web/email flow and operational data are excluded.
- Schema identifier `c2.check.v0.4-draft` is retained for compatibility; it is not the package release version.

# Contributing

Please open an issue describing the observed behavior before a large change. Small, focused fixes with fixture-based regression tests are welcome.

1. Use Python 3.11–3.13.
2. Run `python -m unittest discover -s tests -v`.
3. Run `python -m sitecheck demo --out sample.json` and validate it with `python -m sitecheck validate sample.json`.
4. Keep reports deterministic where fixtures are used. Keep `is_sample: true` on fixture examples.
5. Add evidence for findings and list missing coverage. Never infer rankings, revenue or AI citations from HTML checks.
6. Do not crawl external websites in automated tests, add credentials, weaken TLS/robots/IP checks, or silently increase crawl limits.

The TLS harness requires an `openssl` executable; tests that cannot run must remain explicit skips. Report security issues privately as described in SECURITY.md. Contributions are offered under this repository's MIT license. Do not submit third-party code you cannot license accordingly.

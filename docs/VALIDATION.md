# Validation record — 0.1.0

Local release validation on 2026-10-29:

| Environment | Result | Scope |
|---|---|---|
| Linux, Python 3.12, isolated container | 94 passed, no skips | Fixtures and temporary loopback/TLS servers; no external crawling |
| Windows, Python 3.12 | 92 passed, 2 explicitly skipped | TLS harness skips because the OpenSSL executable was not available |
| Docker image, non-root, read-only filesystem, network disabled | Offline demo passed | Produced the fixture JSON report |
| Python wheel | Build and isolated local installation succeeded | Installed CLI generated and validated an offline report |

The CLI does not run an AI provider. Examples are synthetic, marked `is_sample: true`. These checks do not demonstrate complete security, exhaustive robots compliance or compatibility with every live website.

The public CI workflow is configured separately for Linux/Python 3.11–3.13. This local record does not claim those hosted jobs have already run. Consult the repository's Actions page for their actual status.

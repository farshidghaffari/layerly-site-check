# Security policy

This is a local CLI/library, not a hardened public scanning service. Use it only for public websites you are authorised to check. Do not remove the private-address, TLS or robots controls to make a failing check succeed.

## Report privately

Email **farshid@layerly.net** with the subject `Layerly Site Check security report`. Include a minimal reproducer with synthetic addresses/data, affected version and observed vs expected behavior. Do not include customer reports, credentials or live targets you do not own in public issues. No response-time or bounty commitment is offered.

## Boundaries

- The transport pins approved public DNS answers and validates every redirect hop. URL/IP, timeout, decompression and robots paths have regression tests.
- The robots parser implements tested behavior, not every possible server or RFC edge case. Unknown robots results fail closed in this release.
- DNS resolution and in-process timers are not a substitute for an external process deadline and egress isolation. Put network, concurrency, authentication and resource controls around any service integration.
- Raw reports contain diagnostic metadata and excerpts. This repository has no account system, mail delivery, encryption-at-rest or retention daemon.
- No model provider is used and no website content is executed as instructions or JavaScript.

Only the 0.1.x line is currently maintained. An issue or a passing test suite does not establish absence of vulnerabilities. Validate changes before exposing this code to untrusted requests.

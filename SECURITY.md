# Security Policy

FAAR is pre-alpha security-sensitive financial infrastructure. v0.4.0 is a hardened reference runtime with operator controls, not a live-money release.

## Current status

This repository contains an executable reference security kernel plus self-red-team regression evidence (`docs/RED_TEAM_REPORT.md`). It is **not independently audited**, **not formally verified**, and **not approved for real funds**. `docs/GO_LIVE_CHECKLIST.md` records exactly which live-money gates are closed in-repo and which remain open or belong to a deployment.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting on this repository ("Security" tab → "Report a vulnerability"). If that is unavailable to you, open an issue titled "security contact request" containing **no** technical detail and a maintainer will provide a private channel.

Please include a reproduction against the mock/paper model where possible (the `test/support.py` helpers make this short) and the invariant from `docs/INVARIANTS.md` you believe is violated. Do not publish exploit details against any future live deployment before a fix is released.

## Reportable issues

Treat the following as security-sensitive:

- unauthorized economic execution
- duplicate economic execution for one logical intent
- authority/capability bypass
- grant self-escalation
- replay/idempotency failure
- a retry admitted while a previous attempt's permit is still live
- signing-key exposure or acceptance of a revoked/unknown key
- permit forgery, relabelling, or consumption across an epoch, halt, or restore
- settlement evidence spoofing or evidence-chain laundering
- fail-open behavior under ambiguity
- risk-limit or aggregate-usage bypass
- adapter target/asset/amount substitution
- non-authoritative settlement accepted as final
- unbounded capability construction or a limit silently unenforced by parsing
- confused-deputy execution payloads
- resurrection of consumed authority after a datastore restore
- an operator path that releases held budget or reactivates a revoked grant version

## Emergency controls

Operators of a deployment should know `docs/OPERATIONS.md` §1 (`halt` / `resume`) before the first funded intent.

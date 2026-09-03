---
name: Gate 8 independent security review
about: Pin a commit and track the required external human review
title: "Gate 8 review: <full commit SHA>"
labels: security
assignees: ""
---

This issue coordinates an independent human review; it is not an approval.
Do not post secrets, credentials, private keys, or live exploit details here.

## Target

- Full commit SHA:
- Tree hash:
- Reviewer:
- Independence statement:
- Review start date:

## Scope

- [ ] Core authority, runtime, permits, settlement, evidence, and controls
- [ ] SQLite and PostgreSQL 16 store contract/migrations
- [ ] Selected adapter and verifier (name it):
- [ ] Claims and go-live checklist
- [ ] Deployment evidence explicitly excluded or listed

Follow `docs/INDEPENDENT_SECURITY_REVIEW.md`.

## Evidence run

- [ ] Python 3.11 `make check`
- [ ] Python 3.12 `make check`
- [ ] Python 3.13 `make check`
- [ ] PostgreSQL 16 contract tests
- [ ] PostgreSQL mapped red-team pass
- [ ] PostgreSQL crash-injection sweep
- [ ] Reviewer-selected mutations/reproductions

## Findings

Link the private report or child security advisories. Track each finding and its
remediation commit without copying sensitive exploit details into this issue.

## Completion

- [ ] No open critical/high finding
- [ ] Security-relevant fixes delta-reviewed
- [ ] Final report URL/artifact:
- [ ] Report SHA-256:
- [ ] Reviewer conclusion for pinned SHA:
- [ ] `docs/GO_LIVE_CHECKLIST.md` updated by maintainer

Gate 8 remains OPEN until every completion item is satisfied. This issue cannot
close Gate 6.4 or any venue/environment DEPLOYMENT row.

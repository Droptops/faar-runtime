# Instructions for Coding Agents

FAAR is security-sensitive financial infrastructure. Optimize for invariant preservation, traceability, and narrow changes—not feature velocity.

## Hard rules

1. Never add real API keys, seed phrases, private keys, wallet secrets, or production credentials.
2. Never connect tests to real funds by default.
3. Do not weaken an invariant to make a test pass.
4. Do not turn LLM output into a trusted authorization decision without deterministic validation.
5. Do not create retry logic that generates a new `intent_id` for an ambiguous prior execution.
6. Do not silently coerce unknown state into success or failure.
7. Every economic denial/stop condition must be machine-readable.
8. Every new executor/adapter requires settlement and replay semantics in its design.
9. Security-relevant behavior changes require regression tests.
10. Keep ConstraintGate/AAR evidence claims separate from FAAR runtime claims.
11. Money-moving grants must remain bounded by construction; never interpret a missing financial limit as infinity.
12. Execution adapters receive only a sanitized `ExecutionRequest` plus a signed, narrowly scoped `ExecutionPermit`; do not reintroduce full model metadata, grant documents, or policy objects into the credentialed executor boundary, and never let a submitter receipt advance settlement.
13. Positive settlement is not trusted merely because it is positive: effect identity, authority of the lookup, and economic amount must be checked.
14. Do not add a real-money adapter until `docs/V0_2_RELEASE_GATES.md` is satisfied and independently reviewed; track status in `docs/GO_LIVE_CHECKLIST.md`.
15. Never trust absence of an effect while a previous attempt's permit is still live, and never resolve an ambiguity window early to improve liveness.
16. Every check that stops an economic effect needs a test that fails when the check is removed; map new attack classes in `evals/run_redteam.py`.

## Development order

Prefer:

```text
spec -> invariant test -> deterministic implementation -> adversarial test -> adapter
```

over:

```text
adapter -> happy path -> patch security later
```

## Claims

Do not describe FAAR as audited, formally verified, production-safe, exactly-once in production, or secure against a class of attacks unless the corresponding evidence exists in this repository and the claim scope is explicit.

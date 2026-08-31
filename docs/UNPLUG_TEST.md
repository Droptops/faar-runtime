# FAAR Unplug Test

A useful deployment test is not “did the agent produce something?” but “what real capability disappears when each component is removed?”

FAAR applies that idea to authority boundaries.

## Remove the model

Expected:

- no new autonomous proposals;
- FAAR's grants, risk limits, and evidence remain intact;
- no hidden scheduler/tool should continue inventing unsigned intents.

## Remove the authority signer

Expected:

- new economic intents cannot become executable;
- no fallback from “signer unavailable” to trusting model text.

## Remove the risk signer

Expected:

- new risk-bearing intents DEFER/STOP;
- no use of stale state merely to preserve throughput.

## Remove FAAR from the execution path

Production requirement:

- the model/coordinator must **not** retain an alternate credential/path capable of reaching the venue directly;
- trading-only credentials should not have withdrawal/root-account authority where the venue supports narrower permissions.

This cannot be guaranteed by a Python library alone. It is a deployment/key-isolation property and therefore a live-money release gate.

## Remove the outcome verifier

Expected:

- settlement can still be recorded;
- the system cannot promote “economic effect occurred” to “task objective met” without the separately defined success criteria/evidence.

## Why this matters

If removing FAAR leaves the model with the same direct wallet/exchange authority, FAAR is advisory middleware rather than an authority boundary. If removing the outcome verifier changes nothing about reported success, “done” is probably being inferred from process completion instead of measured.

# Security Policy

FAAR is pre-alpha security-sensitive financial infrastructure. v0.4.0 is a hardened reference runtime, not a live-money release.

## Current status

This repository contains an executable reference security kernel plus self-red-team regression evidence. It is **not independently audited**, **not formally verified**, and **not approved for real funds**.

## Reportable issues

Treat the following as security-sensitive:

- unauthorized economic execution
- duplicate economic execution for one logical intent
- authority/capability bypass
- grant self-escalation
- replay/idempotency failure
- signing-key exposure
- settlement evidence spoofing
- fail-open behavior under ambiguity
- risk-limit bypass
- adapter target/asset/amount substitution
- non-authoritative settlement accepted as final
- unbounded capability construction
- confused-deputy execution payloads

Until a private reporting channel is configured, do not publish exploit details against any future live deployment.

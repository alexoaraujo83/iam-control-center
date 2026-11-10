# Source-applied migration archive

This directory deliberately separates an **exact Git-sourced historical SQL artifact** from a **hardened CI regression fixture**. Neither is an active migration and neither should be replayed on an existing Neon or Production baseline.

## Canonical historical SQL (immutable provenance)

- File: `applied/0001_context_key_hardening.sql`
- Original Git path: `database/migrations/0001_context_key_hardening.sql`
- Original Git commit (source ledger): `b80c98c51746e1d49039015eb649b9bdd735ef7f`
- Git blob SHA-1: `a471428ef2f8ec068fbc9b7f7590df3caed997ad`
- Exact file SHA-256: `2447395628fa0f1230abd95eb522e5b45d1baea1208c9c21b20346a10718fbab`
- Source ledger migration ID: `0001_context_key_hardening`
- Source ledger execution login: `iam_migrator_login`
- Source ledger applied_at: `2026-11-05T04:16:49.492Z` UTC

The exact historical bytes were retrieved from that immutable Git commit and their SHA-256 matches a directly authorized read-only SELECT from the Neon `main` ledger on 2026-11-10 UTC. The repository test runner checks this digest without executing the original SQL.

## Hardened regression fixture — *not* the historical applied bytes

- File: `0001_context_key_hardening.sql` (existing path retained to preserve disposable CI tests)
- Current fixture SHA-256 at snapshot: `8d3d617fece260d845b5a173d94706afafa9e82327aaed406e1fe93a0d17d842`
- This is **not byte-identical** to the migration applied in Neon; its preflight was substantially hardened after the original deployment.
- The runner executes the hardened variant **only** inside a disposable PostgreSQL 18 database to test role preflight, DDL, transaction/advisory lock, checksum behavior and rollback. Do not use that variant to infer the applied source checksum or assume the source ledger matches the runner's computed test checksum.

## Branch lineage observed

- Neon `main`: `0001_context_key_hardening` recorded with the exact checksum above.
- Neon `development`: inherited the same `0001` row and additionally records `0002_sessions_touch_contract` (checksum `ac855c5829808da2268f42cbf1a3196e8776c1760202622ff42c8172e59dfb8f`, source SHA `e39fe77d2c6f91fa652417cd0f869884735b914a`, applied `2026-11-08T13:21:02.982Z` UTC).
- The schema comparison between these Neon branches shows the sessions-touch trigger/function change; this is distinct from the historical `0001` record.

Read-only evidence and limitations: `docs/evidence/neon-ledger-source-provenance-2026-11-10.md`.

## Operational rule

The `applied/` directory is a historical evidence store, **never** an active migration queue. The schema-only source dump omits ledger rows, so it is not independently sufficient to reconstruct applied history. A clean database bootstrap in `database/bootstrap/` is a distinct lineage. `database/proposals/` contains unapproved proposals and must not be automatically promoted or executed.

Do not renumber, modify, or replay the source-applied `0001` on Neon. Separately review baseline/schema parity, real tenant RLS tests and rollback behavior before declaring the operational migration lineage fully reconciled or merging a database PR.

# Neon migration-ledger provenance — read-only evidence (2026-11-10 UTC)

**Repository:** `alexoaraujo83/iam-control-center` — PR #85  
**Neon project:** `twilight-fire-88497009`; database `iam_database`  
**Operation:** PostgreSQL read-only transaction. No GRANT, DDL, migration, DML, production deployment or role modification.

## Authorized access path

A direct `SELECT` using `iam_migrator_login` fails with `permission denied for schema iam` because the login does **not inherit** the migrator group's access. The existing role membership explicitly permits `SET ROLE iam_migrator`, which already has schema USAGE and SELECT on the ledger. No new privileges are required for this read-only audit.

The following statements were executed as `iam_migrator_login` by Neon in **one transaction** on each existing branch:

```sql
SET TRANSACTION READ ONLY;
SET LOCAL ROLE iam_migrator;
SELECT session_user AS login, current_user AS effective_role,
       migration_id, checksum_sha256, source_sha, applied_at, execution_role
FROM iam.schema_migrations
ORDER BY applied_at DESC
LIMIT 20;
```

Observed session_user: `iam_migrator_login`. Effective current_user: `iam_migrator`. `SET LOCAL` ends at the transaction boundary.

## Verified rows

| Neon branch | migration_id | checksum_sha256 | source_sha | applied_at (UTC) | execution_role |
| --- | --- | --- | --- | --- | --- |
| `main` (`br-little-fire-b6adup9f`) | `0001_context_key_hardening` | `2447395628fa0f1230abd95eb522e5b45d1baea1208c9c21b20346a10718fbab` | `b80c98c51746e1d49039015eb649b9bdd735ef7f` | `2026-11-05T04:16:49.492Z` | `iam_migrator_login` |
| `development` (`br-proud-brook-b6woqo6z`) | `0001_context_key_hardening` | `2447395628fa0f1230abd95eb522e5b45d1baea1208c9c21b20346a10718fbab` | `b80c98c51746e1d49039015eb649b9bdd735ef7f` | `2026-11-05T04:16:49.492Z` | `iam_migrator_login` |
| `development` | `0002_sessions_touch_contract` | `ac855c5829808da2268f42cbf1a3196e8776c1760202622ff42c8172e59dfb8f` | `e39fe77d2c6f91fa652417cd0f869884735b914a` | `2026-11-08T13:21:02.982Z` | `iam_migrator_login` |

The two `0001` rows are identical *in these branch snapshots*; this does not independently prove two executions. The `0002` row and corresponding schema function/trigger change exist only in `development`. Neon `compare_database_schema` showed `iam.touch_session_last_seen_at()` added and `iam.sessions.sessions_touch` redirected from `iam.touch_updated_at()` to the new function in `development` relative to `main`. Comparing PR #85's Neon preview branch to its parent `development` returned an empty schema diff.

## Exact historic source versus test fixture

- Original Git commit `b80c98c51746e1d49039015eb649b9bdd735ef7f`, path `database/migrations/0001_context_key_hardening.sql`, blob `a471428ef2f8ec068fbc9b7f7590df3caed997ad`, SHA-256 `2447395628fa0f1230abd95eb522e5b45d1baea1208c9c21b20346a10718fbab`. This **matches** the Neon ledger entry.
- The existing regression file `database/archive/source-applied-migrations/0001_context_key_hardening.sql` at PR #85's audited HEAD has SHA-256 `8d3d617fece260d845b5a173d94706afafa9e82327aaed406e1fe93a0d17d842`. It has changed after deployment and is **not** the original applied file.
- The original bytes are now preserved independently at `database/archive/source-applied-migrations/applied/0001_context_key_hardening.sql`; the CI runner checks their checksum without executing them. The hardened fixture remains in disposable PostgreSQL 18 test execution.


## Additional read-only catalog and negative RLS evidence

### Branch-to-branch catalog comparisons (Neon `compare_database_schema`)

- `schema-restore-validation-20261105` compared with source `main`: the complete returned schema diff contains only **three schema `USAGE` GRANT lines** for `iam_schema_export_reader` on `iam`, `audit`, and `app_private`. Other SQL DDL was identical in this specific branch comparison.
- `schema-export-validation-20261105` compared with source `main`: the returned SQL diff consists of **extra `SELECT` GRANTs** for `iam_schema_export_reader` on existing application tables/view (plus an ACL heading). This confirms the export-validation branch has broader read-only ACLs than the operational main, not that those ACLs may be copied to Production.
- `preview/pr-85` compared with parent `development`: empty schema diff. `development` compared with `main`: the sessions-touch function/trigger correction as detailed above.

**Scope:** these are comparisons of *Neon branch schemas*, not cryptographically authenticated reconstruction of the repository's checked-in schema-only dump, and they do not export applied ledger data or test application behavior.

### Runtime access with non-BYPASSRLS login

On both Neon `main` and `development`, connected as `iam_app_runtime_login`, then in one `READ ONLY` transaction used `SET LOCAL ROLE iam_app_runtime` and `SET LOCAL row_security=on`. The effective role reported `rolbypassrls=false`. Without a signed tenant context, `app_private.current_tenant_id()` resolved `NULL`; `SELECT count(*)` from `iam.tenants` and `iam.memberships` returned **0** for each table.

On `development`, repeated that transaction with only synthetic `iam.tenant_id`, `iam.identity_id`, future expiry, nonce, and a deliberately invalid signature set using transaction-local `set_config(..., true)`. The resolver still returned `NULL` and each table had **0 visible rows**. No real tenant, identity, key, or signature was queried or written. This is a negative *forged-GUC* check, not proof of valid signed-context A/B isolation.

Remaining: valid signed tenant A/B tests on an authorized isolated Neon runtime branch, INSERT/UPDATE denial, audit/outbox propagation, idempotency and rollback evidence before any database merge.

## Remaining gates (not cleared by ledger read)

1. Normalize/compare authenticated **full schema snapshot** and DDL manifest of operational Neon against the versioned baseline, including ownership, ACLs and provider-managed role differences. The schema-only dump alone does not include historical ledger rows.
2. Validate isolated Neon RLS behavior with runtime non-BYPASSRLS tenants A/B, rollback and relevant audit/outbox behavior, with reproducible evidence; PostgreSQL 18 disposable tests are not substitutes.
3. Obtain independent review of the original P1 migration-lineage finding and approve the operational next migration sequence. Do **not** infer clean bootstrap `0001_initial_iam_schema.sql` is an applied predecessor or promote proposed `0002_context_resolver_volatility_hardening.sql`.

**Safety:** No existing historical migration was replayed or renumbered, no persistent Neon object was changed, and no Production service was modified.

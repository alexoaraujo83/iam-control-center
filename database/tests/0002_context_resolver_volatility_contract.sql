-- CI-only contract for proposed migration 0002.
-- Run after the proposal is applied to the disposable operational fixture.
\set ON_ERROR_STOP on

SELECT set_config('ci.resolver_checksum', :'resolver_checksum', false);
SELECT set_config('ci.source_sha', :'source_sha', false);

DO $assert_function_hardening$
DECLARE
  v_current record;
  v_setter record;
  v_ledger record;
BEGIN
  SELECT p.provolatile, p.prosecdef, pg_get_userbyid(p.proowner) AS owner,
         p.proconfig
    INTO v_current
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('app_private.current_tenant_id()');
  IF NOT FOUND OR v_current.provolatile <> 'v'
     OR NOT v_current.prosecdef OR v_current.owner <> 'iam_owner'
     OR NOT (v_current.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam']::text[])
     OR v_current.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam, public']::text[] THEN
    RAISE EXCEPTION 'current_tenant_id must be VOLATILE, SECURITY DEFINER, iam_owner-owned and use hardened search_path';
  END IF;

  SELECT p.provolatile, p.prosecdef, pg_get_userbyid(p.proowner) AS owner,
         p.proconfig
    INTO v_setter
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('iam.set_tenant_context(uuid,uuid,bigint,text,text)');
  IF NOT FOUND OR NOT v_setter.prosecdef OR v_setter.owner <> 'iam_owner'
     OR NOT (v_setter.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam']::text[])
     OR v_setter.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam, public']::text[] THEN
    RAISE EXCEPTION 'set_tenant_context must remain SECURITY DEFINER and remove public from search_path';
  END IF;

  SELECT migration_id, checksum_sha256, source_sha, execution_role
    INTO v_ledger
    FROM iam.schema_migrations
   WHERE migration_id = '0002_context_resolver_volatility_hardening';
  IF NOT FOUND
     OR v_ledger.checksum_sha256 <> current_setting('ci.resolver_checksum')
     OR v_ledger.source_sha <> current_setting('ci.source_sha')
     OR v_ledger.execution_role <> 'iam_migrator_login' THEN
    RAISE EXCEPTION 'proposal 0002 ledger evidence mismatch: %', v_ledger;
  END IF;
END
$assert_function_hardening$;

BEGIN;
-- Add a minimal test-only RLS policy so the resolver is exercised by the
-- same row-security predicate used by the full operational schema.
ALTER TABLE iam.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY resolver_test_owner ON iam.tenants
  TO iam_owner USING (true) WITH CHECK (true);
CREATE POLICY resolver_test_runtime ON iam.tenants
  TO iam_app_runtime
  USING (id = app_private.current_tenant_id())
  WITH CHECK (id = app_private.current_tenant_id());
GRANT USAGE ON SCHEMA iam, app_private TO iam_app_runtime;
GRANT SELECT ON TABLE iam.tenants TO iam_app_runtime;
GRANT EXECUTE ON FUNCTION app_private.current_tenant_id() TO iam_app_runtime;
GRANT EXECUTE ON FUNCTION iam.set_tenant_context(uuid, uuid, bigint, text, text) TO iam_app_runtime;
GRANT EXECUTE ON FUNCTION iam.clear_tenant_context() TO iam_app_runtime;

SET LOCAL ROLE iam_owner;
INSERT INTO iam.tenants (id, status)
VALUES
  ('30000000-0000-4000-8000-000000000003', 'active'),
  ('40000000-0000-4000-8000-000000000004', 'active');
INSERT INTO iam.identities (id, status)
VALUES
  ('30000000-0000-4000-8000-000000000033', 'active'),
  ('40000000-0000-4000-8000-000000000044', 'active');
INSERT INTO iam.memberships (tenant_id, identity_id, status)
VALUES
  ('30000000-0000-4000-8000-000000000003', '30000000-0000-4000-8000-000000000033', 'active'),
  ('40000000-0000-4000-8000-000000000004', '40000000-0000-4000-8000-000000000044', 'active');
INSERT INTO app_private.context_keys (key_id, secret, active)
VALUES ('ci-volatility-key', decode(repeat('42', 32), 'hex'), true);

RESET ROLE;
SET LOCAL ROLE iam_app_runtime;

-- One top-level SQL statement uses materialized, dependency-ordered CTEs to
-- set tenant A, query under RLS, set tenant B, and query again. This is the
-- planner boundary at which a STABLE resolver could reuse tenant A.
DO $same_statement_context_switch$
DECLARE
  v_a uuid[];
  v_b uuid[];
BEGIN
  WITH
  tenant_a AS MATERIALIZED (
    SELECT
      '30000000-0000-4000-8000-000000000003'::uuid AS tenant_id,
      '30000000-0000-4000-8000-000000000033'::uuid AS identity_id,
      floor(extract(epoch FROM clock_timestamp()))::bigint + 180 AS expires_at,
      'ci-volatility-a'::text AS nonce
  ),
  set_a AS MATERIALIZED (
    SELECT tenant_id,
      iam.set_tenant_context(
        tenant_id, identity_id, expires_at, nonce,
        encode(public.hmac(
          convert_to(tenant_id::text || '|' || identity_id::text || '|' || expires_at::text || '|' || nonce, 'UTF8'),
          decode(repeat('42', 32), 'hex'), 'sha256'
        ), 'hex')
      ) AS applied
    FROM tenant_a
  ),
  read_a AS MATERIALIZED (
    SELECT set_a.tenant_id, q.visible_tenants
    FROM set_a
    CROSS JOIN LATERAL (
      SELECT array_agg(t.id ORDER BY t.id) AS visible_tenants
      FROM iam.tenants t
      WHERE set_a.tenant_id IS NOT NULL
    ) q
  ),
  tenant_b AS MATERIALIZED (
    SELECT
      '40000000-0000-4000-8000-000000000004'::uuid AS tenant_id,
      '40000000-0000-4000-8000-000000000044'::uuid AS identity_id,
      floor(extract(epoch FROM clock_timestamp()))::bigint + 180 AS expires_at,
      'ci-volatility-b'::text AS nonce
    FROM read_a
  ),
  set_b AS MATERIALIZED (
    SELECT tenant_id,
      iam.set_tenant_context(
        tenant_id, identity_id, expires_at, nonce,
        encode(public.hmac(
          convert_to(tenant_id::text || '|' || identity_id::text || '|' || expires_at::text || '|' || nonce, 'UTF8'),
          decode(repeat('42', 32), 'hex'), 'sha256'
        ), 'hex')
      ) AS applied
    FROM tenant_b
  ),
  read_b AS MATERIALIZED (
    SELECT set_b.tenant_id, q.visible_tenants
    FROM set_b
    CROSS JOIN LATERAL (
      SELECT array_agg(t.id ORDER BY t.id) AS visible_tenants
      FROM iam.tenants t
      WHERE set_b.tenant_id IS NOT NULL
    ) q
  )
  SELECT read_a.visible_tenants, read_b.visible_tenants
    INTO v_a, v_b
    FROM read_a CROSS JOIN read_b;

  IF v_a IS DISTINCT FROM ARRAY['30000000-0000-4000-8000-000000000003'::uuid]
     OR v_b IS DISTINCT FROM ARRAY['40000000-0000-4000-8000-000000000004'::uuid] THEN
    RAISE EXCEPTION 'same-statement RLS context switch leaked or reused tenant context: A=%, B=%', v_a, v_b;
  END IF;
END
$same_statement_context_switch$;

SELECT iam.clear_tenant_context();

-- Invalid context attempts are checked from an empty context in independent
-- statements; the application must abort the request transaction on failure.
DO $invalid_signature$
DECLARE
  v_rejected boolean := false;
BEGIN
  BEGIN
    PERFORM iam.set_tenant_context(
      '30000000-0000-4000-8000-000000000003',
      '30000000-0000-4000-8000-000000000033',
      floor(extract(epoch FROM clock_timestamp()))::bigint + 180,
      'ci-invalid-signature', repeat('0', 64)
    );
  EXCEPTION WHEN insufficient_privilege THEN
    v_rejected := true;
  END;
  IF NOT v_rejected THEN
    RAISE EXCEPTION 'tampered signature was not rejected';
  END IF;
END
$invalid_signature$;

RESET ROLE;
ROLLBACK;
SELECT 'PASS proposed 0002: VOLATILE tenant resolver, hardened setter search_path and same-statement tenant context switching' AS result;

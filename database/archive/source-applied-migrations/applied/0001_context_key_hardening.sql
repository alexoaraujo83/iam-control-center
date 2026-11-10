-- IAM Control Center — context-key hardening
-- Baseline: existing iam-database schema (not a clean-database bootstrap).
-- PostgreSQL 18. Execute with psql variables:
--   -v migration_checksum=<SHA-256 of this exact file>
--   -v source_sha=<40-character Git commit SHA containing this file>
-- The transaction acquires the advisory migration lock and records its ledger
-- entry atomically with the DDL. session_user must be iam_migrator_login.

BEGIN;
-- The login is intentionally not a direct member of iam_owner. Follow the
-- reviewed two-step role chain so the effective role is iam_owner while the
-- authenticated session identity remains iam_migrator_login.
SET LOCAL ROLE iam_migrator;
SET LOCAL ROLE iam_owner;
SELECT iam.acquire_migration_lock();

DO $preflight$
DECLARE
  v_function_oid oid;
  v_search_path text[];
  v_active_keys bigint;
BEGIN
  IF current_user <> 'iam_owner' THEN
    RAISE EXCEPTION 'effective current_user must be iam_owner; got %', current_user;
  END IF;

  IF session_user <> 'iam_migrator_login' THEN
    RAISE EXCEPTION 'session_user must be iam_migrator_login; got %', session_user;
  END IF;

  IF to_regclass('app_private.context_keys') IS NULL THEN
    RAISE EXCEPTION 'required table app_private.context_keys does not exist';
  END IF;

  IF to_regprocedure('app_private.current_tenant_id()') IS NULL THEN
    RAISE EXCEPTION 'required function app_private.current_tenant_id() does not exist';
  END IF;

  SELECT p.oid, p.proconfig
    INTO v_function_oid, v_search_path
    FROM pg_proc AS p
   WHERE p.oid = to_regprocedure('app_private.current_tenant_id()');

  IF NOT EXISTS (
    SELECT 1
      FROM pg_roles AS r
     WHERE r.oid = (SELECT proowner FROM pg_proc WHERE oid = v_function_oid)
       AND r.rolname = 'iam_owner'
  ) THEN
    RAISE EXCEPTION 'app_private.current_tenant_id() must be owned by iam_owner';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_proc AS p
     WHERE p.oid = v_function_oid
       AND p.prosecdef IS TRUE
  ) THEN
    RAISE EXCEPTION 'app_private.current_tenant_id() must remain SECURITY DEFINER';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_extension AS e
      JOIN pg_namespace AS n ON n.oid = e.extnamespace
     WHERE e.extname = 'pgcrypto'
       AND n.nspname = 'public'
  ) OR to_regprocedure('public.hmac(bytea,bytea,text)') IS NULL THEN
    RAISE EXCEPTION 'expected pgcrypto public.hmac(bytea, bytea, text) dependency is missing';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM unnest(coalesce(v_search_path, ARRAY[]::text[])) AS s(value)
     WHERE s.value = 'search_path=pg_catalog, app_private, iam, public'
  ) THEN
    RAISE EXCEPTION 'function search_path differs from the reviewed source state: %',
      coalesce(v_search_path::text, '<unset>');
  END IF;

  SELECT count(*)
    INTO v_active_keys
    FROM app_private.context_keys
   WHERE active IS TRUE;

  IF v_active_keys > 1 THEN
    RAISE EXCEPTION 'cannot enforce one active context key: found % active rows',
      v_active_keys;
  END IF;

  IF to_regclass('app_private.context_keys_one_active_idx') IS NOT NULL THEN
    RAISE EXCEPTION 'index app_private.context_keys_one_active_idx already exists; inspect before applying';
  END IF;
END
$preflight$;

-- At most one active HMAC key may exist. Inactive historical keys remain allowed.
CREATE UNIQUE INDEX context_keys_one_active_idx
    ON app_private.context_keys (active)
    WHERE active IS TRUE;

-- Remove public from the SECURITY DEFINER function's implicit lookup path.
-- pgcrypto's hmac call remains explicitly schema-qualified as public.hmac(...).
ALTER FUNCTION app_private.current_tenant_id()
    SET search_path TO pg_catalog, app_private, iam;

DO $verify$
DECLARE
  v_search_path text[];
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_index AS i
     WHERE i.indexrelid = to_regclass('app_private.context_keys_one_active_idx')
       AND i.indisunique
       AND i.indisvalid
       AND pg_get_expr(i.indpred, i.indrelid) = '(active IS TRUE)'
  ) THEN
    RAISE EXCEPTION 'partial unique index verification failed';
  END IF;

  SELECT p.proconfig
    INTO v_search_path
    FROM pg_proc AS p
   WHERE p.oid = to_regprocedure('app_private.current_tenant_id()');

  IF NOT (v_search_path @> ARRAY['search_path=pg_catalog, app_private, iam']::text[])
     OR v_search_path @> ARRAY['search_path=pg_catalog, app_private, iam, public']::text[] THEN
    RAISE EXCEPTION 'function search_path verification failed: %',
      coalesce(v_search_path::text, '<unset>');
  END IF;
END
$verify$;

SELECT iam.record_migration(
  '0001_context_key_hardening',
  :'migration_checksum',
  NULLIF(:'source_sha', '')
);

COMMIT;

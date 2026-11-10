-- PROPOSAL ONLY — not part of the active migration directory.
-- Do not execute against persistent Neon/Production until migration lineage,
-- source equivalence, review, and a separate execution approval are complete.
-- This follows 0001_context_key_hardening in the disposable operational fixture.
\set ON_ERROR_STOP on

BEGIN;

DO $authenticated_preflight$
DECLARE
  v_login record;
BEGIN
  IF session_user <> 'iam_migrator_login' OR current_user <> session_user THEN
    RAISE EXCEPTION 'proposal must start as a direct authenticated iam_migrator_login session';
  END IF;

  SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
         rolreplication, rolbypassrls
    INTO v_login
    FROM pg_roles
   WHERE rolname = session_user;
  IF NOT FOUND OR NOT v_login.rolcanlogin OR v_login.rolinherit
     OR v_login.rolsuper OR v_login.rolcreatedb OR v_login.rolcreaterole
     OR v_login.rolreplication OR v_login.rolbypassrls THEN
    RAISE EXCEPTION 'migration login has unexpected or privileged role attributes';
  END IF;

  IF NOT pg_has_role(session_user, 'iam_migrator', 'MEMBER')
     OR pg_has_role(session_user, 'iam_migrator', 'USAGE')
     OR NOT pg_has_role(session_user, 'iam_owner', 'MEMBER')
     OR pg_has_role(session_user, 'iam_owner', 'USAGE') THEN
    RAISE EXCEPTION 'migration login must have SET-only transitive membership and no inherited owner privileges';
  END IF;
END
$authenticated_preflight$;

SET LOCAL ROLE iam_migrator;
DO $ledger_preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM iam.schema_migrations
     WHERE migration_id = '0001_context_key_hardening'
  ) THEN
    RAISE EXCEPTION 'required predecessor 0001_context_key_hardening is not recorded';
  END IF;
  IF EXISTS (
    SELECT 1 FROM iam.schema_migrations
     WHERE migration_id = '0002_context_resolver_volatility_hardening'
  ) THEN
    RAISE EXCEPTION 'proposal 0002 is already recorded; inspect ledger before retry';
  END IF;
END
$ledger_preflight$;

SET LOCAL ROLE iam_owner;
SELECT iam.acquire_migration_lock();

DO $function_preflight$
DECLARE
  v_current record;
  v_setter record;
BEGIN
  IF current_user <> 'iam_owner' OR session_user <> 'iam_migrator_login' THEN
    RAISE EXCEPTION 'proposal must execute as iam_owner through authenticated iam_migrator_login';
  END IF;

  SELECT p.provolatile, p.prosecdef, pg_get_userbyid(p.proowner) AS owner,
         p.proconfig
    INTO v_current
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('app_private.current_tenant_id()');

  IF NOT FOUND OR v_current.provolatile <> 's'
     OR NOT v_current.prosecdef OR v_current.owner <> 'iam_owner'
     OR NOT (v_current.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam']::text[])
     OR v_current.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam, public']::text[] THEN
    RAISE EXCEPTION 'current_tenant_id does not match the expected applied-0001 predecessor state';
  END IF;

  SELECT p.provolatile, p.prosecdef, pg_get_userbyid(p.proowner) AS owner,
         p.proconfig
    INTO v_setter
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('iam.set_tenant_context(uuid,uuid,bigint,text,text)');

  IF NOT FOUND OR NOT v_setter.prosecdef OR v_setter.owner <> 'iam_owner'
     OR NOT (v_setter.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam, public']::text[]) THEN
    RAISE EXCEPTION 'set_tenant_context does not match the expected predecessor SECURITY DEFINER/search_path state';
  END IF;
END
$function_preflight$;

-- current_tenant_id reads transaction-local GUCs and clock_timestamp().
-- STABLE permits stale reuse when context changes within one statement.
-- VOLATILE forces a fresh evaluation at each call.
ALTER FUNCTION app_private.current_tenant_id() VOLATILE;

-- set_tenant_context uses only pg_catalog functions and a schema-qualified
-- app_private.current_tenant_id() call; public is not needed in its lookup path.
ALTER FUNCTION iam.set_tenant_context(uuid, uuid, bigint, text, text)
  SET search_path TO pg_catalog, app_private, iam;

DO $verify$
DECLARE
  v_current record;
  v_setter record;
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
    RAISE EXCEPTION 'current_tenant_id volatility/SECURITY DEFINER/owner/search_path verification failed: %', v_current;
  END IF;

  SELECT p.provolatile, p.prosecdef, pg_get_userbyid(p.proowner) AS owner,
         p.proconfig
    INTO v_setter
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('iam.set_tenant_context(uuid,uuid,bigint,text,text)');

  IF NOT FOUND OR NOT v_setter.prosecdef OR v_setter.owner <> 'iam_owner'
     OR NOT (v_setter.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam']::text[])
     OR v_setter.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam, public']::text[] THEN
    RAISE EXCEPTION 'set_tenant_context SECURITY DEFINER/owner/search_path verification failed: %', v_setter;
  END IF;
END
$verify$;

SELECT iam.record_migration(
  '0002_context_resolver_volatility_hardening',
  :'migration_checksum',
  NULLIF(:'source_sha', '')
);

COMMIT;

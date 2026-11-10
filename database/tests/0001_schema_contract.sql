-- CI-only contract for the source-derived incremental context-key migration fixture.
-- Run as the disposable PostgreSQL administrator after migration 0001 commits.
\set ON_ERROR_STOP on

SELECT set_config('ci.migration_checksum', :'migration_checksum', false);
SELECT set_config('ci.source_sha', :'source_sha', false);

DO $assert_migration$
DECLARE
  v_index record;
  v_function record;
  v_ledger record;
  v_expected_checksum text := current_setting('ci.migration_checksum');
  v_expected_source text := current_setting('ci.source_sha');
BEGIN
  SELECT i.indisunique, i.indisvalid, pg_get_expr(i.indpred, i.indrelid) AS predicate
    INTO v_index
    FROM pg_index i
   WHERE i.indexrelid = to_regclass('app_private.context_keys_one_active_idx');
  IF NOT FOUND OR NOT v_index.indisunique OR NOT v_index.indisvalid
     OR v_index.predicate <> '(active IS TRUE)' THEN
    RAISE EXCEPTION 'context_keys_one_active_idx is missing or invalid';
  END IF;

  SELECT p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner) AS owner
    INTO v_function
    FROM pg_proc p
   WHERE p.oid = to_regprocedure('app_private.current_tenant_id()');
  IF NOT FOUND OR NOT v_function.prosecdef
     OR v_function.owner <> 'iam_owner'
     OR NOT (v_function.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam']::text[])
     OR v_function.proconfig @> ARRAY['search_path=pg_catalog, app_private, iam, public']::text[] THEN
    RAISE EXCEPTION 'current_tenant_id SECURITY DEFINER ownership/search_path contract failed: %', v_function;
  END IF;

  SELECT migration_id, checksum_sha256, source_sha, execution_role
    INTO v_ledger
    FROM iam.schema_migrations
   WHERE migration_id = '0001_context_key_hardening';
  IF NOT FOUND
     OR v_ledger.checksum_sha256 <> v_expected_checksum
     OR v_ledger.source_sha <> v_expected_source
     OR v_ledger.execution_role <> 'iam_migrator_login' THEN
    RAISE EXCEPTION 'migration ledger evidence mismatch: %', v_ledger;
  END IF;

  IF (SELECT count(*) FROM app_private.context_keys WHERE active IS TRUE) <> 0 THEN
    RAISE EXCEPTION 'fixture must start with zero active context keys';
  END IF;
  IF app_private.current_tenant_id() IS NOT NULL THEN
    RAISE EXCEPTION 'current_tenant_id must fail closed when no signed context exists';
  END IF;
END
$assert_migration$;

-- Exercise the partial unique index. The second active key must fail, while
-- inactive historical keys remain permitted. All synthetic rows are rolled back.
BEGIN;
INSERT INTO app_private.context_keys(key_id, secret, active)
VALUES ('ci-active-1', decode(repeat('11', 32), 'hex'), true);
INSERT INTO app_private.context_keys(key_id, secret, active)
VALUES ('ci-inactive-1', decode(repeat('22', 32), 'hex'), false);
DO $assert_one_active_key$
BEGIN
  BEGIN
    INSERT INTO app_private.context_keys(key_id, secret, active)
    VALUES ('ci-active-2', decode(repeat('33', 32), 'hex'), true);
    RAISE EXCEPTION 'second active context key unexpectedly succeeded';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
  IF (SELECT count(*) FROM app_private.context_keys WHERE active IS TRUE) <> 1 THEN
    RAISE EXCEPTION 'partial unique index did not preserve exactly one active key';
  END IF;
  IF (SELECT count(*) FROM app_private.context_keys WHERE active IS FALSE) <> 1 THEN
    RAISE EXCEPTION 'inactive historical context key was unexpectedly rejected';
  END IF;
END
$assert_one_active_key$;
ROLLBACK;

DO $assert_no_fixture_rows$
BEGIN
  IF EXISTS (SELECT 1 FROM app_private.context_keys) THEN
    RAISE EXCEPTION 'synthetic context key rows escaped test rollback';
  END IF;
END
$assert_no_fixture_rows$;

SELECT 'PASS context-key migration contract: partial unique index, SECURITY DEFINER search_path, authenticated ledger, fail-closed context, uniqueness and rollback' AS result;


DO $assert_migration_principal_privileges$
DECLARE
  v_lock record;
  v_record record;
BEGIN
  IF NOT has_schema_privilege('iam_migrator', 'iam', 'USAGE')
     OR NOT has_table_privilege('iam_migrator', 'iam.schema_migrations', 'SELECT')
     OR has_table_privilege('iam_migrator', 'iam.schema_migrations', 'INSERT')
     OR has_table_privilege('iam_migrator', 'iam.schema_migrations', 'UPDATE')
     OR has_table_privilege('iam_migrator', 'iam.schema_migrations', 'DELETE')
     OR NOT has_function_privilege('iam_migrator', 'iam.acquire_migration_lock()', 'EXECUTE')
     OR NOT has_function_privilege('iam_migrator', 'iam.record_migration(text,text,text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'migration principal effective schema/ledger/function privileges diverge from source contract';
  END IF;

  SELECT p.prosecdef, pg_get_userbyid(p.proowner) AS owner, p.proconfig,
         coalesce(bool_or(grantee = 0), false) AS public_execute
    INTO v_lock
    FROM pg_proc p
    LEFT JOIN aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a ON true
   WHERE p.oid = to_regprocedure('iam.acquire_migration_lock()')
   GROUP BY p.prosecdef, p.proowner, p.proconfig;
  IF NOT FOUND OR NOT v_lock.prosecdef OR v_lock.owner <> 'iam_owner'
     OR v_lock.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']::text[]
     OR v_lock.public_execute THEN
    RAISE EXCEPTION 'acquire_migration_lock SECURITY DEFINER/owner/search_path/ACL contract failed';
  END IF;

  SELECT p.prosecdef, pg_get_userbyid(p.proowner) AS owner, p.proconfig,
         coalesce(bool_or(grantee = 0), false) AS public_execute
    INTO v_record
    FROM pg_proc p
    LEFT JOIN aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a ON true
   WHERE p.oid = to_regprocedure('iam.record_migration(text,text,text)')
   GROUP BY p.prosecdef, p.proowner, p.proconfig;
  IF NOT FOUND OR NOT v_record.prosecdef OR v_record.owner <> 'iam_owner'
     OR v_record.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, iam']::text[]
     OR v_record.public_execute THEN
    RAISE EXCEPTION 'record_migration SECURITY DEFINER/owner/search_path/ACL contract failed';
  END IF;
END
$assert_migration_principal_privileges$;

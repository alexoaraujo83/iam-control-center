-- IAM Control Center — context-key hardening
-- Baseline: existing iam-database schema (not a clean-database bootstrap).
-- PostgreSQL 18. Execute with psql variables:
--   -v migration_checksum=<SHA-256 of this exact file>
--   -v source_sha=<40-character Git commit SHA containing this file>
-- The transaction acquires the advisory migration lock and records its ledger
-- entry atomically with the DDL. session_user must be iam_migrator_login.

BEGIN;
-- Validate the authenticated login and its complete migration-role path before
-- SET ROLE, advisory locks, or any schema/data DDL.
DO $authenticated_role_preflight$
DECLARE
  v_login record;
  v_migrator record;
  v_owner record;
  v_login_edges integer;
  v_migrator_edges integer;
  v_migrator_grantees integer;
  v_owner_edges integer;
  v_owner_grantees integer;
  v_database_owner oid;
  v_database_owner_name name;
BEGIN
  IF session_user <> 'iam_migrator_login' OR current_user <> session_user THEN
    RAISE EXCEPTION
      'migration must start as a direct iam_migrator_login session; session_user=%, current_user=%',
      session_user, current_user;
  END IF;

  SELECT rolcanlogin, rolinherit, rolsuper, rolbypassrls,
         rolcreaterole, rolcreatedb, rolreplication
    INTO v_login
    FROM pg_roles
   WHERE rolname = session_user;
  IF NOT FOUND
     OR v_login.rolcanlogin IS DISTINCT FROM TRUE
     OR v_login.rolinherit IS DISTINCT FROM FALSE
     OR v_login.rolsuper IS DISTINCT FROM FALSE
     OR v_login.rolbypassrls IS DISTINCT FROM FALSE
     OR v_login.rolcreaterole IS DISTINCT FROM FALSE
     OR v_login.rolcreatedb IS DISTINCT FROM FALSE
     OR v_login.rolreplication IS DISTINCT FROM FALSE THEN
    RAISE EXCEPTION 'authenticated migrator login has unexpected or privileged role attributes';
  END IF;

  SELECT rolcanlogin, rolinherit, rolsuper, rolbypassrls,
         rolcreaterole, rolcreatedb, rolreplication
    INTO v_migrator
    FROM pg_roles
   WHERE rolname = 'iam_migrator';
  IF NOT FOUND
     OR v_migrator.rolcanlogin IS DISTINCT FROM FALSE
     OR v_migrator.rolinherit IS DISTINCT FROM FALSE
     OR v_migrator.rolsuper IS DISTINCT FROM FALSE
     OR v_migrator.rolbypassrls IS DISTINCT FROM FALSE
     OR v_migrator.rolcreaterole IS DISTINCT FROM FALSE
     OR v_migrator.rolcreatedb IS DISTINCT FROM FALSE
     OR v_migrator.rolreplication IS DISTINCT FROM FALSE THEN
    RAISE EXCEPTION 'iam_migrator group role has unexpected or privileged attributes';
  END IF;

  SELECT rolcanlogin, rolinherit, rolsuper, rolbypassrls,
         rolcreaterole, rolcreatedb, rolreplication
    INTO v_owner
    FROM pg_roles
   WHERE rolname = 'iam_owner';
  IF NOT FOUND
     OR v_owner.rolcanlogin IS DISTINCT FROM FALSE
     OR v_owner.rolinherit IS DISTINCT FROM FALSE
     OR v_owner.rolsuper IS DISTINCT FROM FALSE
     OR v_owner.rolbypassrls IS DISTINCT FROM FALSE
     OR v_owner.rolcreaterole IS DISTINCT FROM FALSE
     OR v_owner.rolcreatedb IS DISTINCT FROM FALSE
     OR v_owner.rolreplication IS DISTINCT FROM FALSE THEN
    RAISE EXCEPTION 'iam_owner group role has unexpected or privileged attributes';
  END IF;

  SELECT count(*) INTO v_login_edges
    FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid = m.member
   WHERE member_role.rolname = session_user;
  IF v_login_edges <> 1 OR NOT EXISTS (
    SELECT 1
      FROM pg_auth_members m
      JOIN pg_roles member_role ON member_role.oid = m.member
      JOIN pg_roles granted_role ON granted_role.oid = m.roleid
     WHERE member_role.rolname = session_user
       AND granted_role.rolname = 'iam_migrator'
       AND m.inherit_option IS FALSE
       AND m.set_option IS TRUE
       AND m.admin_option IS FALSE
  ) THEN
    RAISE EXCEPTION 'iam_migrator_login must have exactly one SET-only, non-admin membership: iam_migrator';
  END IF;

  SELECT count(*) INTO v_migrator_edges
    FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid = m.member
   WHERE member_role.rolname = 'iam_migrator';
  IF v_migrator_edges <> 1 OR NOT EXISTS (
    SELECT 1
      FROM pg_auth_members m
      JOIN pg_roles member_role ON member_role.oid = m.member
      JOIN pg_roles granted_role ON granted_role.oid = m.roleid
     WHERE member_role.rolname = 'iam_migrator'
       AND granted_role.rolname = 'iam_owner'
       AND m.inherit_option IS FALSE
       AND m.set_option IS TRUE
       AND m.admin_option IS FALSE
  ) THEN
    RAISE EXCEPTION 'iam_migrator must have exactly one SET-only, non-admin membership: iam_owner';
  END IF;

  SELECT count(*) INTO v_owner_edges
    FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid = m.member
   WHERE member_role.rolname = 'iam_owner';
  IF v_owner_edges <> 0 THEN
    RAISE EXCEPTION 'iam_owner must not be a member of any additional role';
  END IF;

  -- Neon/PostgreSQL 18 grants the database owner a provider-managed ADMIN
  -- membership on roles created by its CREATEROLE principal. Neon may also
  -- record a separate SET-only edge granted by the database owner itself.
  -- Allow only the actual current database owner, with those exact options;
  -- every other incoming membership remains a hard failure.
  SELECT d.datdba, owner_role.rolname
    INTO v_database_owner, v_database_owner_name
    FROM pg_database d
    JOIN pg_roles owner_role ON owner_role.oid = d.datdba
   WHERE d.datname = current_database();

  IF v_database_owner IS NULL
     OR v_database_owner_name NOT IN ('iam_database_owner', 'iam_bootstrap_admin')
     OR v_database_owner = (SELECT oid FROM pg_roles WHERE rolname IN
          ('iam_owner','iam_migrator','iam_migrator_login',
           'iam_app_runtime','iam_app_runtime_login') LIMIT 1)
     OR pg_has_role(session_user, v_database_owner, 'MEMBER') THEN
    RAISE EXCEPTION 'database owner identity is not an approved provider/bootstrap principal';
  END IF;

  -- iam_migrator may be granted only to the authenticated login and the
  -- actual database owner. Neon/PostgreSQL 18 can expose both a provider-issued
  -- ADMIN edge and one owner-issued SET-only edge for that owner. Accept exactly
  -- those two option shapes; all other grantees and duplicate provider edges fail closed.
  SELECT count(*) INTO v_migrator_grantees
    FROM pg_auth_members m
    JOIN pg_roles granted_role ON granted_role.oid = m.roleid
   WHERE granted_role.rolname = 'iam_migrator';

  IF v_migrator_grantees NOT IN (2, 3)
     OR NOT EXISTS (
       SELECT 1
         FROM pg_auth_members m
         JOIN pg_roles member_role ON member_role.oid = m.member
         JOIN pg_roles granted_role ON granted_role.oid = m.roleid
        WHERE member_role.rolname = 'iam_migrator_login'
          AND granted_role.rolname = 'iam_migrator'
          AND m.inherit_option IS FALSE
          AND m.set_option IS TRUE
          AND m.admin_option IS FALSE
     )
     OR (
       SELECT count(*)
         FROM pg_auth_members m
         JOIN pg_roles grantor_role ON grantor_role.oid = m.grantor
        WHERE m.member = v_database_owner
          AND m.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'iam_migrator')
          AND m.inherit_option IS FALSE
          AND m.set_option IS FALSE
          AND m.admin_option IS TRUE
          AND grantor_role.rolsuper IS TRUE
     ) <> 1
     OR (
       SELECT count(*)
         FROM pg_auth_members m
        WHERE m.member = v_database_owner
          AND m.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'iam_migrator')
          AND m.inherit_option IS FALSE
          AND m.set_option IS TRUE
          AND m.admin_option IS FALSE
          AND m.grantor = v_database_owner
     ) > 1
     OR EXISTS (
       SELECT 1
         FROM pg_auth_members m
         JOIN pg_roles grantor_role ON grantor_role.oid = m.grantor
        WHERE m.member = v_database_owner
          AND m.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'iam_migrator')
          AND NOT (
            (m.inherit_option IS FALSE AND m.set_option IS FALSE
             AND m.admin_option IS TRUE AND grantor_role.rolsuper IS TRUE)
            OR
            (m.inherit_option IS FALSE AND m.set_option IS TRUE
             AND m.admin_option IS FALSE AND m.grantor = v_database_owner)
          )
     )
     OR EXISTS (
       SELECT 1
         FROM pg_auth_members m
         JOIN pg_roles member_role ON member_role.oid = m.member
         JOIN pg_roles granted_role ON granted_role.oid = m.roleid
        WHERE granted_role.rolname = 'iam_migrator'
          AND member_role.rolname NOT IN ('iam_migrator_login', v_database_owner_name)
     ) THEN
    RAISE EXCEPTION 'iam_migrator may be granted only to iam_migrator_login and the exact provider database-owner edges (found % membership rows)', v_migrator_grantees;
  END IF;

  -- iam_owner may be granted to iam_migrator and to the actual database
  -- owner only. Neon records one provider ADMIN edge and may record one
  -- owner-issued SET-only edge; reject every other grantee or option shape.
  SELECT count(*) INTO v_owner_grantees
    FROM pg_auth_members m
    JOIN pg_roles granted_role ON granted_role.oid = m.roleid
   WHERE granted_role.rolname = 'iam_owner';

  IF v_owner_grantees NOT IN (2, 3)
     OR NOT EXISTS (
       SELECT 1
         FROM pg_auth_members m
         JOIN pg_roles member_role ON member_role.oid = m.member
         JOIN pg_roles granted_role ON granted_role.oid = m.roleid
        WHERE member_role.rolname = 'iam_migrator'
          AND granted_role.rolname = 'iam_owner'
          AND m.inherit_option IS FALSE
          AND m.set_option IS TRUE
          AND m.admin_option IS FALSE
     )
     OR NOT EXISTS (
       SELECT 1
         FROM pg_auth_members m
         JOIN pg_roles grantor_role ON grantor_role.oid = m.grantor
        WHERE m.member = v_database_owner
          AND m.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'iam_owner')
          AND m.inherit_option IS FALSE
          AND m.set_option IS FALSE
          AND m.admin_option IS TRUE
          AND grantor_role.rolsuper IS TRUE
     )
     OR EXISTS (
       SELECT 1
         FROM pg_auth_members m
         JOIN pg_roles grantor_role ON grantor_role.oid = m.grantor
        WHERE m.member = v_database_owner
          AND m.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'iam_owner')
          AND NOT (
            (m.inherit_option IS FALSE AND m.set_option IS FALSE
             AND m.admin_option IS TRUE AND grantor_role.rolsuper IS TRUE)
            OR
            (m.inherit_option IS FALSE AND m.set_option IS TRUE
             AND m.admin_option IS FALSE AND m.grantor = v_database_owner)
          )
     )
     OR EXISTS (
       SELECT 1
         FROM pg_auth_members m
         JOIN pg_roles member_role ON member_role.oid = m.member
         JOIN pg_roles granted_role ON granted_role.oid = m.roleid
        WHERE granted_role.rolname = 'iam_owner'
          AND member_role.rolname NOT IN ('iam_migrator', v_database_owner_name)
     ) THEN
    RAISE EXCEPTION 'iam_owner may be granted only to iam_migrator and the exact provider database-owner edges (found % grantees)', v_owner_grantees;
  END IF;

  IF NOT pg_has_role(session_user, 'iam_owner', 'MEMBER')
     OR pg_has_role(session_user, 'iam_owner', 'USAGE') THEN
    RAISE EXCEPTION 'migrator login must have SET-only transitive membership, never inherited owner privileges';
  END IF;
END
$authenticated_role_preflight$;

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

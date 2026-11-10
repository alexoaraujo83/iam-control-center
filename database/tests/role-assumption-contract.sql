-- CI-only assertions against the disposable PostgreSQL 18 bootstrap fixture.
-- The bootstrap and migration runner create the roles and authenticate the
-- migrator login. This file must not GRANT memberships or simulate a login.
\set ON_ERROR_STOP on

DO $assert_role_attributes$
DECLARE
  membership record;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles
     WHERE rolname = 'iam_migrator_login'
       AND rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
  ) THEN
    RAISE EXCEPTION 'migrator login must be LOGIN, NOINHERIT, NOSUPERUSER, NOBYPASSRLS';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_roles
     WHERE rolname IN ('iam_owner','iam_migrator','iam_app_runtime')
       AND (rolcanlogin OR rolsuper OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'group roles must remain NOLOGIN/NOSUPERUSER/NOBYPASSRLS';
  END IF;

  IF NOT has_database_privilege('iam_owner', current_database(), 'CREATE')
     OR has_database_privilege('iam_migrator_login', current_database(), 'CREATE')
     OR has_database_privilege('iam_app_runtime_login', current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'database CREATE must be held only by iam_owner';
  END IF;

  SELECT m.admin_option, m.inherit_option, m.set_option
    INTO membership
    FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid = m.member
    JOIN pg_roles granted_role ON granted_role.oid = m.roleid
   WHERE member_role.rolname = 'iam_migrator'
     AND granted_role.rolname = 'iam_owner';
  IF NOT FOUND OR membership.admin_option OR membership.inherit_option OR NOT membership.set_option THEN
    RAISE EXCEPTION 'iam_migrator -> iam_owner must be ADMIN FALSE, INHERIT FALSE, SET TRUE';
  END IF;

  SELECT m.admin_option, m.inherit_option, m.set_option
    INTO membership
    FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid = m.member
    JOIN pg_roles granted_role ON granted_role.oid = m.roleid
   WHERE member_role.rolname = 'iam_migrator_login'
     AND granted_role.rolname = 'iam_migrator';
  IF NOT FOUND OR membership.admin_option OR membership.inherit_option OR NOT membership.set_option THEN
    RAISE EXCEPTION 'iam_migrator_login -> iam_migrator must be ADMIN FALSE, INHERIT FALSE, SET TRUE';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_auth_members m
      JOIN pg_roles member_role ON member_role.oid = m.member
      JOIN pg_roles granted_role ON granted_role.oid = m.roleid
     WHERE member_role.rolname = 'iam_migrator_login'
       AND granted_role.rolname = 'iam_owner'
  ) THEN
    RAISE EXCEPTION 'migrator login must use the intermediary iam_migrator role';
  END IF;

  IF pg_has_role('iam_migrator_login', 'iam_owner', 'USAGE') THEN
    RAISE EXCEPTION 'migrator login must not inherit owner privileges';
  END IF;
  IF NOT pg_has_role('iam_migrator_login', 'iam_owner', 'MEMBER') THEN
    RAISE EXCEPTION 'migrator login must retain the explicit transitive SET path to owner';
  END IF;
  IF pg_has_role('iam_app_runtime_login', 'iam_owner', 'MEMBER')
     OR pg_has_role('iam_app_runtime_login', 'iam_migrator', 'MEMBER')
     OR pg_has_role('iam_app_runtime', 'iam_owner', 'MEMBER')
     OR pg_has_role('iam_app_runtime', 'iam_migrator', 'MEMBER') THEN
    RAISE EXCEPTION 'runtime must not be a member of owner or migrator';
  END IF;
END
$assert_role_attributes$;

DO $assert_bootstrap_admin_is_locked$
DECLARE
  admin_edges integer;
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_roles
     WHERE rolname = 'iam_bootstrap_admin'
       AND NOT rolcanlogin
       AND NOT rolcreaterole
       AND NOT rolsuper
       AND NOT rolcreatedb
       AND NOT rolbypassrls
  ) THEN
    RAISE EXCEPTION 'bootstrap administrator must be disabled after one-time provisioning';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_authid
     WHERE rolname = 'iam_bootstrap_admin'
       AND rolpassword IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'bootstrap administrator password must be cleared after provisioning';
  END IF;

  -- PostgreSQL 18 creates an implicit ADMIN membership for the role creator.
  -- The grantor is the bootstrap superuser, so the creator cannot revoke it.
  -- The membership is acceptable only because the principal is NOLOGIN,
  -- NOCREATEROLE, and has neither INHERIT nor SET on these memberships.
  SELECT count(*)
    INTO admin_edges
    FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid = m.member
    JOIN pg_roles granted_role ON granted_role.oid = m.roleid
   WHERE member_role.rolname = 'iam_bootstrap_admin'
     AND granted_role.rolname IN ('iam_owner','iam_migrator','iam_app_runtime')
     AND m.admin_option
     AND NOT m.inherit_option
     AND NOT m.set_option;

  IF admin_edges <> 3 THEN
    RAISE EXCEPTION 'expected exactly three inert PostgreSQL 18 creator memberships; found %', admin_edges;
  END IF;
END
$assert_bootstrap_admin_is_locked$;

DO $assert_no_unexpected_iam_edges$
DECLARE edge_count integer;
BEGIN
  SELECT count(*)
    INTO edge_count
    FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid = m.member
    JOIN pg_roles granted_role ON granted_role.oid = m.roleid
   WHERE member_role.rolname IN (
           'iam_owner','iam_migrator','iam_migrator_login',
           'iam_app_runtime','iam_app_runtime_login'
         );
  IF edge_count <> 3 THEN
    RAISE EXCEPTION 'expected exactly three memberships granted to IAM principals; found %', edge_count;
  END IF;
  IF EXISTS (
    SELECT 1
      FROM pg_auth_members m
      JOIN pg_roles member_role ON member_role.oid = m.member
     WHERE member_role.rolname IN (
       'iam_owner','iam_migrator','iam_migrator_login',
       'iam_app_runtime','iam_app_runtime_login'
     )
       AND m.admin_option
  ) THEN
    RAISE EXCEPTION 'IAM principals must not hold ADMIN OPTION memberships';
  END IF;
END
$assert_no_unexpected_iam_edges$;

DO $assert_session_role_contract$
BEGIN
  -- The runner executes migration 0001 through an authenticated
  -- iam_migrator_login session and performs both SET ROLE transitions.
  -- This block runs as the disposable test administrator and checks the
  -- membership/privilege contract; it does not impersonate that session.
  IF NOT pg_has_role('iam_migrator_login', 'iam_migrator', 'MEMBER')
     OR NOT pg_has_role('iam_migrator', 'iam_owner', 'MEMBER') THEN
    RAISE EXCEPTION 'migrator role-assumption chain is incomplete';
  END IF;
  RAISE NOTICE 'PASS local migrator role-assumption contract: exact memberships, no inherited owner privileges, no runtime escalation';
END
$assert_session_role_contract$;

-- IAM Control Center — role bootstrap (REVIEW PROPOSAL ONLY)
-- PostgreSQL 18. Run only after independent approval and a verified recovery point.
-- This file creates roles and memberships; it is NOT a migration and is NOT
-- invoked by application startup. It deliberately creates LOGIN roles without
-- passwords. Provision credentials separately through an approved secret path.
--
-- Administrative principal requirements:
--   * authenticated session (session_user = current_user)
--   * NOSUPERUSER + CREATEROLE
--   * owner of the target database
-- The Neon project owner may have BYPASSRLS/CREATEDB/REPLICATION. Those
-- attributes are accepted only for this one-time administrative bootstrap;
-- this principal must never be configured as an application runtime.

\set ON_ERROR_STOP on
BEGIN;

DO $preflight$
DECLARE
  admin_role record;
  database_owner oid;
BEGIN
  SELECT rolcanlogin, rolsuper, rolcreaterole
    INTO admin_role
    FROM pg_roles
   WHERE rolname = current_user;

  IF current_user <> 'iam_bootstrap_admin' THEN
    RAISE EXCEPTION 'bootstrap must use the dedicated iam_bootstrap_admin principal';
  END IF;

  IF NOT FOUND OR session_user <> current_user
     OR NOT admin_role.rolcanlogin
     OR admin_role.rolsuper
     OR NOT admin_role.rolcreaterole THEN
    RAISE EXCEPTION
      'bootstrap requires a direct, non-superuser LOGIN with CREATEROLE; session_user must equal current_user';
  END IF;

  SELECT datdba INTO database_owner
    FROM pg_database
   WHERE datname = current_database();

  IF database_owner <> (SELECT oid FROM pg_roles WHERE rolname = current_user) THEN
    RAISE EXCEPTION
      'bootstrap principal must own target database %', current_database();
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_roles
     WHERE rolname IN (
       'iam_owner',
       'iam_migrator',
       'iam_migrator_login',
       'iam_app_runtime',
       'iam_app_runtime_login'
     )
  ) THEN
    RAISE EXCEPTION
      'one or more target IAM roles already exist; bootstrap is intentionally non-idempotent';
  END IF;
END
$preflight$;

-- NOLOGIN group roles: never use these as connection credentials.
CREATE ROLE iam_owner
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;

CREATE ROLE iam_migrator
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;

CREATE ROLE iam_app_runtime
  NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;

-- LOGIN roles are created without passwords. They cannot authenticate with
-- password-based methods until credentials are provisioned out-of-band.
CREATE ROLE iam_migrator_login
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;

CREATE ROLE iam_app_runtime_login
  LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;

-- PostgreSQL 18 / Neon may retain provider-managed ADMIN memberships for the
-- database owner. Do not attempt to ALTER the authenticated bootstrap role here:
-- PostgreSQL does not permit this least-privilege principal to disable itself.
-- A separate, independently privileged operator must lock the one-time login
-- after this transaction commits. Never reuse it as an application runtime.

-- Exact, non-admin membership topology expected by migration 0001.
GRANT iam_owner TO iam_migrator
  WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;

GRANT iam_migrator TO iam_migrator_login
  WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;

-- Runtime inherits only the runtime group. It cannot SET ROLE and cannot
-- administer memberships. Schema/table privileges and RLS policies are
-- intentionally NOT granted by this bootstrap.
GRANT iam_app_runtime TO iam_app_runtime_login
  WITH INHERIT TRUE, SET FALSE, ADMIN FALSE;

-- The migrator needs CREATE on the database to create the owned schemas.
-- CONNECT is granted explicitly to the two LOGIN principals; no other
-- database privileges are added here.
DO $database_grants$
BEGIN
  -- PostgreSQL grants CONNECT and TEMP to PUBLIC by default. Remove those
  -- ambient privileges so the two LOGIN principals receive CONNECT explicitly.
  EXECUTE format(
    'REVOKE CONNECT, TEMP ON DATABASE %I FROM PUBLIC',
    current_database()
  );
  EXECUTE format(
    'GRANT CREATE ON DATABASE %I TO iam_owner',
    current_database()
  );
  EXECUTE format(
    'GRANT CONNECT ON DATABASE %I TO iam_migrator_login, iam_app_runtime_login',
    current_database()
  );
END
$database_grants$;

-- Deliberately do not ALTER CURRENT_USER. The caller cannot reliably disable
-- its own LOGIN under PostgreSQL's role-management rules; lock it separately.

COMMIT;

-- CI fixture for the incremental context-key hardening migration.
-- This is deliberately NOT a full production-schema dump and is never deployed.
-- It models only the reviewed source objects read or changed by 0001_context_key_hardening.sql.
-- Source: Neon project twilight-fire-88497009 / database iam_database.
-- Object definitions were inspected from the source branch on 2026-11-05.
-- The migration's precondition is the pre-hardening search_path including public.

\set ON_ERROR_STOP on
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

SET ROLE iam_owner;
CREATE SCHEMA iam AUTHORIZATION iam_owner;
CREATE SCHEMA audit AUTHORIZATION iam_owner;
CREATE SCHEMA app_private AUTHORIZATION iam_owner;

CREATE TABLE iam.tenants (
  id uuid PRIMARY KEY,
  status text NOT NULL
);
CREATE TABLE iam.identities (
  id uuid PRIMARY KEY,
  status text NOT NULL
);
CREATE TABLE iam.memberships (
  tenant_id uuid NOT NULL,
  identity_id uuid NOT NULL,
  status text NOT NULL,
  PRIMARY KEY (tenant_id, identity_id)
);

CREATE TABLE iam.schema_migrations (
  migration_id text PRIMARY KEY,
  checksum_sha256 character(64) NOT NULL
    CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
  source_sha text
    CHECK (source_sha IS NULL OR source_sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  execution_role name NOT NULL
);

CREATE TABLE app_private.context_keys (
  key_id text PRIMARY KEY,
  secret bytea NOT NULL CHECK (octet_length(secret) >= 32),
  active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION iam.acquire_migration_lock()
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path TO pg_catalog
AS $function$
  SELECT pg_advisory_xact_lock(721347, 18001)
$function$;

CREATE OR REPLACE FUNCTION iam.record_migration(
  p_migration_id text,
  p_checksum_sha256 text,
  p_source_sha text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO pg_catalog, iam
AS $function$
DECLARE
  v_existing char(64);
BEGIN
  IF p_migration_id IS NULL OR p_migration_id !~ '^[0-9]{4}_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'invalid migration id';
  END IF;
  IF p_checksum_sha256 IS NULL OR p_checksum_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid SHA-256 checksum';
  END IF;
  IF p_source_sha IS NOT NULL
     AND p_source_sha !~ '^([0-9a-f]{40}|[0-9a-f]{64})$' THEN
    RAISE EXCEPTION 'invalid source SHA';
  END IF;

  SELECT checksum_sha256 INTO v_existing
    FROM iam.schema_migrations
   WHERE migration_id = p_migration_id;
  IF FOUND THEN
    IF v_existing <> p_checksum_sha256 THEN
      RAISE EXCEPTION 'migration checksum mismatch for %', p_migration_id;
    END IF;
    RETURN;
  END IF;

  INSERT INTO iam.schema_migrations (
    migration_id, checksum_sha256, source_sha, execution_role
  ) VALUES (
    p_migration_id, p_checksum_sha256, p_source_sha, session_user
  );
END;
$function$;

CREATE OR REPLACE FUNCTION app_private.current_tenant_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path TO pg_catalog, app_private, iam, public
AS $function$
DECLARE
  v_tenant uuid;
  v_identity uuid;
  v_expires bigint;
  v_nonce text;
  v_signature text;
  v_secret bytea;
  v_payload text;
BEGIN
  v_tenant := nullif(current_setting('iam.tenant_id', true), '')::uuid;
  v_identity := nullif(current_setting('iam.identity_id', true), '')::uuid;
  v_expires := nullif(current_setting('iam.expires_at', true), '')::bigint;
  v_nonce := nullif(current_setting('iam.nonce', true), '');
  v_signature := nullif(current_setting('iam.signature', true), '');
  IF v_tenant IS NULL OR v_identity IS NULL OR v_expires IS NULL
     OR v_nonce IS NULL OR v_signature IS NULL THEN
    RETURN NULL;
  END IF;
  IF v_expires < extract(epoch FROM clock_timestamp())::bigint
     OR v_expires > extract(epoch FROM clock_timestamp())::bigint + 300 THEN
    RETURN NULL;
  END IF;
  SELECT secret INTO v_secret
    FROM app_private.context_keys
   WHERE active;
  IF v_secret IS NULL THEN
    RETURN NULL;
  END IF;
  v_payload := v_tenant::text || '|' || v_identity::text || '|'
    || v_expires::text || '|' || v_nonce;
  IF encode(public.hmac(convert_to(v_payload, 'UTF8'), v_secret, 'sha256'), 'hex')
     <> lower(v_signature) THEN
    RETURN NULL;
  END IF;
  IF NOT EXISTS (
    SELECT 1
      FROM iam.memberships m
      JOIN iam.tenants t ON t.id = m.tenant_id
      JOIN iam.identities i ON i.id = m.identity_id
     WHERE m.tenant_id = v_tenant
       AND m.identity_id = v_identity
       AND m.status = 'active'
       AND t.status = 'active'
       AND i.status = 'active'
  ) THEN
    RETURN NULL;
  END IF;
  RETURN v_tenant;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$function$;



CREATE OR REPLACE FUNCTION iam.set_tenant_context(
  p_tenant_id uuid,
  p_identity_id uuid,
  p_expires_at bigint,
  p_nonce text,
  p_signature text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO pg_catalog, app_private, iam, public
AS $function$
BEGIN
  PERFORM set_config('iam.tenant_id', p_tenant_id::text, true);
  PERFORM set_config('iam.identity_id', p_identity_id::text, true);
  PERFORM set_config('iam.expires_at', p_expires_at::text, true);
  PERFORM set_config('iam.nonce', p_nonce, true);
  PERFORM set_config('iam.signature', p_signature, true);
  IF app_private.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
    PERFORM set_config('iam.tenant_id', '', true);
    PERFORM set_config('iam.identity_id', '', true);
    PERFORM set_config('iam.expires_at', '', true);
    PERFORM set_config('iam.nonce', '', true);
    PERFORM set_config('iam.signature', '', true);
    RAISE EXCEPTION 'invalid or expired tenant context' USING ERRCODE = '42501';
  END IF;
END;
$function$;
ALTER FUNCTION iam.set_tenant_context(uuid, uuid, bigint, text, text) OWNER TO iam_owner;

CREATE OR REPLACE FUNCTION iam.clear_tenant_context()
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path TO pg_catalog
AS $function$
  SELECT set_config('iam.tenant_id', '', true),
         set_config('iam.identity_id', '', true),
         set_config('iam.expires_at', '', true),
         set_config('iam.nonce', '', true),
         set_config('iam.signature', '', true)
$function$;
ALTER FUNCTION iam.clear_tenant_context() OWNER TO iam_owner;

REVOKE ALL ON SCHEMA iam, audit, app_private FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA iam, app_private FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam, app_private FROM PUBLIC;

-- Reproduce the minimal source privileges required by the migration principal.
-- The bootstrap intentionally grants no schema/table/function privileges.
GRANT USAGE ON SCHEMA iam TO iam_migrator;
GRANT SELECT ON TABLE iam.schema_migrations TO iam_migrator;
GRANT EXECUTE ON FUNCTION iam.acquire_migration_lock() TO iam_migrator;
GRANT EXECUTE ON FUNCTION iam.record_migration(text, text, text) TO iam_migrator;
RESET ROLE;

GRANT EXECUTE ON FUNCTION iam.set_tenant_context(uuid, uuid, bigint, text, text) TO iam_app_runtime;
GRANT EXECUTE ON FUNCTION iam.clear_tenant_context() TO iam_app_runtime;

-- IAM Control Center — migration 0001 (REVIEW PROPOSAL)
-- PostgreSQL 18; clean database only. No extensions, seeds, policies or runtime grants.
-- RLS without policies is intentional default-deny. Never execute on Neon before approval.

BEGIN;
DO $preflight$
DECLARE
  role_name text;
  role_row record;
  session_role_row record;
  expected_inherit boolean;
BEGIN
  IF current_user <> 'iam_owner' THEN
    RAISE EXCEPTION 'effective current_user must be iam_owner; got %', current_user;
  END IF;
  IF NOT has_database_privilege(current_user, current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'iam_owner must have CREATE privilege on database %', current_database();
  END IF;

  SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
    INTO session_role_row
    FROM pg_roles
   WHERE rolname = session_user;
  IF NOT FOUND OR session_user <> 'iam_migrator_login'
     OR NOT session_role_row.rolcanlogin OR session_role_row.rolinherit
     OR session_role_row.rolsuper OR session_role_row.rolcreatedb
     OR session_role_row.rolcreaterole OR session_role_row.rolreplication
     OR session_role_row.rolbypassrls THEN
    RAISE EXCEPTION 'migration session must be a non-privileged LOGIN role';
  END IF;

  -- Fail closed if any IAM group role has an administrative attribute.
  -- INHERIT is part of the declared role contract, not an incidental default.
  FOREACH role_name IN ARRAY ARRAY['iam_owner','iam_migrator','iam_app_runtime'] LOOP
    expected_inherit := (role_name = 'iam_app_runtime');
    SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole,
           rolreplication, rolbypassrls
      INTO role_row
      FROM pg_roles
     WHERE rolname = role_name;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'required role % missing; migration does not create roles', role_name;
    END IF;
    IF role_row.rolcanlogin THEN
      RAISE EXCEPTION 'role % must be NOLOGIN', role_name;
    END IF;
    IF role_row.rolinherit IS DISTINCT FROM expected_inherit THEN
      RAISE EXCEPTION 'role % has unexpected INHERIT attribute', role_name;
    END IF;
    IF role_row.rolsuper OR role_row.rolcreatedb OR role_row.rolcreaterole
       OR role_row.rolreplication OR role_row.rolbypassrls THEN
      RAISE EXCEPTION 'role % has a prohibited administrative attribute', role_name;
    END IF;
  END LOOP;

  -- Require the exact two-step migration capability chain; no direct
  -- login-to-owner grant and no inherited/admin membership is accepted.
  IF NOT EXISTS (
    SELECT 1
      FROM pg_auth_members m
      JOIN pg_roles member_role ON member_role.oid = m.member
      JOIN pg_roles granted_role ON granted_role.oid = m.roleid
     WHERE member_role.rolname = 'iam_migrator_login'
       AND granted_role.rolname = 'iam_migrator'
       AND m.inherit_option IS FALSE
       AND m.set_option IS TRUE
       AND m.admin_option IS FALSE
  ) OR NOT EXISTS (
    SELECT 1
      FROM pg_auth_members m
      JOIN pg_roles member_role ON member_role.oid = m.member
      JOIN pg_roles granted_role ON granted_role.oid = m.roleid
     WHERE member_role.rolname = 'iam_migrator'
       AND granted_role.rolname = 'iam_owner'
       AND m.inherit_option IS FALSE
       AND m.set_option IS TRUE
       AND m.admin_option IS FALSE
  ) OR EXISTS (
    SELECT 1
      FROM pg_auth_members m
      JOIN pg_roles member_role ON member_role.oid = m.member
      JOIN pg_roles granted_role ON granted_role.oid = m.roleid
     WHERE member_role.rolname = 'iam_migrator_login'
       AND granted_role.rolname = 'iam_owner'
  ) THEN
    RAISE EXCEPTION 'migration requires the exact iam_migrator_login -> iam_migrator -> iam_owner SET chain';
  END IF;

  -- Check the complete SET-capable membership graph, including the session
  -- login. The expected migrator -> owner path is allowed; privileged targets
  -- (including provider-managed neon_superuser) are never allowed.
  IF EXISTS (
    WITH RECURSIVE role_memberships(root_role, granted_role, path) AS (
      SELECT root.oid, m.roleid, ARRAY[root.oid, m.roleid]::oid[]
        FROM pg_roles root
        JOIN pg_auth_members m ON m.member = root.oid
       WHERE root.rolname IN ('iam_owner','iam_migrator','iam_app_runtime',session_user)
      UNION ALL
      SELECT rm.root_role, m.roleid, rm.path || m.roleid
        FROM role_memberships rm
        JOIN pg_auth_members m ON m.member = rm.granted_role
       WHERE NOT m.roleid = ANY(rm.path)
    )
    SELECT 1
      FROM role_memberships rm
      JOIN pg_roles granted ON granted.oid = rm.granted_role
     WHERE granted.rolname = 'neon_superuser'
        OR granted.rolsuper
        OR granted.rolcreatedb
        OR granted.rolcreaterole
        OR granted.rolreplication
        OR granted.rolbypassrls
  ) THEN
    RAISE EXCEPTION 'IAM roles or migration session have membership in a privileged role';
  END IF;

  IF to_regnamespace('iam') IS NOT NULL OR to_regnamespace('audit') IS NOT NULL
     OR to_regnamespace('app_private') IS NOT NULL THEN
    RAISE EXCEPTION 'migration 0001 requires a clean database; target schema already exists';
  END IF;
END $preflight$;

CREATE SCHEMA iam AUTHORIZATION iam_owner;
CREATE SCHEMA audit AUTHORIZATION iam_owner;
CREATE SCHEMA app_private AUTHORIZATION iam_owner;

CREATE TABLE iam.tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text UNIQUE,
  display_name text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 160),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenants_slug_format CHECK (slug IS NULL OR slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
);

CREATE TABLE iam.identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issuer text NOT NULL CHECK (issuer ~ '^https://[^[:space:]]+$'),
  subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  email text, email_verified boolean NOT NULL DEFAULT false, display_name text,
  last_authenticated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT identities_issuer_subject_key UNIQUE (issuer, subject)
);

CREATE TABLE iam.memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES iam.tenants(id) ON DELETE RESTRICT,
  identity_id uuid NOT NULL REFERENCES iam.identities(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'invited' CHECK (status IN ('invited','active','suspended','revoked')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT memberships_id_tenant_id_key UNIQUE (id, tenant_id),
  CONSTRAINT memberships_id_tenant_identity_key UNIQUE (id, tenant_id, identity_id),
  CONSTRAINT memberships_tenant_identity_key UNIQUE (tenant_id, identity_id)
);

CREATE TABLE iam.roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES iam.tenants(id) ON DELETE RESTRICT,
  key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_.:-]{0,95}$'),
  display_name text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 120),
  description text, is_system boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT roles_id_tenant_id_key UNIQUE (id, tenant_id),
  CONSTRAINT roles_tenant_key_key UNIQUE (tenant_id, key)
);

CREATE TABLE iam.permissions (
  key text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
  description text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.membership_roles (
  tenant_id uuid NOT NULL, membership_id uuid NOT NULL, role_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (membership_id, role_id),
  CONSTRAINT membership_roles_membership_tenant_fk FOREIGN KEY (membership_id, tenant_id)
    REFERENCES iam.memberships(id, tenant_id) ON DELETE CASCADE,
  CONSTRAINT membership_roles_role_tenant_fk FOREIGN KEY (role_id, tenant_id)
    REFERENCES iam.roles(id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE iam.role_permissions (
  tenant_id uuid NOT NULL, role_id uuid NOT NULL,
  permission_key text NOT NULL REFERENCES iam.permissions(key) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (role_id, permission_key),
  CONSTRAINT role_permissions_role_tenant_fk FOREIGN KEY (role_id, tenant_id)
    REFERENCES iam.roles(id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE iam.invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES iam.tenants(id) ON DELETE RESTRICT,
  email_normalized text NOT NULL CHECK (email_normalized = lower(btrim(email_normalized))),
  token_hash bytea NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','revoked','expired')),
  expires_at timestamptz NOT NULL, invited_by_membership_id uuid,
  accepted_by_identity_id uuid REFERENCES iam.identities(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT invitations_inviter_tenant_fk FOREIGN KEY (invited_by_membership_id, tenant_id)
    REFERENCES iam.memberships(id, tenant_id) ON DELETE RESTRICT
);

CREATE TABLE audit.events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  tenant_id uuid REFERENCES iam.tenants(id) ON DELETE RESTRICT,
  actor_identity_id uuid REFERENCES iam.identities(id) ON DELETE RESTRICT,
  actor_membership_id uuid,
  action text NOT NULL CHECK (length(action) BETWEEN 1 AND 160),
  target_type text, target_id text,
  outcome text NOT NULL CHECK (outcome IN ('success','denied','failure')),
  request_id text, metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata)='object'),
  CONSTRAINT events_actor_membership_identity_required
    CHECK (actor_membership_id IS NULL OR (tenant_id IS NOT NULL AND actor_identity_id IS NOT NULL)),
  CONSTRAINT events_actor_membership_tenant_identity_fk
    FOREIGN KEY (actor_membership_id, tenant_id, actor_identity_id)
    REFERENCES iam.memberships(id, tenant_id, identity_id) ON DELETE RESTRICT
);

-- Administrative migration ledger: no runtime/PUBLIC grants, so RLS is not needed here.
-- Keeping FORCE RLS off permits the migration principal (iam_owner) to verify/write checksums.
CREATE TABLE iam.schema_migrations (
  version text PRIMARY KEY, name text NOT NULL,
  checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
  applied_at timestamptz NOT NULL DEFAULT now(), applied_by text NOT NULL DEFAULT current_user
);

CREATE INDEX memberships_identity_status_idx ON iam.memberships(identity_id, status);
CREATE INDEX memberships_tenant_status_idx ON iam.memberships(tenant_id, status);
CREATE INDEX membership_roles_tenant_membership_idx ON iam.membership_roles(tenant_id, membership_id);
CREATE INDEX role_permissions_tenant_role_idx ON iam.role_permissions(tenant_id, role_id);
CREATE INDEX invitations_tenant_status_expiry_idx ON iam.invitations(tenant_id, status, expires_at);
CREATE INDEX audit_events_tenant_time_idx ON audit.events(tenant_id, occurred_at DESC);
CREATE INDEX audit_events_actor_time_idx ON audit.events(actor_identity_id, occurred_at DESC);

-- Business/audit tables are RLS-enabled and forced. No policy = default deny.
-- schema_migrations is intentionally excluded as privileged migration metadata.
DO $rls$
DECLARE item record;
BEGIN
  FOR item IN SELECT * FROM (VALUES
    ('iam','tenants'),('iam','identities'),('iam','memberships'),('iam','roles'),
    ('iam','permissions'),('iam','membership_roles'),('iam','role_permissions'),
    ('iam','invitations'),('audit','events')
  ) AS t(schema_name,table_name)
  LOOP
    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',item.schema_name,item.table_name);
    EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',item.schema_name,item.table_name);
  END LOOP;
END $rls$;

REVOKE ALL ON SCHEMA iam, audit, app_private FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA iam, audit FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam, audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_private FROM PUBLIC;
COMMIT;

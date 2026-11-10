-- CI-only tests. Run as PostgreSQL superuser on disposable PostgreSQL 18.
\set ON_ERROR_STOP on

DO $assert_schema$
DECLARE expected_count integer; actual_count integer;
BEGIN
  SELECT count(*) INTO expected_count FROM (VALUES
    ('iam','tenants'),('iam','identities'),('iam','memberships'),('iam','roles'),
    ('iam','permissions'),('iam','membership_roles'),('iam','role_permissions'),
    ('iam','invitations'),('iam','schema_migrations'),('audit','events')
  ) AS expected(schema_name,table_name);
  SELECT count(*) INTO actual_count
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE (n.nspname,c.relname) IN (
    ('iam','tenants'),('iam','identities'),('iam','memberships'),('iam','roles'),
    ('iam','permissions'),('iam','membership_roles'),('iam','role_permissions'),
    ('iam','invitations'),('iam','schema_migrations'),('audit','events')
  ) AND c.relkind='r';
  IF actual_count <> expected_count THEN
    RAISE EXCEPTION 'expected % tables, found %',expected_count,actual_count;
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_namespace n
    WHERE n.nspname IN ('iam','audit','app_private')
      AND n.nspowner <> (SELECT oid FROM pg_roles WHERE rolname='iam_owner')
  ) THEN
    RAISE EXCEPTION 'all IAM schemas must be owned by iam_owner';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname IN ('iam','audit') AND c.relkind='r'
      AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname='iam_owner')
  ) THEN
    RAISE EXCEPTION 'all IAM tables must be owned by iam_owner';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname IN ('iam','audit') AND c.relkind='r'
      AND NOT (n.nspname='iam' AND c.relname='schema_migrations')
      AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
  ) THEN RAISE EXCEPTION 'RLS must be enabled and forced on every business/audit table'; END IF;
  IF (SELECT relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='iam' AND c.relname='schema_migrations') THEN
    RAISE EXCEPTION 'migration ledger must remain outside RLS';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('iam','audit')
  ) THEN RAISE EXCEPTION 'baseline must not create RLS policies'; END IF;
  IF (SELECT is_nullable FROM information_schema.columns
      WHERE table_schema='iam' AND table_name='tenants' AND column_name='slug') <> 'YES'
  THEN RAISE EXCEPTION 'tenant slug must be nullable'; END IF;
  IF EXISTS (
    SELECT 1 FROM pg_roles
     WHERE rolname IN ('iam_owner','iam_migrator','iam_app_runtime')
       AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole
            OR rolreplication OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'IAM group roles must be NOLOGIN and have no administrative attributes';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_roles
     WHERE (rolname='iam_app_runtime' AND NOT rolinherit)
        OR (rolname IN ('iam_owner','iam_migrator') AND rolinherit)
  ) THEN
    RAISE EXCEPTION 'IAM group role INHERIT attributes do not match the contract';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid=m.member
    JOIN pg_roles granted_role ON granted_role.oid=m.roleid
    WHERE member_role.rolname='iam_migrator_login'
      AND granted_role.rolname='iam_migrator'
      AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid=m.member
    JOIN pg_roles granted_role ON granted_role.oid=m.roleid
    WHERE member_role.rolname='iam_migrator'
      AND granted_role.rolname='iam_owner'
      AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option
  ) OR EXISTS (
    SELECT 1 FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid=m.member
    JOIN pg_roles granted_role ON granted_role.oid=m.roleid
    WHERE member_role.rolname='iam_migrator_login'
      AND granted_role.rolname='iam_owner'
  ) THEN
    RAISE EXCEPTION 'migration role chain must be exact, two-step, SET-only and non-admin';
  END IF;

  IF EXISTS (
    WITH RECURSIVE role_memberships(root_role, granted_role, path) AS (
      SELECT root.oid, m.roleid, ARRAY[root.oid,m.roleid]::oid[]
        FROM pg_roles root
        JOIN pg_auth_members m ON m.member=root.oid
       WHERE root.rolname IN ('iam_owner','iam_migrator','iam_app_runtime')
      UNION ALL
      SELECT rm.root_role, m.roleid, rm.path || m.roleid
        FROM role_memberships rm
        JOIN pg_auth_members m ON m.member=rm.granted_role
       WHERE NOT m.roleid=ANY(rm.path)
    )
    SELECT 1
      FROM role_memberships rm
      JOIN pg_roles granted ON granted.oid=rm.granted_role
     WHERE granted.rolname='neon_superuser'
        OR granted.rolsuper OR granted.rolcreatedb OR granted.rolcreaterole
        OR granted.rolreplication OR granted.rolbypassrls
  ) THEN
    RAISE EXCEPTION 'IAM group roles must not inherit or assume privileged roles';
  END IF;
  IF has_table_privilege('iam_app_runtime','iam.schema_migrations','SELECT')
     OR has_table_privilege('iam_app_runtime','iam.schema_migrations','INSERT') THEN
    RAISE EXCEPTION 'runtime must not access migration ledger';
  END IF;
END $assert_schema$;

-- Composite FK must reject a membership from tenant A assigned a role from tenant B.
BEGIN;
INSERT INTO iam.tenants(id,slug,display_name) VALUES
 ('00000000-0000-4000-8000-000000000001','tenant-a','Tenant A'),
 ('00000000-0000-4000-8000-000000000002','tenant-b','Tenant B'),
 ('00000000-0000-4000-8000-000000000003',NULL,'Tenant without slug');
INSERT INTO iam.identities(id,issuer,subject) VALUES
 ('00000000-0000-4000-8000-000000000010','https://issuer.example/','subject-a'),
 ('00000000-0000-4000-8000-000000000011','https://issuer.example/','subject-b');
INSERT INTO iam.memberships(id,tenant_id,identity_id,status)
VALUES ('00000000-0000-4000-8000-000000000020',
 '00000000-0000-4000-8000-000000000001',
 '00000000-0000-4000-8000-000000000010','active');
INSERT INTO iam.roles(id,tenant_id,key,display_name)
VALUES ('00000000-0000-4000-8000-000000000030',
 '00000000-0000-4000-8000-000000000002','admin','Admin');
DO $assert_composite_fk$
BEGIN
  BEGIN
    INSERT INTO iam.membership_roles(tenant_id,membership_id,role_id)
    VALUES ('00000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-000000000020',
      '00000000-0000-4000-8000-000000000030');
    RAISE EXCEPTION 'cross-tenant membership-role assignment unexpectedly succeeded';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;
END $assert_composite_fk$;

-- Audit actor identity must match the referenced membership, not merely its tenant.
DO $assert_audit_actor_identity$
BEGIN
  BEGIN
    INSERT INTO audit.events(tenant_id,actor_identity_id,actor_membership_id,action,outcome)
    VALUES ('00000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-000000000011',
      '00000000-0000-4000-8000-000000000020',
      'test.audit.identity-mismatch','failure');
    RAISE EXCEPTION 'audit event accepted an identity different from its membership';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;

  BEGIN
    INSERT INTO audit.events(tenant_id,actor_identity_id,actor_membership_id,action,outcome)
    VALUES ('00000000-0000-4000-8000-000000000001',
      NULL,
      '00000000-0000-4000-8000-000000000020',
      'test.audit.missing-identity','failure');
    RAISE EXCEPTION 'audit event accepted a membership without its actor identity';
  EXCEPTION WHEN check_violation THEN NULL;
  END;

  INSERT INTO audit.events(tenant_id,actor_identity_id,actor_membership_id,action,outcome)
  VALUES ('00000000-0000-4000-8000-000000000001',
    '00000000-0000-4000-8000-000000000010',
    '00000000-0000-4000-8000-000000000020',
    'test.audit.valid-actor','success');
END $assert_audit_actor_identity$;
ROLLBACK;

-- Test-only grants isolate RLS behavior from ordinary SQL privilege errors.
GRANT USAGE ON SCHEMA iam,audit TO iam_app_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON iam.tenants TO iam_app_runtime;
BEGIN;
INSERT INTO iam.tenants(id,slug,display_name)
VALUES ('00000000-0000-4000-8000-000000000101','owner-fixture','Owner fixture');
SET ROLE iam_app_runtime;
DO $assert_default_deny$
DECLARE visible_count integer;
BEGIN
  SELECT count(*) INTO visible_count FROM iam.tenants;
  IF visible_count <> 0 THEN
    RAISE EXCEPTION 'runtime saw % rows without an approved policy',visible_count;
  END IF;
  BEGIN
    INSERT INTO iam.tenants(id,slug,display_name)
    VALUES ('00000000-0000-4000-8000-000000000102','runtime-write','Must be denied');
    RAISE EXCEPTION 'runtime INSERT unexpectedly succeeded without a policy';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $assert_default_deny$;
RESET ROLE;
ROLLBACK;

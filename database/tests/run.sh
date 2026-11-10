#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?DATABASE_URL must point to the disposable PostgreSQL administrator database}"
: "${BOOTSTRAP_DATABASE_URL:?BOOTSTRAP_DATABASE_URL must authenticate as iam_bootstrap_admin}"
: "${MIGRATOR_DATABASE_URL:?MIGRATOR_DATABASE_URL must authenticate as iam_migrator_login}"
: "${POSTGRES_TEST_PASSWORD:?POSTGRES_TEST_PASSWORD must be unique to this disposable CI run}"

# Generate credentials at runtime. Never commit fixed passwords or hashes.
BOOTSTRAP_TEST_PASSWORD="${BOOTSTRAP_TEST_PASSWORD:-$(openssl rand -hex 32)}"
MIGRATOR_TEST_PASSWORD="${MIGRATOR_TEST_PASSWORD:-$(openssl rand -hex 32)}"
export BOOTSTRAP_TEST_PASSWORD MIGRATOR_TEST_PASSWORD

echo "Preparing a non-superuser database-owner fixture for the role bootstrap..."
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v bootstrap_password="$BOOTSTRAP_TEST_PASSWORD" <<'SQL'
CREATE ROLE iam_bootstrap_admin
  LOGIN CREATEROLE NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS
  PASSWORD :'bootstrap_password';
SQL
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "ALTER DATABASE iam_schema_test OWNER TO iam_bootstrap_admin;"

echo "Running the reviewed role bootstrap as its least-privilege administrative principal..."
PGPASSWORD="$BOOTSTRAP_TEST_PASSWORD" psql "$BOOTSTRAP_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f database/bootstrap/0000_iam_roles.sql

echo "Locking the one-time bootstrap principal through the separate PostgreSQL administrator session..."
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "ALTER ROLE iam_bootstrap_admin WITH NOLOGIN NOCREATEROLE PASSWORD NULL;"

echo "Checking role attributes, membership options, and database privileges..."
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f database/tests/0000_role_bootstrap_contract.sql
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f database/tests/role-assumption-contract.sql

echo "Simulating the Neon database-owner SET-only membership recorded by the source catalog..."
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
SET ROLE iam_bootstrap_admin;
GRANT iam_migrator TO iam_bootstrap_admin
  WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
GRANT iam_owner TO iam_bootstrap_admin
  WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
GRANT iam_app_runtime TO iam_bootstrap_admin
  WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
RESET ROLE;
SQL

echo "Verifying the one-time bootstrap principal can no longer authenticate..."
if PGPASSWORD="$BOOTSTRAP_TEST_PASSWORD" psql "$BOOTSTRAP_DATABASE_URL" -v ON_ERROR_STOP=1 -c "SELECT 1;" >/dev/null 2>&1; then
  echo "ERROR: locked bootstrap principal unexpectedly authenticated" >&2
  exit 1
fi
role_count="$(PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c \
  "SELECT count(*) FROM pg_roles WHERE rolname IN ('iam_owner','iam_migrator','iam_migrator_login','iam_app_runtime','iam_app_runtime_login');")"
test "$role_count" = "5"

echo "Verifying PostgreSQL rolls back role DDL after a transaction failure..."
if PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
  "BEGIN; CREATE ROLE iam_bootstrap_rollback_probe NOLOGIN; SELECT 1 / 0; COMMIT;"; then
  echo "ERROR: rollback probe unexpectedly succeeded" >&2
  exit 1
fi
rollback_probe="$(PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c \
  "SELECT count(*) FROM pg_roles WHERE rolname = 'iam_bootstrap_rollback_probe';")"
test "$rollback_probe" = "0"

echo "Provisioning the source-derived baseline fixture on the disposable database..."
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f database/tests/fixtures/iam_database_context_key_baseline.sql

echo "Setting a disposable password only for the authenticated CI migration test..."
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v migrator_password="$MIGRATOR_TEST_PASSWORD" <<'SQL'
ALTER ROLE iam_migrator_login PASSWORD :'migrator_password';
SQL

echo "Verifying the exact historical source migration SHA-256 independently from the hardened regression fixture..."
historical_source="database/archive/source-applied-migrations/applied/0001_context_key_hardening.sql"
historical_digest="2447395628fa0f1230abd95eb522e5b45d1baea1208c9c21b20346a10718fbab"
actual_digest="$(sha256sum "$historical_source" | awk '{print $1}')"
if [[ "$actual_digest" != "$historical_digest" ]]; then
  echo "ERROR: historical migration SQL differs from the source Neon ledger checksum" >&2
  exit 1
fi
echo "PASS: exact historical source artifact matches approved Neon ledger digest"

echo "Running migration over an authenticated non-privileged LOGIN session..."
migration_checksum="$(sha256sum database/archive/source-applied-migrations/0001_context_key_hardening.sql | awk '{print $1}')"
source_sha="$(git rev-parse HEAD)"

# Negative security tests: each privileged attribute and unexpected membership
# must be rejected before SET ROLE/DDL. Confirm the failed transaction leaves
# both the index and migration ledger untouched.
assert_migration_rejected() {
  local scenario="$1"
  if PGPASSWORD="$MIGRATOR_TEST_PASSWORD" psql "$MIGRATOR_DATABASE_URL" -v ON_ERROR_STOP=1 \
    -v migration_checksum="$migration_checksum" -v source_sha="$source_sha" \
    -f database/archive/source-applied-migrations/0001_context_key_hardening.sql >/dev/null 2>&1; then
    echo "ERROR: migration unexpectedly accepted unsafe role state: $scenario" >&2
    exit 1
  fi
  local index_count ledger_count
  index_count="$(PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 \
    -c "SELECT count(*) FROM pg_class WHERE oid = to_regclass('app_private.context_keys_one_active_idx');")"
  ledger_count="$(PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 \
    -c "SELECT count(*) FROM iam.schema_migrations WHERE migration_id = '0001_context_key_hardening';")"
  test "$index_count" = "0"
  test "$ledger_count" = "0"
  echo "PASS: unsafe role state rejected before DDL ($scenario)"
}

for attribute in SUPERUSER BYPASSRLS CREATEROLE CREATEDB; do
  case "$attribute" in
    SUPERUSER) disable_attribute="NOSUPERUSER" ;;
    BYPASSRLS) disable_attribute="NOBYPASSRLS" ;;
    CREATEROLE) disable_attribute="NOCREATEROLE" ;;
    CREATEDB) disable_attribute="NOCREATEDB" ;;
  esac
  PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -c "ALTER ROLE iam_migrator_login $attribute;"
  assert_migration_rejected "$attribute"
  PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -c "ALTER ROLE iam_migrator_login $disable_attribute;"
done

# The owner group role is the final privilege boundary after SET ROLE. It must
# remain non-login, non-admin, and must not be a member of any other role.
for attribute in LOGIN SUPERUSER BYPASSRLS CREATEROLE CREATEDB; do
  case "$attribute" in
    LOGIN) disable_attribute="NOLOGIN" ;;
    SUPERUSER) disable_attribute="NOSUPERUSER" ;;
    BYPASSRLS) disable_attribute="NOBYPASSRLS" ;;
    CREATEROLE) disable_attribute="NOCREATEROLE" ;;
    CREATEDB) disable_attribute="NOCREATEDB" ;;
  esac
  PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -c "ALTER ROLE iam_owner $attribute;"
  assert_migration_rejected "iam_owner $attribute"
  PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -c "ALTER ROLE iam_owner $disable_attribute;"
done

PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "GRANT iam_app_runtime TO iam_owner WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;"
assert_migration_rejected "unexpected membership granted to iam_owner"
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "REVOKE iam_app_runtime FROM iam_owner;"

PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "GRANT iam_owner TO iam_app_runtime_login WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;"
assert_migration_rejected "unapproved login membership granted to iam_owner"
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "REVOKE iam_owner FROM iam_app_runtime_login;"

PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "GRANT iam_app_runtime TO iam_migrator_login WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;"
assert_migration_rejected "unexpected iam_app_runtime membership"
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "REVOKE iam_app_runtime FROM iam_migrator_login;"

PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "GRANT iam_owner TO iam_migrator_login WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;"
assert_migration_rejected "direct iam_owner membership"
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "REVOKE iam_owner FROM iam_migrator_login;"

PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "GRANT iam_migrator TO iam_app_runtime_login WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;"
assert_migration_rejected "unapproved login membership granted to iam_migrator"
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "REVOKE iam_migrator FROM iam_app_runtime_login;"

echo "Running migration over the authenticated, least-privilege LOGIN session..."
PGPASSWORD="$MIGRATOR_TEST_PASSWORD" psql "$MIGRATOR_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -v migration_checksum="$migration_checksum" -v source_sha="$source_sha" \
  -f database/archive/source-applied-migrations/0001_context_key_hardening.sql

# Contract checks inspect the disposable database as its administrator.
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -v migration_checksum="$migration_checksum" -v source_sha="$source_sha" \
  -f database/tests/0001_schema_contract.sql

echo "Applying proposal-only resolver volatility hardening in the disposable CI database..."
resolver_checksum="$(sha256sum database/proposals/0002_context_resolver_volatility_hardening.sql | awk '{print $1}')"
PGPASSWORD="$MIGRATOR_TEST_PASSWORD" psql "$MIGRATOR_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -v migration_checksum="$resolver_checksum" -v source_sha="$source_sha" \
  -f database/proposals/0002_context_resolver_volatility_hardening.sql
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -v resolver_checksum="$resolver_checksum" -v source_sha="$source_sha" \
  -f database/tests/0002_context_resolver_volatility_contract.sql

echo "Running explicit advisory-lock concurrency and migration-ledger semantic tests..."
bash database/tests/migration-lock-ledger-contract.sh

echo "Running the independent clean-database initial-schema contract..."
bash database/tests/initial-schema-contract.sh

echo "Running the isolated sessions-touch corrective migration contract..."
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
SET ROLE iam_owner;
CREATE TABLE iam.sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION iam.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql SET search_path TO 'pg_catalog'
AS $function$
BEGIN
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END
$function$;
ALTER FUNCTION iam.touch_updated_at() OWNER TO iam_owner;
CREATE TRIGGER sessions_touch BEFORE UPDATE ON iam.sessions
FOR EACH ROW EXECUTE FUNCTION iam.touch_updated_at();
RESET ROLE;
SQL
{
  printf '%s\n' 'SET ROLE iam_owner;'
  cat database/migrations/0002_sessions_touch_contract.sql
} | PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1
{
  printf '%s\n' 'SET ROLE iam_owner;'
  cat database/tests/0002_sessions_touch_contract.sql
} | PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql "$DATABASE_URL" -v ON_ERROR_STOP=1

echo "PASS: role bootstrap, role-assumption, initial schema, incremental migration, advisory-lock concurrency, ledger idempotency/checksum, rollback, RLS default-deny, tenant integrity, and context-key uniqueness"

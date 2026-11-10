#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?DATABASE_URL must authenticate as the disposable PostgreSQL administrator}"
: "${MIGRATOR_DATABASE_URL:?MIGRATOR_DATABASE_URL must authenticate as iam_migrator_login}"
: "${POSTGRES_TEST_PASSWORD:?POSTGRES_TEST_PASSWORD is required}"
: "${MIGRATOR_TEST_PASSWORD:?MIGRATOR_TEST_PASSWORD is required}"
database_name="iam_initial_schema_test"
admin_url="${DATABASE_URL%/*}/${database_name}"
migrator_url="${MIGRATOR_DATABASE_URL%/*}/${database_name}"
cleanup() {
  PGPASSWORD="$POSTGRES_TEST_PASSWORD" dropdb --if-exists --no-password --maintenance-db="$DATABASE_URL" "$database_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
echo "[initial-schema] creating an isolated empty database owned by iam_owner"
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql -X --no-password "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "CREATE DATABASE $database_name OWNER iam_owner;"
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql -X --no-password "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "REVOKE CONNECT ON DATABASE $database_name FROM PUBLIC;"
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql -X --no-password "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "GRANT CONNECT ON DATABASE $database_name TO iam_migrator_login;"
echo "[initial-schema] applying clean-database bootstrap through the real LOGIN and two-step SET ROLE chain"
PGPASSWORD="$MIGRATOR_TEST_PASSWORD" psql -X --no-password "$migrator_url" -v ON_ERROR_STOP=1 <<'SQL'
SET ROLE iam_migrator;
SET ROLE iam_owner;
\i database/bootstrap/0001_initial_iam_schema.sql
SQL
echo "[initial-schema] running the independent bootstrap, ownership, default-deny, tenant-integrity, and audit contracts"
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql -X --no-password "$admin_url" -v ON_ERROR_STOP=1 -f database/tests/0001_initial_schema_contract.sql
echo "[initial-schema] PASS: clean bootstrap contract is independent from incremental context-key migration"

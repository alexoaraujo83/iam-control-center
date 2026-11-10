#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?DATABASE_URL must authenticate as the disposable PostgreSQL administrator}"
: "${MIGRATOR_DATABASE_URL:?MIGRATOR_DATABASE_URL must authenticate as iam_migrator_login}"
: "${POSTGRES_TEST_PASSWORD:?POSTGRES_TEST_PASSWORD is required}"
: "${MIGRATOR_TEST_PASSWORD:?MIGRATOR_TEST_PASSWORD is required}"
tmp_dir="$(mktemp -d)"
ready_file="$tmp_dir/lock-held"
holder_log="$tmp_dir/holder.log"
contender_log="$tmp_dir/contender.log"
cleanup() {
  if [[ -n "${holder_pid:-}" ]]; then wait "$holder_pid" 2>/dev/null || true; fi
  PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql -X --no-password "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -c "DROP TABLE IF EXISTS iam.migration_lock_probe" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql -X --no-password "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE iam.migration_lock_probe (
  id integer PRIMARY KEY,
  marker text NOT NULL
);
GRANT INSERT, SELECT ON iam.migration_lock_probe TO iam_migrator;
SQL
echo "[migration-lock] starting transaction A and waiting for its advisory lock"
(
  PGPASSWORD="$MIGRATOR_TEST_PASSWORD" psql -X --no-password -At "$MIGRATOR_DATABASE_URL" -v ON_ERROR_STOP=1 >"$holder_log" 2>&1 <<SQL
BEGIN;
SET LOCAL ROLE iam_migrator;
SELECT 'A_LOCK_ATTEMPT|' || pg_backend_pid() || '|' || extract(epoch FROM clock_timestamp())::text;
SELECT iam.acquire_migration_lock();
SELECT 'A_LOCK_ACQUIRED|' || pg_backend_pid() || '|' || extract(epoch FROM clock_timestamp())::text;
\! touch "$ready_file"
SELECT pg_sleep(4);
INSERT INTO iam.migration_lock_probe (id, marker) VALUES (1, 'transaction-a-committed');
SELECT 'A_PRECOMMIT_MARKER|' || pg_backend_pid() || '|' || extract(epoch FROM clock_timestamp())::text;
COMMIT;
SELECT 'A_TRANSACTION_COMMITTED|' || pg_backend_pid() || '|' || extract(epoch FROM clock_timestamp())::text;
SQL
) &
holder_pid=$!
for attempt in $(seq 1 100); do
  [[ -f "$ready_file" ]] && break
  if ! kill -0 "$holder_pid" 2>/dev/null; then cat "$holder_log" >&2; echo "ERROR: transaction A exited before acquiring the migration lock" >&2; exit 1; fi
  sleep 0.1
done
if [[ ! -f "$ready_file" ]]; then cat "$holder_log" >&2; echo "ERROR: transaction A did not acquire the migration lock within 10 seconds" >&2; exit 1; fi
echo "[migration-lock] starting transaction B; it must wait until A commits"
start_ns="$(date +%s%N)"
PGPASSWORD="$MIGRATOR_TEST_PASSWORD" psql -X --no-password -At "$MIGRATOR_DATABASE_URL" -v ON_ERROR_STOP=1 >"$contender_log" 2>&1 <<'SQL'
BEGIN;
SET LOCAL ROLE iam_migrator;
SELECT 'B_LOCK_ATTEMPT|' || pg_backend_pid() || '|' || extract(epoch FROM clock_timestamp())::text;
SELECT iam.acquire_migration_lock();
SELECT 'B_COMMIT_MARKER_VISIBLE|' || count(*) FROM iam.migration_lock_probe
 WHERE id = 1 AND marker = 'transaction-a-committed';
SELECT 'B_LOCK_ACQUIRED|' || pg_backend_pid() || '|' || extract(epoch FROM clock_timestamp())::text;
COMMIT;
SELECT 'B_TRANSACTION_COMMITTED|' || pg_backend_pid() || '|' || extract(epoch FROM clock_timestamp())::text;
SQL
end_ns="$(date +%s%N)"
elapsed_ms="$(( (end_ns - start_ns) / 1000000 ))"
wait "$holder_pid"
holder_pid=""

a_pid="$(awk -F'|' '$1 == "A_LOCK_ATTEMPT" {print $2; exit}' "$holder_log")"
b_pid="$(awk -F'|' '$1 == "B_LOCK_ATTEMPT" {print $2; exit}' "$contender_log")"
a_acquired="$(awk -F'|' '$1 == "A_LOCK_ACQUIRED" {print $3; exit}' "$holder_log")"
b_attempt="$(awk -F'|' '$1 == "B_LOCK_ATTEMPT" {print $3; exit}' "$contender_log")"
a_precommit="$(awk -F'|' '$1 == "A_PRECOMMIT_MARKER" {print $3; exit}' "$holder_log")"
b_marker_visible="$(awk -F'|' '$1 == "B_COMMIT_MARKER_VISIBLE" {print $2; exit}' "$contender_log")"
b_acquired="$(awk -F'|' '$1 == "B_LOCK_ACQUIRED" {print $3; exit}' "$contender_log")"

if [[ -z "$a_pid" || -z "$b_pid" || -z "$a_acquired" || -z "$b_attempt" || -z "$a_precommit" || -z "$b_acquired" || -z "$b_marker_visible" ]]; then
  cat "$holder_log" "$contender_log" >&2
  echo "ERROR: missing lock concurrency evidence" >&2
  exit 1
fi
if [[ "$b_marker_visible" != "1" ]]; then
  cat "$holder_log" "$contender_log" >&2
  echo "ERROR: transaction B acquired the lock without observing transaction A's committed marker" >&2
  exit 1
fi
if [[ "$a_pid" == "$b_pid" ]]; then
  echo "ERROR: lock contenders did not use distinct PostgreSQL backend PIDs ($a_pid)" >&2
  exit 1
fi
if ! awk -v aa="$a_acquired" -v ba="$b_attempt" -v ar="$a_precommit" -v bc="$b_acquired" \
  'BEGIN { exit !(aa < ba && ba < ar && ar < bc) }'; then
  cat "$holder_log" "$contender_log" >&2
  echo "ERROR: lock event order must be A_acquired < B_attempt < A_precommit_marker < B_acquired" >&2
  exit 1
fi
if (( elapsed_ms < 2000 )); then
  echo "ERROR: transaction B did not block long enough on the migration advisory lock (${elapsed_ms}ms)" >&2
  exit 1
fi
echo "PASS: distinct backend PIDs A=$a_pid B=$b_pid; B observed A's committed marker after lock acquisition; event order A_acquired < B_attempt < A_precommit_marker < B_acquired; B waited ${elapsed_ms}ms"
echo "[migration-ledger] validating idempotency, checksum mismatch rejection, and rollback"
PGPASSWORD="$MIGRATOR_TEST_PASSWORD" psql -X --no-password "$MIGRATOR_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
SET LOCAL ROLE iam_migrator;
DO $ledger_contract$
DECLARE v_count integer;
BEGIN
  PERFORM iam.record_migration('9999_test_ledger_idempotence', repeat('a',64), repeat('b',40));
  PERFORM iam.record_migration('9999_test_ledger_idempotence', repeat('a',64), repeat('b',40));
  SELECT count(*) INTO v_count FROM iam.schema_migrations WHERE migration_id='9999_test_ledger_idempotence';
  IF v_count <> 1 THEN RAISE EXCEPTION 'idempotent ledger insert expected one row, found %',v_count; END IF;
  BEGIN
    PERFORM iam.record_migration('9999_test_ledger_idempotence', repeat('c',64), repeat('b',40));
    RAISE EXCEPTION 'ledger accepted a mismatched checksum';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'migration checksum mismatch for 9999_test_ledger_idempotence' THEN RAISE; END IF;
  END;
END
$ledger_contract$;
ROLLBACK;
SQL
remaining="$(PGPASSWORD="$POSTGRES_TEST_PASSWORD" psql -X --no-password "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM iam.schema_migrations WHERE migration_id='9999_test_ledger_idempotence';")"
test "$remaining" = "0"
echo "PASS: ledger idempotency, mismatch rejection, and rollback"

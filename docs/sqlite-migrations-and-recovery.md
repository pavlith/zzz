# SQLite migration and recovery runbook (development)

Current schema version: **2**. `back/database/migrations.go` stores applied versions in `schema_migrations` and runs each upgrade within a SQLite transaction. `v1` is a frozen compatibility baseline using GORM AutoMigrate for current legacy development databases; `v2` creates a partial unique index allowing at most one prepared rotation per Vault. Repeat application is idempotent. Failed v2 does not record version 2 or delete duplicated rows. Existing development DBs are upgraded in place, retaining user and rotation records (covered by tests).

**Important:** This is not yet a full production SQL-only migration system. SQL-defined v1 baseline, downgrade scripts, upgrade from a representative real backup, cross-version restore tests, SQLite FK constraints and full security audit remain open. Do not run production upgrades on irreplaceable data.

## Pre-upgrade procedure

1. Stop all app processes and background sync writers; identify the exact DB file/SQLite DSN.
2. Backup using SQLite's online backup/VACUUM INTO mechanism, not by blindly copying the live DB file (WAL data may be pending). Store backup and secret material separately, use tight permissions and verify restore on a disposable copy.
3. Check free disk capacity, `PRAGMA integrity_check;`, `PRAGMA foreign_key_check;`, expected `schema_migrations` versions and whether the application build supports the stored version.
4. Run `zzz migrate` once on a *copy* and run integration tests before executing it against the controlled instance.
5. Apply migrations while writes are disabled, verify version 2 and constraints and preserve the pre-upgrade verified backup.

## Failure / restore

On migration error, stop and investigate; do not delete or manually rewrite `schema_migrations` to force past a failed step. If duplicate `prepared` rotations block v2, determine the correct surviving rotation through an operator-reviewed process; never silently delete encrypted envelope data. Use a verified offline backup and documented restore procedure to roll back the *whole DB*. There is no automatic destructive downgrade. Restore must include relevant application version, key-history records and backup provenance.

## Verification

`go test -race ./back/database ./back/api` covers schema repeat run, migration conflict and upgrade from a legacy baseline. Comprehensive disaster-recovery rehearsal, checksums of a real deployment backup and concurrent writer fault-injection are pending (M1-04/M6-02).

## Automated verification added

- `TestSQLiteVacuumBackupRestoreAcrossMigration` creates a legacy SQLite DB containing data, snapshots it with `VACUUM INTO`, opens the restored file, migrates it forward and verifies the old user and schema ledger. This is a reproducible local backup/restore test, not a full disaster recovery simulation.
- `TestMigrationRejectsForeignKeyCorruption` detects an orphan reference using SQLite `foreign_key_check` and refuses to migrate an invalid database.
- The migration-ledger table is now created using explicit `CREATE TABLE IF NOT EXISTS` SQL rather than GORM AutoMigrate.

**M1-04 remains partial:** version 1 still uses GORM `AutoMigrate` to bootstrap the full application schema. An immutable SQL-only baseline, realistic upgrade fixtures and concurrent-writer stress testing remain necessary before treating database migrations as production ready.

# Database Roles

SurfaceLab uses three Postgres roles:

- `surfacelab_migrate`: schema owner for migrations and DDL. This role is not used by runtime services.
- `surfacelab_scanner`: write-focused runtime role for the Go scanner. It can insert scan records, insert steps and findings, and update scan status.
- `surfacelab_orchestrator`: read-only runtime role for the Python orchestrator. It can read scans, steps, and findings.

Runtime roles do not own schema objects and do not have `SUPERUSER`, `CREATEDB`, or `CREATEROLE`.

## Apply Locally

Run the role setup as a database owner or existing admin role:

```bash
cd path/to/surface-lab
psql -U postgres \
  -v migrate_password='change-me-migrate' \
  -v scanner_password='change-me-scanner' \
  -v orchestrator_password='change-me-orchestrator' \
  -d surfacelab \
  -f services/scanner/db/roles/001_runtime_roles.sql
```

Then run migrations with the migrate role:

```bash
migrate -database 'postgresql://surfacelab_migrate:change-me-migrate@localhost:5432/surfacelab?sslmode=disable' \
  -path services/scanner/db/migrations up
```

Use separate runtime URLs for the services:

```bash
export DATABASE_URL='postgresql://surfacelab_scanner:change-me-scanner@localhost:5432/surfacelab?sslmode=disable'
```

```bash
export DATABASE_URL='postgresql://surfacelab_orchestrator:change-me-orchestrator@localhost:5432/surfacelab?sslmode=disable'
```

## Privilege Model

- `surfacelab_migrate` owns the `public` schema and all tables, sequences, and functions in it.
- `surfacelab_scanner` gets `USAGE` on `public`, `SELECT/INSERT/UPDATE` on `scans`, and `SELECT/INSERT` on `scan_steps` and `findings`.
- `surfacelab_orchestrator` gets `USAGE` on `public` and `SELECT` on `scans`, `scan_steps`, and `findings`.
- Default privileges ensure future tables created by `surfacelab_migrate` remain readable by the orchestrator and readable/writable by the scanner without granting ownership to runtime roles.

## Notes

- The default table privileges for `surfacelab_scanner` are intentionally a little broader than the current schema because Postgres default privileges apply per object class, not per table name. Keep future tables under review and tighten grants with follow-up migration SQL if new tables should not be visible to runtime roles.
- No application query changes are required for this pass. The services only need separate `DATABASE_URL` values.

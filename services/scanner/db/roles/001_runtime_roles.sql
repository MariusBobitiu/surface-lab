\set ON_ERROR_STOP on

-- Apply with psql and provide passwords as variables, for example:
-- psql \
--   -v migrate_password='change-me-migrate' \
--   -v scanner_password='change-me-scanner' \
--   -v orchestrator_password='change-me-orchestrator' \
--   -d surfacelab \
--   -f services/scanner/db/roles/001_runtime_roles.sql

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'surfacelab_migrate') THEN
    CREATE ROLE surfacelab_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'surfacelab_scanner') THEN
    CREATE ROLE surfacelab_scanner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'surfacelab_orchestrator') THEN
    CREATE ROLE surfacelab_orchestrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END
$$;

ALTER ROLE surfacelab_migrate PASSWORD :'migrate_password';
ALTER ROLE surfacelab_scanner PASSWORD :'scanner_password';
ALTER ROLE surfacelab_orchestrator PASSWORD :'orchestrator_password';

ALTER SCHEMA public OWNER TO surfacelab_migrate;

DO $$
DECLARE
  object_name text;
  function_identity text;
BEGIN
  FOR object_name IN
    SELECT quote_ident(tablename)
    FROM pg_tables
    WHERE schemaname = 'public'
  LOOP
    EXECUTE format('ALTER TABLE public.%s OWNER TO surfacelab_migrate', object_name);
  END LOOP;

  FOR object_name IN
    SELECT quote_ident(sequence_name)
    FROM information_schema.sequences
    WHERE sequence_schema = 'public'
  LOOP
    EXECUTE format('ALTER SEQUENCE public.%s OWNER TO surfacelab_migrate', object_name);
  END LOOP;

  FOR object_name, function_identity IN
    SELECT
      quote_ident(p.proname),
      pg_get_function_identity_arguments(p.oid)
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
  LOOP
    EXECUTE format(
      'ALTER FUNCTION public.%s(%s) OWNER TO surfacelab_migrate',
      object_name,
      function_identity
    );
  END LOOP;
END
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO surfacelab_scanner;
GRANT USAGE ON SCHEMA public TO surfacelab_orchestrator;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE ON TABLE public.scans TO surfacelab_scanner;
GRANT SELECT, INSERT ON TABLE public.scan_steps TO surfacelab_scanner;
GRANT SELECT, INSERT ON TABLE public.findings TO surfacelab_scanner;
GRANT SELECT, INSERT ON TABLE public.signals TO surfacelab_scanner;
GRANT SELECT, INSERT ON TABLE public.evidence TO surfacelab_scanner;

GRANT SELECT ON TABLE public.scans TO surfacelab_orchestrator;
GRANT SELECT ON TABLE public.scan_steps TO surfacelab_orchestrator;
GRANT SELECT ON TABLE public.findings TO surfacelab_orchestrator;
GRANT SELECT ON TABLE public.signals TO surfacelab_orchestrator;
GRANT SELECT ON TABLE public.evidence TO surfacelab_orchestrator;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO surfacelab_scanner;

ALTER DEFAULT PRIVILEGES FOR ROLE surfacelab_migrate IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE surfacelab_migrate IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE ON TABLES TO surfacelab_scanner;
ALTER DEFAULT PRIVILEGES FOR ROLE surfacelab_migrate IN SCHEMA public
  GRANT SELECT ON TABLES TO surfacelab_orchestrator;

ALTER DEFAULT PRIVILEGES FOR ROLE surfacelab_migrate IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE surfacelab_migrate IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO surfacelab_scanner;

ALTER DEFAULT PRIVILEGES FOR ROLE surfacelab_migrate IN SCHEMA public
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

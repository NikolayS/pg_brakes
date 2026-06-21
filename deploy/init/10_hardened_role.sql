-- pg_bumpers — Layer 1 WALL: the hardened native agent role (idempotent).
-- =====================================================================================
-- Source of truth: docs/spec/SPEC.md (v0.8) §3 (layer 1 WALL), §4 ("Network/roles — do
-- FIRST"), §5 (role-hardening matrix). decisions.md: "Native roles = the security wall,
-- hardened … 'not superuser' is insufficient." Issue #5.
--
-- This migration is the DETERMINISTIC FLOOR's first layer: it makes a hostile *raw*
-- libpq client (no proxy, no MCP) physically unable to read non-whitelisted data or to
-- write/escalate, EVEN BEFORE the proxy. Every line below maps to a row in the
-- role-hardening matrix that deploy/test/wall_matrix.sh asserts by ATTEMPTING the denied
-- action as the agent role and proving it fails.
--
-- It is fully IDEMPOTENT: safe to run repeatedly (the dev substrate sources it on every
-- `up`). Re-running re-asserts the hardened state (defends against config drift).
--
-- The role is the fixed name `pgb_agent` and is scoped to the connected database (the
-- dev substrate applies it against `postgres`). To re-target, change the name here OR run
-- this file against the intended database; identifiers are kept as plain literals (not
-- psql :'vars') on purpose — psql does NOT interpolate :'var' inside the DO $$…$$ bodies
-- this migration uses, so plain literals are the robust, no-surprise choice.
--
-- Enforcement taxonomy (honest):
--   [REVOKE]    an explicit REVOKE strips a default/inherited privilege.
--   [NO-GRANT]  the capability is denied by NEVER granting it + member-of-nothing +
--               NOT superuser; PostgreSQL gates it on a predefined-role membership or the
--               superuser bit this role does not hold. (You cannot REVOKE what was never
--               granted; the harness proves the deny by ATTEMPTING the action.)
--   [ATTR]      a role attribute (NOSUPERUSER, NOINHERIT, …) set at the role level.
-- =====================================================================================

\set ON_ERROR_STOP on

-- Run inside a single txn so a partial apply never leaves a half-hardened role.
BEGIN;

-- -------------------------------------------------------------------------------------
-- 0. Role existence + [ATTR] attribute matrix (idempotent).
--    Create if absent, then UNCONDITIONALLY re-assert every attribute (drift defense).
--    MUST be: LOGIN, NOSUPERUSER, NOINHERIT, NOCREATEDB, NOCREATEROLE, NOREPLICATION,
--    NOBYPASSRLS. (BYPASSRLS off => RLS policies actually bind for this role.)
-- -------------------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgb_agent') THEN
    -- Dev placeholder password; production credentials come from the secret store, not
    -- this file. LOGIN so a raw client can attempt to connect (that the WALL blocks the
    -- *actions*, and the pg_hba boundary blocks the *origin*, is the whole point).
    CREATE ROLE pgb_agent LOGIN PASSWORD 'pgb_agent_dev_pw';
  END IF;
END
$$;

-- [ATTR] Re-assert the full attribute matrix every run (idempotent hardening).
ALTER ROLE pgb_agent
  NOSUPERUSER       -- [ATTR] not superuser (the bypass-everything bit)
  NOCREATEDB        -- [ATTR] cannot CREATE DATABASE
  NOCREATEROLE      -- [ATTR] cannot create/alter other roles (no lateral escalation)
  NOREPLICATION     -- [ATTR] cannot start replication / create slots (no WAL exfil)
  NOBYPASSRLS       -- [ATTR] RLS policies bind (cannot read around row security)
  NOINHERIT         -- [ATTR] does NOT auto-inherit privileges of granted roles;
                    --        even if a role were granted it must SET ROLE explicitly.
  LOGIN;

-- [ATTR] Pin search_path: no mutable / "$user" injection. A pinned, schema-qualified
-- path defeats search-path-hijack (a writable schema earlier in the path shadowing a
-- trusted object). pg_catalog is implicitly first; we name only the whitelisted schema.
ALTER ROLE pgb_agent SET search_path = pg_catalog, "public";

-- -------------------------------------------------------------------------------------
-- 1. [REVOKE] Member-of-nothing — strip EVERY predefined pg_* role + any other.
--    Enumerate ALL roles the agent is a member of and REVOKE them, so the matrix test's
--    "pg_auth_members empty for the agent" assertion holds. This explicitly covers
--    pg_read_all_data, pg_write_all_data, pg_execute_server_program, pg_read_server_files,
--    pg_write_server_files, pg_monitor, and every other pg_* predefined role.
-- -------------------------------------------------------------------------------------
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT g.rolname AS granted_role
    FROM pg_auth_members m
    JOIN pg_roles a ON a.oid = m.member
    JOIN pg_roles g ON g.oid = m.roleid
    WHERE a.rolname = 'pgb_agent'
  LOOP
    EXECUTE format('REVOKE %I FROM pgb_agent', r.granted_role);
  END LOOP;
END
$$;

-- [REVOKE] Belt-and-suspenders: explicitly REVOKE the headline predefined roles even if
-- the loop above already covered them (REVOKE of a non-member is a harmless no-op). This
-- makes the intent auditable line-by-line and documents the matrix.
-- REVOKE of a non-member emits a NOTICE/WARNING per role; silence just these so a clean
-- re-apply isn't drowned in noise. ON_ERROR_STOP still aborts on any real ERROR.
SET LOCAL client_min_messages = error;
REVOKE pg_read_all_data            FROM pgb_agent;
REVOKE pg_write_all_data           FROM pgb_agent;
REVOKE pg_read_all_settings        FROM pgb_agent;
REVOKE pg_read_all_stats           FROM pgb_agent;
REVOKE pg_stat_scan_tables         FROM pgb_agent;
REVOKE pg_monitor                  FROM pgb_agent;
REVOKE pg_execute_server_program   FROM pgb_agent;   -- the COPY … PROGRAM gate
REVOKE pg_read_server_files        FROM pgb_agent;   -- pg_read_file / server-file read
REVOKE pg_write_server_files       FROM pgb_agent;
REVOKE pg_maintain                 FROM pgb_agent;
REVOKE pg_checkpoint               FROM pgb_agent;
REVOKE pg_signal_backend           FROM pgb_agent;
REVOKE pg_create_subscription      FROM pgb_agent;
REVOKE pg_use_reserved_connections FROM pgb_agent;
RESET client_min_messages;

-- [NO-GRANT] REPLICATION is a role ATTRIBUTE, cleared via NOREPLICATION above (§0).
-- There is no GRANT REPLICATION; the attribute is the control. Asserted in the matrix.

-- -------------------------------------------------------------------------------------
-- 2. [REVOKE] Default-deny on data: revoke PUBLIC's implicit privileges, then strip any
--    privilege the agent may have picked up. The SELECT-whitelist (§4) is the ONLY way
--    back in. This guarantees "default-deny elsewhere".
-- -------------------------------------------------------------------------------------
-- Block the agent from creating objects in (or even using) public except read-whitelist.
-- Note: in PG15+ PUBLIC already lacks CREATE on public; we re-assert for older drift and
-- additionally revoke from the agent role directly.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM pgb_agent;   -- agent cannot create tables/etc.
-- Re-grant only CONNECT to this DB + USAGE on the whitelisted schema (read surface).
-- (CONNECT is granted via the database default to PUBLIC; USAGE on public is the path to
-- the whitelisted relation. We do not touch DATABASE-level grants to avoid lock-out.)
GRANT USAGE ON SCHEMA public TO pgb_agent;

-- -------------------------------------------------------------------------------------
-- 3. [REVOKE] PUBLIC EXECUTE on functions — revoke the language default, then grant back
--    NOTHING by default. (PostgreSQL grants EXECUTE to PUBLIC on every newly-created
--    function unless revoked.) Combined with member-of-nothing this denies reachable
--    SECURITY DEFINER / volatile server-side write functions to the agent.
--    We scope the blanket revoke to the application schema(s); pg_catalog built-ins are
--    governed by predefined-role membership (already stripped) and the superuser bit
--    (NOSUPERUSER), which is why pg_read_file/lo_*/etc. are denied even without an
--    explicit REVOKE (the harness proves each by attempting it).
-- -------------------------------------------------------------------------------------
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM pgb_agent;
-- Future functions created in public: default-deny EXECUTE to PUBLIC as well.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- -------------------------------------------------------------------------------------
-- 4. [NO-GRANT] Large objects / server files are gated by superuser + predefined-role
--    membership (pg_read_server_files / pg_write_server_files), both denied above. There
--    is no per-object GRANT to revoke for the lo_*/pg_read_file built-ins; the deny is
--    structural and proven by the harness attempting lo_import / pg_read_file /
--    COPY…PROGRAM and asserting a permission error. Documented, not silently skipped.
--
-- 5. [NO-GRANT] dblink / postgres_fdw / file_fdw egress: the agent is NOT superuser and
--    has no CREATE on the database, so it cannot CREATE EXTENSION. The harness asserts
--    these extensions are NOT installed AND that the agent cannot create them.
-- -------------------------------------------------------------------------------------

COMMIT;

-- =====================================================================================
-- 6. The SELECT-WHITELIST (explicit grants only; default-deny everywhere else).
--    This is the ONLY positive grant surface. A demo schema + two tables model the
--    whitelist: public.allowed_read is granted SELECT; public.secret_data is NOT (so a
--    raw agent SELECT on it must fail — the matrix's positive+negative read pair).
--    Real deployments replace these with their own allow-listed relations/columns.
-- =====================================================================================
BEGIN;

CREATE TABLE IF NOT EXISTS public.allowed_read (
    id    integer PRIMARY KEY,
    label text NOT NULL
);
INSERT INTO public.allowed_read (id, label) VALUES
    (1, 'whitelisted row one'),
    (2, 'whitelisted row two')
ON CONFLICT (id) DO NOTHING;

-- A NON-whitelisted table: the agent must NOT be able to SELECT this (default-deny).
CREATE TABLE IF NOT EXISTS public.secret_data (
    id     integer PRIMARY KEY,
    secret text NOT NULL
);
INSERT INTO public.secret_data (id, secret) VALUES
    (1, 'TOP SECRET — must never reach the agent role')
ON CONFLICT (id) DO NOTHING;

-- THE WHITELIST: explicit SELECT on the one allowed relation. No INSERT/UPDATE/DELETE
-- anywhere (no write grant). secret_data is intentionally NOT granted.
GRANT SELECT ON public.allowed_read TO pgb_agent;

-- Re-assert default-deny on the secret table for the agent (no-op if never granted;
-- defends against drift where a prior run / operator granted it).
REVOKE ALL ON public.secret_data FROM pgb_agent;

COMMIT;

-- =====================================================================================
-- Done. The agent role is now: LOGIN, NOSUPERUSER, NOINHERIT, member-of-nothing,
-- NOCREATEDB/ROLE, NOREPLICATION, NOBYPASSRLS, search_path pinned, PUBLIC EXECUTE
-- revoked, NO write grant, SELECT only on the explicit whitelist, default-deny
-- everywhere else. dblink/fdw/COPY-PROGRAM/lo_*/pg_read_file denied structurally.
-- deploy/test/wall_matrix.sh asserts every one of these by attempting the denied action.
-- =====================================================================================

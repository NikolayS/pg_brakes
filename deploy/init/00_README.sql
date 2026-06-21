-- pg_bumpers — primary init hooks (docker-compose entrypoint)
--
-- Files in this directory are executed once, in alphabetical order, by the
-- official postgres image on FIRST boot of the `primary` service
-- (/docker-entrypoint-initdb.d). They run as the bootstrap superuser.
--
-- Source of truth: docs/spec/SPEC.md (v0.8) §3 (WALL layers 0-1), §4 (_meta audit).
--
-- ===========================================================================
-- >>> HARDENED-ROLE INCLUDE POINT — issue #5 (do NOT duplicate here) <<<
-- ===========================================================================
-- The native-role WALL (hardened agent role, least-privilege GRANTs, the
-- role-hardening test matrix, and the pg_hba network boundary) lands in
-- issue #5 (SPEC §3 layer 0-1). When #5 lands, its bootstrap SQL goes here as
-- e.g. deploy/init/10_hardened_role.sql and will be picked up automatically by
-- this same entrypoint mount. This file deliberately does NOT create that role
-- so the two issues don't collide on the WALL work.
-- ===========================================================================

-- Minimal, non-WALL baseline so a fresh `up` is queryable end-to-end.
-- (A trivial marker table; replaced/augmented by real fixtures later.)
CREATE TABLE IF NOT EXISTS public.pgb_devstack_marker (
    id        integer PRIMARY KEY,
    note      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.pgb_devstack_marker (id, note)
VALUES (1, 'pg_bumpers devstack primary initialized')
ON CONFLICT (id) DO NOTHING;

-- Replication role for the streaming standby (docker path). The local-stack.sh
-- path creates an equivalent role for the local PG18 substrate. Password is a
-- dev placeholder; production credentials come from secrets, not this file.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'replicator') THEN
        CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replicator';
    END IF;
END
$$;

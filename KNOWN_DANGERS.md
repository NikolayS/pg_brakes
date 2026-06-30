# Known dangers — operational hazards in pg_bumpers' own setup. Honesty-first; see also [KNOWN_BYPASSES.md](KNOWN_BYPASSES.md).

## D1 — `deploy/sql/10_hardened_role.sql` can take down an existing production database
The role-hardening SQL revokes privileges from **`PUBLIC`** in schema `public` — `REVOKE EXECUTE ON ALL FUNCTIONS … FROM PUBLIC`, `ALTER DEFAULT PRIVILEGES … REVOKE EXECUTE … FROM PUBLIC`, and the `CREATE` / `TEMPORARY` / `lo_*` revokes. Those change the privilege model for **every role in the database, not just `pgb_agent`**.

It is safe on a **greenfield/throwaway** database (nothing depends on those defaults). On a **live application database it strips implicit `PUBLIC` grants that running applications and monitoring rely on** — any role that could execute a function *only* via the `PUBLIC` default loses access the instant the revoke runs. Applied to a production primary, this caused permission-denied errors on functions the application relied on, breaking it for users. Recoverable with a re-`GRANT`, but the blast radius is invisible until something breaks.

**Do NOT apply `10_hardened_role.sql` to an existing production database as-is.** Rehearse it on a thin clone and smoke-test your application first, or apply only the agent-role-specific REVOKEs and skip the `… FROM PUBLIC` statements. **Fix in progress:** the default BYO hardening will constrain the agent role *only* and never mutate `PUBLIC`; the strict `PUBLIC` lockdown becomes an explicit, blast-radius-checked, clone-rehearsed opt-in for *dedicated* databases.

The lesson: a safety tool's own setup must obey the tool's own floor — bounded, reversible, rehearsed-on-a-clone. This one didn't.

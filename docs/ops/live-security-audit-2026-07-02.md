# Live-DB security audit — 2026-07-02 (pre-go-live, internal)

Read-only verification of the **live remote DB** (`prmsonskzrubqsazmpwd`), independent of the
code, to confirm no privilege residue before go-live. **This does NOT replace T7** (an external
human review) — it strengthens the posture and closes the "verify against the live DB" items the
attack-surface inventory flagged.

| Check | Result |
|---|---|
| Supabase security advisors (ERROR/CRITICAL) | **0** (16 lints total; the rest are WARN — see below) |
| RLS enabled on every `public` table | **Yes** — query for `relrowsecurity=false` returned zero rows |
| anon-key read of `ledger_entries`, `payouts`, `advertiser_charges`, `publishers` | **0 rows each** (RLS denies; default table GRANTs are inert without a permissive policy) |
| anon-executable public functions | **none** (empty `aclexplode` for anon EXECUTE) |
| `app.admins` reachable via the Data API | **No** — `PGRST106 Invalid schema: app` (schema not exposed) |
| Admin RPCs' internal gate | `approve_clawback`, `reject_clawback`, `resolve_dispute`, `gdpr_delete_publisher` each open with `IF NOT (SELECT app.is_admin()) THEN RAISE EXCEPTION 'unauthorized'` (verified in-file) |

## The 7 WARN advisors — `authenticated_security_definer_function_executable`

These correspond to inventory item #5: admin/money SECURITY DEFINER RPCs are `EXECUTE`-grantable
by any `authenticated` role, with the admin check performed **inside** the function
(`is_admin()` → RAISE). This is a deliberate design (the admin calls them directly via PostgREST
with their own JWT), and the internal gate is confirmed present + first-statement on each. It is
**defense-in-depth-worthy, not a hole** — a reviewer should confirm each gate is unbypassable
and consider whether to additionally REVOKE `authenticated` EXECUTE and route these through a
service-role edge function. **Left unchanged pending T7** (a live REVOKE risks the admin path and
is a design decision, not a clear fix).

## Conclusion

The money-critical authorization boundary (RLS on all tables + `app.admins` unreachable + admin
RPCs internally gated + no anon reach) holds on the live DB. The remaining WARNs are a documented
design tradeoff for the external reviewer to adjudicate. **T7 remains the hard go-live gate.**

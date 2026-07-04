# LumaLine load-test plan (M6-T2) — window-protocol write ceiling

**Status: harness BUILT (`scripts/load/`), not yet run.** Running is a separate, gated step — it goes
against a **local** stack only. Never run this against prod: it would create real windows/impressions
and confound M5's first-charge reconcile. The harness enforces this with a hard guard (below).

## What it measures

The hot path is `window_open → window_beat×N → close_window` (SQL RPCs in
`20260627025330_window_rpcs.sql`). Each honest window is ~5–6 DB writes: 1 insert (open) + ≥3 updates
(beats) + 1 update + 1 insert (close). The harness drives many concurrent synthetic devices through
that loop at honest cadence and reports:

- **throughput** — total ops/s and successful **writes/s** (the number the ~15k-writes/s ceiling claim is about);
- **latency** — p50 / p95 / p99 / max per op (`open`/`beat`/`close`);
- **error taxonomy** — a histogram by `(op, code)` so a rate-limit 429, an anti-batch reject, or a
  timeout are distinguished, not lumped.

## The ceiling claim it validates

The production-readiness handoff documents ~**15k writes/s @ ~50k concurrent devs** for the UNLOGGED
`ad_windows` + direct-RPC beats design. That is unvalidated. Because each device completes one window
per ~5s (5s dwell + ≥500ms×3 anti-batch spacing), a device sustains ~1–1.2 writes/s, so ~15k writes/s
implies ~12–15k concurrent devices. The harness scales `--users` toward that and records where error
rate / p99 latency start to climb — the real ceiling, and the trigger point for the migration below.

## Honest cadence (why the harness can't just hammer)

The server enforces, and the harness respects:
- **anti-batch**: ≥500ms wall-clock between beats (harness uses 600ms);
- **HMAC hash-chain**: each beat = `HMAC_sha256("seq|prev|activity", challenge)`, `prev` = previous
  beat's hmac (or `window_id` for beat 1) — replicated in `scripts/load/lib/hmac-chain.mjs`, locked to
  the server contract by `test/load-harness.test.mjs`;
- **full dwell**: `close_window` credits only when elapsed ≥ `dwell_ms` (5000) with ≥3 beats +
  activity progress. The harness produces genuinely creditable windows so it exercises the real
  credit/insert path, not just rejects.

## Safety guard (hard)

`assertSafeTarget()` in `harness.mjs` refuses to run if the target URL contains the prod ref
`prmsonskzrubqsazmpwd`, or if the host is not `127.0.0.1`/`localhost` (unless `LOAD_ALLOW_NONLOCAL=1`
is set for a non-prod remote you own — the prod-ref check still fires regardless). Default target is
the local stack `http://127.0.0.1:54321`.

## Rate-limit tuning (`LUMALINE_RL_MAX_PER_MIN`, `rl_buckets`)

The salted-IP fixed-window limiter (`20260627041000_rate_limit.sql`) guards the **anonymous self-promo
feed**, not authenticated device windows. Tuning goal (task acceptance): the limit must **not 429 a
legitimate single dev's cadence** while still capping a single-source flood. Method: run the harness's
anon path (future extension) at one-dev cadence, confirm zero 429s; then at flood cadence, confirm the
limiter clamps. `rl_hit` fails **open** on a missing hash, so a backend hiccup never blocks honest
ticks — verify that holds under load.

## Cloudflare Durable Objects migration trigger

Document (and the harness helps set) the concrete trigger to move `ad_windows` off Postgres onto
Cloudflare DO: when measured sustained writes/s approaches the ceiling at acceptable p99, OR when p99
`beat` latency exceeds the heartbeat interval under target concurrency. Until then, UNLOGGED
`ad_windows` + direct RPC is sufficient; the trigger is a number this harness produces, not a guess.

## How to run (local, gated)

```bash
supabase start                                   # bring up the local stack
# export local keys from `supabase status` (or accept the built-in local demo defaults):
#   export LOAD_BASE=http://127.0.0.1:54321
#   export LOAD_SERVICE_KEY=… LOAD_ANON_KEY=… LOAD_JWT_SECRET=…
node scripts/load/harness.mjs --users 200 --duration 30 --beats 3
node scripts/load/harness.mjs --users 2000 --duration 60      # step toward the ceiling
# full JSON report is written to /tmp/lumaline-load-<ts>.json
```

The harness seeds synthetic `auth.users → publishers → devices` (publishers.auth_user_id is NOT NULL)
via the GoTrue admin API + service-role inserts, mints per-device JWTs, then runs the loop. Seed data
is local-only; drop it with `supabase db reset` after a run.

## Acceptance (M6-T2)

- harness sustains a target write rate without error spikes (error taxonomy clean at the target);
- tuned limits don't 429 legitimate single-dev traffic;
- the report records the **measured** ceiling + the DO-migration trigger number.

**DEPENDS-ON: M5** for *running* against anything shared. Building + local runs are safe now; do not
point it at prod until M5-T3/T4 are validated and prod is no longer single-owner.

# lumaline PoC — signed feed + status-line client

Proves the trustworthy path end-to-end: a signed ad backend, and a Claude Code
`statusLine` client that shows **"Matei is the best"** for 5 seconds (clearly
labeled sponsored, with a countdown), then reverts to a normal status — counting
exactly one verified impression.

No npm dependencies. Node built-ins only (`http`, `crypto`, `fs`).

## Run it

**Looks like a real Claude Code session** (animated spinner + thinking verb, sponsored line in the status bar):

```bash
node poc/demo-session.mjs        # animated in a real terminal
node poc/demo-session.mjs --plain  # plain frames (auto when piped)
```

**Plumbing proof** (bare tick loop, shows the audit log + backend impression):

```bash
node poc/demo.mjs
```

The demo generates an ed25519 keypair, starts the backend, then simulates Claude
Code's status ticks (~4/sec for ~7s) so you can watch the line appear and expire:

```
[t= 0.1s] ★ Matei is the best  ·  sponsored (5s)
...
[t= 5.0s] ★ Matei is the best  ·  sponsored (1s)
[backend] ... VERIFIED adId=matei-001 dwellMs=5000 nonce=...
[t= 5.4s] Opus 4.8 · ~/projects/lumaline/poc
```

## What each piece does

| File | Role |
|---|---|
| `backend/server.mjs` | `GET /feed` returns a **signed** ad (with a clickable URL); `POST /impression` logs a completed, dwell-verified impression (the billable event). |
| `backend/keygen.mjs` | Generates the ed25519 signing keypair (private stays server-side). |
| `../src/statusline.mjs` | The canonical `statusLine` command (shipped in the npm package). Reads Claude's JSON on stdin, **verifies the signature**, shows the labeled clickable ad for its dwell window, mirrors every render to a local audit log, reports one impression on completion. |
| `demo.mjs` / `demo-session.mjs` | Drive the whole thing without a live Claude session. |

## Trust properties demonstrated

- **No tampering** — uses only the official `statusLine` mechanism; touches nothing of Anthropic's.
- **Signed content** — the client refuses to display anything whose signature doesn't verify (`verify_fail` in the audit log, then no ad).
- **Clearly labeled** — every ad render says `sponsored`.
- **Minimal data** — the impression report is just `{ adId, dwellMs, nonce, ts }`. No code, no file paths, no PII.
- **Auditable** — `.runtime/audit.log` is a local, human-readable mirror of everything the client did and would report.
- **Honest billing** — the backend only records an impression after the full 5s dwell completes (once, deduped by state).

## Trying it live in Claude Code

Use the CLI (see the [root README](../README.md)):

```bash
LUMALINE_HOME="$HOME/.lumaline" node poc/backend/keygen.mjs   # dev keys
LUMALINE_HOME="$HOME/.lumaline" node poc/backend/server.mjs   # keep running
node bin/lumaline.mjs install                                  # wires statusLine (refreshInterval:1)
# ... use Claude Code; uninstall with: node bin/lumaline.mjs uninstall
```

`install` sets `refreshInterval: 1` so the line re-runs every second — event-driven
updates *plus* a wall-clock timer — keeping it live through long idle instead of freezing.

**Caveats (honest):**
- **Idle refresh vs. honest billing.** `refreshInterval` keeps the *display* live during idle, but the client only opens a billable impression window when Claude's stdin shows real activity (`cost`/token counts advancing). Pure idle timer-refreshes never count an impression — no inflating impressions while you're AFK.
- **Frequency cap.** Each impression window is 5s, then a `COOLDOWN_MS` (15s) rest before another can open (and only if there was activity).
- **Cost of `refreshInterval: 1`.** It spawns the client process every second indefinitely. Fine for a PoC; a production build would back it with a persistent helper/daemon so the per-tick command returns instantly.
- This snippet **clobbers any existing `statusLine`** (e.g. the caveman badge). The real client must detect and wrap a prior command instead of overwriting — not done in this PoC.
- `.runtime/` (keys, cache, state, logs) is gitignored.

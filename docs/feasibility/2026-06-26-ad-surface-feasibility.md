# Feasibility: Trustworthy, Update-Safe Sponsored Line in Claude Code (CLI) and VS Code

**Date:** 2026-06-26
**Status:** Assessment complete
**Question:** Can we render a short sponsored line in (a) the Claude Code CLI and (b) the VS Code editor, *without breaking trust* and *without conflicting with future Claude updates*?

---

## TL;DR Verdict

| Surface | Placement | Mechanism | Trustworthy? | Update-safe? | Measurable? |
|---|---|---|---|---|---|
| **CLI** | spinner verb (the "Percolating…" word) | `spinnerVerbs` setting | ✅ yes | ✅ yes | ❌ no callback |
| **CLI** | persistent status line (bottom bar) | `statusLine` setting | ✅ yes | ✅ yes | ✅ per-tick |
| **VS Code** | inside Claude's chat panel spinner | patch Anthropic's bundle | ❌ **no** | ❌ **no** | n/a |
| **VS Code** | editor's own bottom status bar | `createStatusBarItem` API | ✅ yes | ✅ yes | ✅ own render |

**Bottom line:**
- **CLI — fully feasible** through two *official, user-owned settings*. No patching. Survives updates.
- **VS Code — feasible only in a different spot** than Kickbacks uses. Matching Kickbacks' in-panel spinner *requires* the untrustworthy bundle-patching; the trustworthy alternative is our own editor status-bar item (different, less "premium" location).
- The **billable/measurable** unit is the CLI `statusLine` (and the VS Code status-bar item), **not** the spinner verb. This has direct consequences for fair payout (see §4).

---

## 1. Trust + update-conflict criteria (definitions)

A surface passes if it satisfies **all** of:

1. **No tampering** with Anthropic's (or any third party's) code, bundle, or security config (no CSP changes, no DOM injection into other extensions).
2. **User-owned & reversible** — lives in files the user controls (`~/.claude/settings.json`), fully removable, no hidden state.
3. **No silent auto-mutation** — no unsigned background process re-writing things every N seconds (the Kickbacks anti-pattern).
4. **Update-safe** — keeps working across Claude Code / Claude extension updates *without* needing to re-apply a patch.

---

## 2. CLI Claude Code — FEASIBLE ✅

Two sanctioned extension points, both confirmed in the locally installed build (`~/.local/share/claude/versions/2.1.193`):

### 2a. `spinnerVerbs` — the spinner word itself (display only)
- **Official setting**, present in the 2.1.193 bundle (grep-confirmed: token `spinnerVerbs`). Introduced ~v2.1.23.
- Shape (per multiple sources, `~/.claude/settings.json`):
  ```json
  { "spinnerVerbs": { "mode": "replace" | "append", "verbs": ["Percolating...", "Compiling..."] } }
  ```
- `replace` swaps the default verb list; `append` extends it. Verbs should be short present-participles.
- **This is the exact spot Kickbacks sells** — reachable here with zero patching.
- **Limitation (critical):** it's a *static array*. Claude picks a verb at random; there is **no callback** telling us *which* verb was shown, *when*, or for *how long*. → We cannot measure or verify a spinner-verb impression. Brand exposure only; not a billable unit on its own.

### 2b. `statusLine` — persistent bottom line (measurable)
- **Official, documented** (https://code.claude.com/docs/en/statusline).
- Shape:
  ```json
  { "statusLine": { "type": "command", "command": "~/.config/lumaline/statusline", "padding": 0 } }
  ```
- Claude pipes a JSON blob to the command's **stdin** each tick (fields: `model`, `cost`, `context_window`, `workspace.current_dir`, `rate_limits`, …); the command's **stdout** first line is rendered.
- **Tick model:** runs after each new assistant message, after `/compact`, on permission-mode change, on vim-mode toggle. **Debounced 300ms**; an in-flight run is cancelled if a newer tick fires.
- **Timer refresh (`refreshInterval`):** the `statusLine` config also accepts `refreshInterval` (whole **seconds**, min 1; confirmed present in the 2.1.193 bundle — schema describe: *"Re-run the status line command every N seconds in addition to event-driven updates"*). This re-runs the command on a wall-clock timer **even during long idle**, so the line never freezes. Resolves the "refresh at all times" requirement natively — no patching, no sidecar.
- **Because our command runs each tick (and each timer interval), we can render the sponsored line AND record (locally) that it was rendered + timestamp** → this is the surface that yields a measurable, verifiable impression. **Trust caveat:** timer-refreshes fire during idle too, so *billable* impressions must be gated on real activity (advancing `cost`/token fields in stdin), or idle time inflates impressions.

### 2c. CLI constraints
- **Single `statusLine` slot.** Only one command can be configured. If the user already has one (e.g. the caveman badge), naïvely writing ours **clobbers it**. → A well-behaved installer MUST detect an existing `statusLine`, **wrap/chain** it (run the prior command, append our segment), and **restore it on uninstall**. Coexistence behavior is *not documented* by Anthropic, so we own it.
- **Settings writes must be reversible & consented** — back up prior values, write only with explicit user opt-in, provide clean uninstall.

### 2d. CLI update-resilience ✅
- Updates **do not touch** `~/.claude/settings.json` (docs: setup / config location). Settings survive across all install methods.
- The stdin/stdout contract is **stable but unversioned** — changes so far are *additive* (e.g. v2.1.149 added GitHub fields, v2.1.181 added `COLUMNS`/`LINES`). Risk: a future field rename/removal. **Mitigation:** defensive parsing (treat all stdin fields as optional), and don't hard-depend on any single field.
- **No re-patching ever needed** — unlike a bundle patch, settings don't break on update.

---

## 3. VS Code editor — FEASIBLE ONLY IN A DIFFERENT SPOT ⚠️

### 3a. Matching Kickbacks (in Claude's chat-panel spinner) — ❌ NOT trustworthy
- VS Code **forbids** extensions from touching the DOM or another extension's UI: *"extensions have no access to the DOM of VS Code UI … cannot inject HTML/CSS … cannot manipulate another extension's UI"* (VS Code Extension Capabilities). Extensions run in a separate Extension Host.
- Therefore the **only** way to put text in Claude's chat-panel spinner is to **patch Anthropic's extension bundle** — which (per the public Kickbacks code review) **persistently weakens that bundle's Content-Security-Policy** (even after disable) and is re-applied by an **unsigned auto-update every ~90s** = supply-chain risk.
- This **fails trust criteria #1, #3, #4** and **breaks on every Claude extension update by design** (the patch target moves; that's *why* Kickbacks re-patches every 90s). **Rejected.**

### 3b. Our own editor status-bar item — ✅ trustworthy, different location
- `vscode.window.createStatusBarItem(...)` is the **official, sanctioned** way for an extension to contribute UI. It's *our* item in the editor's bottom status bar — we never touch Claude's extension.
- **Update-safe:** it's a VS Code core API, **independent of Claude's extension version** → zero conflict with Claude updates.
- **Measurable:** we control render + visibility, so we can count impressions honestly.
- **Trade-off:** the ad shows in VS Code's **bottom status bar**, not inside Claude's thinking spinner. Honest, but less "premium" placement than Kickbacks markets.
- **Note:** when Claude Code runs in VS Code's **integrated terminal** (not the native panel), the CLI `spinnerVerbs` + `statusLine` paths from §2 already apply — so much of the "VS Code" use case is covered by the CLI mechanisms without any editor extension at all.

---

## 4. Consequence for fair payout (ties to the telemetry requirement)

The earlier goal was: *collect only the minimum data needed to verify watch-time so payout is fair.* This assessment constrains how:

- **The spinner verb (`spinnerVerbs`) is unmeasurable** — no callback. It can only ever be an *unbilled* brand impression. Billing on it would require trusting an unverifiable client claim (exactly Kickbacks' weak spot).
- **The measurable, billable surfaces are the CLI `statusLine` and the VS Code status-bar item**, because our code runs the render and can emit a verifiable impression event (server-issued nonce + dwell, per the broader design).
- **Design implication:** position the **status line as the paid, measured unit**, and treat the **spinner verb as a free value-add** (or measure it only indirectly). This keeps payouts grounded in verifiable events.

---

## 5. Recommendation (go / no-go per surface)

| Surface | Decision |
|---|---|
| CLI `statusLine` | ✅ **GO** — primary, measurable, billable surface. Build the coexistence/wrap logic. |
| CLI `spinnerVerbs` | ✅ **GO** — secondary, free brand surface. Display-only. |
| VS Code editor status-bar item | ✅ **GO (phase 2)** — trustworthy, update-safe; accept the placement difference. |
| VS Code Claude-panel spinner | ❌ **NO-GO** — only achievable via untrustworthy patching. Explicitly out of scope. |

**Net answer to the question:** Yes — a trustworthy, update-safe sponsored line **is feasible on the CLI today** (both spinner verb and status line, via official settings) and **in VS Code via our own status-bar item**. The one thing that is *not* feasible without breaking trust is replicating Kickbacks' exact in-editor-panel spinner placement.

---

## 6. Open items to verify before/while building

- [ ] Confirm exact `spinnerVerbs` accepted schema (mode enum, max verbs, length limits) against the live binary or `https://json.schemastore.org/claude-code-settings.json`.
- [ ] Empirically test `statusLine` wrap-existing-command behavior (does Claude pass identical stdin if we shell out to a prior command?).
- [x] ~~Confirm `statusLine` tick cadence / idle behavior~~ — resolved: event-driven + optional `refreshInterval` (seconds) timer; with `refreshInterval: 1` it refreshes every second through idle. Bundle-confirmed in 2.1.193.
- [x] ~~Decide impression-verification protocol for the measurable surfaces (server-issued nonce + heartbeat)~~ — **shipped (v1)**: server-issued window + HMAC heartbeat hash-chain + anti-batch timing + activity binding + tokenized click redirect. See `docs/superpowers/plans/2026-06-27-verification-protocol-v1.md` and `src/server/`, `src/client/window.mjs` (suite: `npm test`).
- [ ] Activity-gating heuristic: confirm which stdin fields (`cost.total_cost_usd`, `context_window.total_input_tokens`) advance reliably during agentic runs, to gate billable impressions vs idle.
- [ ] `refreshInterval: 1` spawns the client every second — design a persistent helper/daemon so the per-tick command returns instantly in production.

---

## Sources

- Claude Code statusLine docs — https://code.claude.com/docs/en/statusline
- Claude Code settings docs — https://code.claude.com/docs/en/settings
- spinnerVerbs (community-confirmed) — https://danielmiessler.com/blog/customized-spinner-verbs-in-claude-code · https://alexop.dev/posts/claude-code-spinner-verbs-one-piece/ · https://github.com/stoodiohq/spinner-verbs
- VS Code Extension Capabilities (no DOM / no cross-extension UI) — https://code.visualstudio.com/api/extension-capabilities/overview
- VS Code Status Bar API — https://code.visualstudio.com/api/references/vscode-api · https://code.visualstudio.com/api/ux-guidelines/status-bar
- Kickbacks technical breakdown (terminal = spinnerVerbs+statusLine reversible; VS Code = bundle patch + CSP) — https://go-to-agency.com/en/blog/kickbacks-ai-ads-claude-code-spinner
- Local verification: `~/.local/share/claude/versions/2.1.193` bundle contains `spinnerVerbs`, `spinnerTipsEnabled`

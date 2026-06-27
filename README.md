<p align="center">
  <img src="assets/lumaline.jpg" alt="LumaLine" width="120" height="120" />
</p>

<h1 align="center">LumaLine</h1>

<p align="center">
  <b>Get paid while your AI thinks — without compromising your machine.</b><br/>
  An open-source, signed, zero-dependency way to monetize Claude Code's wait-time.
</p>

<p align="center">
  <a href="https://luma-line.lovable.app"><img src="https://img.shields.io/badge/website-luma--line-10B981?style=flat-square" alt="website" /></a>
  <a href="https://luma-line.lovable.app"><img src="https://img.shields.io/badge/status-pre--launch%20%C2%B7%20waitlist%20open-2DD4BF?style=flat-square" alt="status" /></a>
  <img src="https://img.shields.io/badge/dependencies-0-10B981?style=flat-square" alt="zero deps" />
  <img src="https://img.shields.io/badge/node-%E2%89%A518-43853d?style=flat-square" alt="node >=18" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT" />
</p>

<p align="center">
  <a href="https://luma-line.lovable.app"><b>🌐 Website &amp; waitlist</b></a> ·
  <a href="#️-try-it-in-30-seconds"><b>▶️ Try the demo</b></a> ·
  <a href="#️-how-it-works"><b>⚙️ How it works</b></a> ·
  <a href="#️-trust-guardrails"><b>🛡️ Trust</b></a> ·
  <a href="#-for-advertisers"><b>📣 Advertisers</b></a>
</p>

---

When you prompt Claude Code, it thinks for 10–90 seconds and you watch the bar. That attention
has a buyer. **LumaLine** renders **one clearly-labeled, clickable sponsored line** in Claude
Code's status bar during that wait and pays you a share of the revenue — using **only** the
official `statusLine` mechanism. No bundle patching. No silent updates. No security trade-offs.

```
✳ Building… · 1m 12s · sponsored: Deploy faster with Vercel →
```

> One labeled line. One impression — counted only when you're actually there.

---

## 🤔 Why LumaLine exists

Monetizing AI wait-time isn't a new idea. **Kickbacks.ai** proved developers want it — then paid
people by **patching Anthropic's bundle, weakening CSP, and auto-updating silently in the
background**. The idea was right. The method betrayed the people who trusted it.

**The danger was never the money. It was the method.**

Ads in a status line aren't a threat — bundle patching is, silent updates are, unsigned code is.
Strip those out and all that's left is one labeled line and a payout. So with LumaLine you get
**both**: a machine you still trust, *and* a check for attention you were wasting anyway.

You're not paid *despite* the security — you're paid *because* of it. Every ad is signed before
it renders; every second of attention is verified before it counts. **The whole thing is
open-source, so you never have to take our word for it.**

---

## ▶️ Try it in 30 seconds

No install into your real config, no signup — the demo spins up its own signed feed and a fake
Claude Code session:

```bash
git clone https://github.com/JaamesBond/LumaLine.git
cd LumaLine
npm run demo          # cinematic: looks like a real Claude Code session
npm run demo:plumbing # bare tick loop → local audit log + a backend VERIFIED impression
npm test              # 34 tests: crypto, dwell protocol, anti-fraud, click tracker
```

**At launch** (npm package lands when the hosted feed goes live —
[join the waitlist](https://luma-line.lovable.app)):

```bash
npm install -g lumaline
lumaline install      # explicit, reversible — wires the statusLine into Claude Code
lumaline uninstall    # restores your previous statusLine
lumaline doctor       # shows env + where Claude Code config lives
```

`install` is the **only** thing that touches your Claude Code settings, and only when *you* run
it — never automatically on `npm install`. It backs up `~/.claude/settings.json` first and
remembers any prior `statusLine` for a clean restore.

---

## ⚙️ How it works

LumaLine wires a command into Claude Code's official
[`statusLine`](https://code.claude.com/docs/en/statusline) hook. Each tick, that command:

1. **Sanctioned surface** — runs only as the official `statusLine` command. Nothing patched, nothing injected.
2. **Signed content** — fetches the current ad and **verifies its ed25519 signature**. Anything unsigned or forged is refused.
3. **Honest billing** — opens a server-verified dwell window, posts a per-second heartbeat hash-chain bound to real agent activity, and credits **one** impression only after a full, honest dwell — **never during idle**.
4. **You get paid** — transparent, publisher-favored **60/40 split**. Gross revenue always visible.

`refreshInterval: 1` keeps the line live even through long idle, but **billable impressions only
count when there's real activity**, so idle time never inflates counts.

---

## 🛡️ Trust guardrails

The whole pitch is that every objection is answered in code:

| Your worry | The answer |
|---|---|
| Will it touch my Claude config? | Only when you run `lumaline install`. Never on `npm install`. |
| Can I undo it? | `lumaline uninstall` restores your old status line. Full backup kept. |
| Could a forged ad get through? | ed25519-signed. The client refuses anything unsigned. |
| What's it pulling into my machine? | **Zero** runtime dependencies. Nothing transitive to audit. |
| Will I actually get paid fairly? | Honest billing: impressions count only after a real, verified dwell. |
| Do I have to trust your word? | Open-source, with a local audit log of every payload. Verify it yourself. |

What leaves your machine per impression is just `{ adId, dwellMs, nonce, ts }` — no code, no
paths, no prompts, no PII — and it's all mirrored to a human-readable local audit log.

---

## 💸 For developers

- Earn passive income during AI wait-time — attention you're already spending.
- One **reversible** command to install; opt out anytime.
- Clearly labeled, non-intrusive: one line in the status bar.
- You keep **60% of gross**, and gross is always visible.

[**→ Join the waitlist**](https://luma-line.lovable.app)

## 📣 For advertisers

Reach developers who block every other ad:

- **100% viewability** — they're staring at the terminal waiting on the agent.
- **Ad-blocker immune** — uBlock and Pi-hole can't touch a status line.
- **OSC-8 clickable** — zero friction from terminal to browser.
- Highest-intent developer screen-time available, priced on **verified attention** (CPVA) + clicks (CPC), with clawback + invalid-traffic detection so you only pay for real attention.

[**→ Become a launch advertiser**](https://luma-line.lovable.app)

---

## 🗺️ Repository map

```
bin/lumaline.mjs      CLI entry — install · uninstall · statusline · doctor
src/
  statusline.mjs      the per-tick trust loop (fetch → verify → dwell → report)
  install.mjs         reversible, consent-only wiring of ~/.claude/settings.json
  uninstall.mjs       restores your prior statusLine from a sidecar/backup
  config.mjs          all paths + tunables (env-driven, cross-platform)
poc/
  backend/server.mjs  reference signed feed (/feed, /window/*, /impression)
  demo-session.mjs    cinematic demo · demo.mjs  bare plumbing demo
supabase/             production backend (Postgres + RLS + Edge Functions)
test/                 node --test suite
docs/                 design + feasibility (below)
```

## 📚 Docs

- [**Ad-surface feasibility**](docs/feasibility/2026-06-26-ad-surface-feasibility.md) — surface-by-surface analysis of where an ad can live in Claude Code, and why `statusLine` is the sanctioned one.
- [**Verification & economics design**](docs/superpowers/specs/2026-06-27-verification-and-economics-design.md) — the proof-of-dwell protocol, the honest threat model, and CPVA/CPC pricing.
- [**Verification protocol v1**](docs/superpowers/plans/2026-06-27-verification-protocol-v1.md) — server-verified window + heartbeat hash-chain + tokenized click redirect.
- [**Production plan**](docs/superpowers/plans/2026-06-27-production-plan.md) — full v1: Supabase, double-entry ledger, device-code auth, Stripe Connect payouts.

---

## ✅ Project status — honest version

LumaLine is **pre-launch**. Here's what's real today vs. what's coming:

- ✅ **Works now:** the trust loop (signed feed → ed25519 verify → server-verified dwell → honest impression), a reference signed backend, a revenue ledger with clearing/clawback/IVT scan, and a 34-test suite. Run `npm run demo`.
- 🚧 **Before public launch:** hosted signed feed + identity, device-code `lumaline login`, npm publish with provenance, Stripe Connect payouts, and an empirical check that Claude Code's status bar forwards OSC-8 hyperlinks (CPVA is dependable today; CPC is upside until verified).

We'd rather under-promise here than oversell. [Track progress / get launch access →](https://luma-line.lovable.app)

---

## 🤝 Contributing

This is a trust product — adversarial eyes are the whole point. Read the code, open an issue, file
a PR. If you can find a way the billing could be gamed or the install could surprise a user,
that's exactly the bug report we want.

If the idea resonates, **star the repo** — it's the cheapest way to help it reach the developers
who'd want it.

---

## 📄 License & disclaimer

MIT. See [LICENSE](LICENSE).

*LumaLine is an independent open-source project. It is **not affiliated with, endorsed by, or
sponsored by Anthropic**. "Claude" and "Claude Code" are trademarks of Anthropic.*

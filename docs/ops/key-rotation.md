# LumaLine — Ed25519 Key-Compromise + Rotation Runbook

**Scope:** M0-T4 (production-readiness milestone). The Ed25519 signing key that authenticates
every served ad, plus the planned-rotation and key-compromise procedures.
**Branch of record:** `feat/m0-production-rails` (based on `origin/main`).
**Recovery mechanism this runbook leans on:** the keyid trust ring shipped in M0-T3 —
`src/lib/keyring.mjs` + `src/lib/crypto.mjs` (read those two files before acting; they are the
entire substance of "how rotation stays non-destructive").

> **Read this first.** Installed clients **never self-update** (trust invariant). The bundle a
> developer installed is frozen until they `npm update`. Combined with **signed-content-only**
> (the client refuses any ad whose Ed25519 signature does not verify), this means **the order of
> operations is the safety property**, not a nicety. Sign with a key the installed bundle does
> not trust and every one of those clients goes silent. The whole point of the keyid ring is to
> let clients trust the *next* key **before** the feed ever signs with it.

---

## 0. Roles — who does what

Two actors appear throughout. They are not interchangeable.

| Actor | Can do | Must **never** do |
| --- | --- | --- |
| **cc** (Claude Code agent, repo-side) | Generate keypairs locally, compute keyids, edit/commit `src/keys/*.pem`, run `node --test`, open the PR. | Touch the Vault, set edge-function secrets, run `supabase functions deploy`, or `npm publish`. cc has **no production credentials** and the auto-mode guard blocks production writes (see M0-T1 drift: a live reconcile INSERT was correctly refused). |
| **owner** (human, Supabase + npm custody) | Hold the private key, store/rotate Vault + edge secrets, deploy the feed, publish to npm. | Commit any private key. Use the **CRM-bound MCP** for LumaLine deploys (wrong project — see MEMORY: *LumaLine vs CRM Supabase projects*). |

**Custody handoff is always out-of-band.** When cc generates a keypair, the **private** PEM is
handed to the owner over a secure channel (not a commit, not a PR comment, not the audit log) and
cc deletes its local copy. Only the **public** PEM is committed.

---

## 1. Key custody — what lives where

There are exactly three long-lived secrets, and **all three private secrets live only in
Supabase** (edge-function secrets / Vault), never in git:

| Secret | Kind | Lives in | In the npm tarball? |
| --- | --- | --- | --- |
| `LUMALINE_ED25519_PRIVATE_KEY` | Ed25519 **private** (ad signing) | Supabase edge secret / Vault **only** | **No** |
| `LUMALINE_ED25519_KEY_ID` | the active signing key's keyid (public, not secret) | Supabase edge secret | No (it is emitted by the feed) |
| `LUMALINE_JWT_SECRET` | HS256 secret (mints the sentinel device JWT) | Supabase edge secret / Vault **only** | **No** |

The **public** keys are the *only* key material that ships to developers. They are bundled in
`src/keys/` and published via `package.json#files` (`"src/keys"` is in the `files` array, so the
whole directory is in the tarball):

- `src/keys/public.pem` — the **CURRENT** signing key's public half. keyid **`8720926064dfdf50`**.
  This file is also the **legacy/default** key (see §2): `src/config.mjs` resolves `PUB` to the
  bundled `public.pem`, and the client verifies *keyid-absent* envelopes against it.
- `src/keys/next.pem` — the **NEXT** signing key's public half. keyid **`31433cdee001fc81`**.
  Bundled now so clients already trust it; the feed has **not** flipped to it yet.

### 1.1 Outstanding custody action (owner) — move the NEXT private into Vault

The next key's **private** half currently sits on disk at `.secrets/ed25519_next_private.pem`
(the whole `.secrets/` directory is gitignored — confirmed `.gitignore:7` `.secrets/`, so it has
never been committed). It is **not** yet in Vault. Before any compromise event forces a flip to
the next key, the owner must take it into Vault custody and remove the on-disk copy:

```bash
# OWNER, on a trusted machine with the LumaLine project linked (NOT the CRM project):
#   1. confirm the on-disk key's identity matches the bundled next.pem keyid (31433cdee001fc81):
node -e "const c=require('crypto'),fs=require('fs');\
const pub=c.createPublicKey(c.createPrivateKey(fs.readFileSync('.secrets/ed25519_next_private.pem','utf8')));\
console.log(c.createHash('sha256').update(pub.export({type:'spki',format:'der'})).digest('hex').slice(0,16))"
#   -> must print: 31433cdee001fc81

#   2. stage it as a Vault-held edge secret (do NOT yet make it the ACTIVE signing key — that is
#      the §3c flip). Store it under a parked name so it is in Vault but not in use:
supabase secrets set LUMALINE_ED25519_NEXT_PRIVATE_KEY="$(cat .secrets/ed25519_next_private.pem)" \
  --project-ref prmsonskzrubqsazmpwd

#   3. once Vault has it, shred the disk copy:
shred -u .secrets/ed25519_next_private.pem   # or: rm -P on macOS
```

After 1.1, the next key exists as: public (committed, `src/keys/next.pem`) + private (Vault). The
disk no longer holds it. That is the steady state every key should reach.

---

## 2. How keyid works (the recovery mechanism — M0-T3)

**keyid is content-addressed, not a registry.** `keyFingerprint(pem)` in `src/lib/crypto.mjs` is
`sha256(SPKI-DER bytes of the public key)[:16]` (hex). It hashes the canonical DER, so it is
insensitive to PEM whitespace and **binds the id cryptographically to the key bytes** — a
mislabeled or swapped file simply maps to a *different* id and therefore can never be mis-trusted.
The keyid is **not** a security control; the Ed25519 signature is. The keyid only selects *which*
trusted key to verify against, which is what lets us rotate without a flag day.

`loadKeyring({ keysDir, legacyPubPath })` in `src/lib/keyring.mjs` builds a `Map` of
`keyid -> public PEM` by reading every `*.pem` in `keysDir` (the **filename is ignored** for
mapping — each key is keyed by its *computed* fingerprint) and adding the legacy/default key. Its
`verify(adData, sig, keyid)` enforces three safe-failure rules:

- **present keyid** → exact select. Unknown id → no key → **refuse**. Wrong key for the id → the
  signature simply fails to verify → **refuse**.
- **absent keyid** (`null`/`''`, legacy signer) → verify against the **legacy default key ONLY**
  (not a blanket trust of every bundled key).

Wiring (so you know what to touch):
- **Client:** `src/statusline.mjs` builds the ring once per tick from `KEYS_DIR` (= `src/keys`) +
  `PUB` (legacy default), then `src/client/window.mjs` passes the `/window/open` envelope's
  `w.keyid` into `cfg.verifyAd`. `src/config.mjs` adds `KEYS_DIR`.
- **Feed:** `supabase/functions/lumaline-feed/index.ts` emits `keyid = Deno.env
  LUMALINE_ED25519_KEY_ID` (when unset, the field is `undefined` and omitted from the JSON →
  backward-compatible → clients take the legacy path). It signs with `LUMALINE_ED25519_PRIVATE_KEY`.

**Today's legacy default == today's current key.** `PUB` resolves to the bundled
`src/keys/public.pem` (keyid `8720926064dfdf50`). So even though the live feed currently omits
`keyid`, clients still verify, because the keyid-absent path lands on exactly the key the feed is
signing with. (Activating keyid emission is §6.)

### 2.1 Compute any key's keyid from its public PEM (one-liner)

This is the canonical command — it calls the **same** `keyFingerprint()` the client trusts, so it
can never disagree with what the ring computes:

```bash
node -e "import('./src/lib/crypto.mjs').then(m=>console.log(m.keyFingerprint(require('fs').readFileSync(process.argv[1],'utf8'))))" src/keys/public.pem
# src/keys/public.pem -> 8720926064dfdf50   (CURRENT)
# src/keys/next.pem    -> 31433cdee001fc81   (NEXT)
```

For a **private** PEM (e.g. to confirm a Vault key matches a bundled public before flipping),
derive the public first:

```bash
node -e "const c=require('crypto'),fs=require('fs');\
const pub=c.createPublicKey(c.createPrivateKey(fs.readFileSync(process.argv[1],'utf8')));\
console.log(c.createHash('sha256').update(pub.export({type:'spki',format:'der'})).digest('hex').slice(0,16))" .secrets/ed25519_next_private.pem
# -> 31433cdee001fc81
```

---

## 3. PLANNED ROTATION — the safe order that never blacks out clients

Rotate in this order. **Each step must fully land before the next begins.** The order exists
because *signed-content-only* + *no-self-update* together mean a client can only verify a key its
**already-installed** bundle contains — so the new key must be in client bundles **before** the
feed signs with it, and the old key must stay in bundles **until** the last client signing-against
it has updated away.

### (a) Generate the next keypair — **cc**

```bash
# cc, in the repo. Matches poc/backend/keygen.mjs: PKCS8 private PEM + SPKI public PEM.
node -e "const c=require('crypto'),fs=require('fs');\
const {publicKey,privateKey}=c.generateKeyPairSync('ed25519');\
fs.writeFileSync('/tmp/lumaline_new_private.pem',privateKey.export({type:'pkcs8',format:'pem'}));\
const pubPem=publicKey.export({type:'spki',format:'pem'});\
const id=c.createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex').slice(0,16);\
fs.writeFileSync('src/keys/'+id+'.pem',pubPem);\
console.log('keyid',id,'-> committed src/keys/'+id+'.pem ; private at /tmp/lumaline_new_private.pem (hand off + shred)')"
```

cc commits **only** the new `src/keys/<keyid>.pem` (public). cc hands `/tmp/lumaline_new_private.pem`
to the **owner** out-of-band, the owner stores it in Vault (parked, as in §1.1), and cc shreds the
temp file. (If you instead promote the already-bundled `next.pem`, skip generation — its public is
already committed and its private is the §1.1 Vault key.)

### (b) SHIP a client release that trusts the new key — **owner publishes, then wait** 

The new key's public is now in `src/keys/`, so `loadKeyring` will include it in the ring. Cut a
release and publish so installed bundles begin to carry it:

```bash
# cc: prove the bundle is internally consistent before release.
node --test            # expect: pass 49, fail 0

# owner: publish (GA only — package.json currently has "private": true as a publish guard;
# the beta installs from GitHub, which carries the same committed bundle).
npm version patch && npm publish
```

**Then wait for adoption.** Clients pick the new key up only via `npm update` (or a fresh
`npm i -g github:JaamesBond/LumaLine` for the beta). Do not proceed to (c) until a comfortable
majority of active installs have refreshed. There is no client-side telemetry forcing this; it is
a judgement call sized to the install base. **GA has not shipped yet, so today there is no
installed GA cohort to wait on** — for the next planned rotation post-GA, this is the slow step.

### (c) ONLY THEN flip the feed to the new private key — **owner**

```bash
# owner — LumaLine project only; CLI only (Docker unavailable); never the CRM-bound MCP:
supabase secrets set \
  LUMALINE_ED25519_PRIVATE_KEY="$(cat /path/to/new_private.pem)" \
  LUMALINE_ED25519_KEY_ID="<new keyid>" \
  --project-ref prmsonskzrubqsazmpwd

supabase functions deploy lumaline-feed --project-ref prmsonskzrubqsazmpwd --use-api
```

The instant this redeploy is live, the feed signs with the new private and stamps the new keyid.
Clients that updated in (b) select the new bundled key by that keyid and verify. Clients that have
**not** updated do not have the new public key → they refuse and fall back to their plain base
status (graceful, never a crash, never billed). That refusal is exactly why (b) must precede (c)
and why you wait for adoption.

**Verify the flip** (owner or cc against the live URL):

```bash
curl -s -X POST https://prmsonskzrubqsazmpwd.supabase.co/functions/v1/lumaline-feed/window/open \
  -H 'content-type: application/json' -d '{"activitySnapshot":"session"}' | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const j=JSON.parse(s);console.log('keyid:',j.keyid)})"
# -> expect the NEW keyid
```

### (d) Retire the old key from the bundle — **cc**, a LATER release

Once the old-key cohort has aged out (everyone has updated past the (b) release), remove the old
public PEM from `src/keys/` and publish again. Until then it **stays bundled** so any straggler on
an old install still verifies. If the retired key was the legacy default (`public.pem`), also move
`PUB` / the legacy default to a still-trusted key in the same release, so keyid-absent envelopes
keep verifying. Retiring early re-creates the very black-out this whole order prevents.

---

## 4. KEY-COMPROMISE response

If `LUMALINE_ED25519_PRIVATE_KEY` (or the disk copy at `.secrets/ed25519_next_private.pem`, or any
key handoff) is exposed, an attacker can forge ads that **installed clients would accept as
signed**. Respond fast; the keyid ring makes "fast" possible.

### 4.1 Immediate remediation — flip to the already-bundled NEXT key — **owner**

Because clients **already bundle** `next.pem` (keyid `31433cdee001fc81`), remediation is just §3c
with the next key — **no client release and no adoption wait are required**, since the trust was
pre-positioned in M0-T3:

```bash
# owner — LumaLine project, CLI only, never the CRM MCP:
supabase secrets set \
  LUMALINE_ED25519_PRIVATE_KEY="$(cat /path/to/ed25519_next_private.pem)" \
  LUMALINE_ED25519_KEY_ID="31433cdee001fc81" \
  --project-ref prmsonskzrubqsazmpwd

supabase functions deploy lumaline-feed --project-ref prmsonskzrubqsazmpwd --use-api
```

The live feed now signs with the next key and stamps `31433cdee001fc81`. Every up-to-date client
verifies against the bundled `next.pem`; anything signed by the compromised key (which the
attacker holds) keeps verifying *too* until §4.2 lands — so 4.2 is not optional.

> If the compromise is of the **next** key itself (the only currently-bundled spare), you cannot
> hot-flip — there is no second pre-positioned key. Fall back to §3 from (a): generate a fresh
> key, ship it in a client release, then flip. This is why keeping a fresh, **unused** next key
> bundled at all times (re-seed §3a after every flip) is the standing posture.

### 4.2 Revoke the compromised key — **cc**, follow-up release

Remove the compromised public PEM from `src/keys/` and re-seed a fresh next key (§3a), then
publish. Revocation in this model = the key is no longer in any shipped bundle, so newly-updated
clients will refuse anything signed by it. (There is no CRL; the bundle *is* the trust list.)
Rotate `LUMALINE_JWT_SECRET` too if the leak could have included it (it is co-located in the same
Vault), via `supabase secrets set LUMALINE_JWT_SECRET=... && supabase functions deploy ...`.

> **Honest limit — there is NO remote kill for the installed base.** keyid enables *proactive*
> rotation away from a healthy key; it is **not** revocation for clients that have already
> installed. A client's bundle is frozen until the user runs `npm update` / reinstalls, and the
> legacy no-keyid fallback keeps the **current** key (`public.pem`) trusted indefinitely for
> keyid-absent envelopes. So §4.1's flip protects *new* installs and moves the live signer to a
> clean key — it does **not** un-trust the leaked key on machines already carrying it. **Reinstall
> is the only true revocation for the installed base.** This is why the standing posture (a fresh,
> unused next key always pre-bundled) plus shipping releases promptly is the real mitigation, and
> why the blast-radius bound below matters.

### 4.3 Bounded blast radius

What a leaked **ad-signing private key** can and cannot do — the honest bound:

- **Can:** forge an ad envelope (`{windowId,line,label,clickUrl}`) that passes client signature
  verification, i.e. display attacker-chosen text + an attacker-chosen `clickUrl` in the sponsored
  line of clients that still bundle/trust that key — but only as far as the client's own guards
  allow: the URL still passes `safeClickUrl` (absolute http(s), no control chars — no terminal
  injection), the line is still labeled `sponsored`, and a forged ad still needs a live
  `/window/open` to bind `windowId` (`window.mjs` refuses `ad.windowId !== w.windowId`).
- **Cannot:** mint money or move ledger entries — the signing key is **display authentication
  only**. Billing is server-side: the sentinel line item has `cpva_bid_micros=0` and
  `cpc_bid_micros=0`, so a view credits `gross=0` and a click bills 0 (honest-billing invariant
  holds regardless of the key). It also **cannot** mint the sentinel device JWT (separate secret,
  `LUMALINE_JWT_SECRET`) and cannot read prompts/paths/PII (data-minimization: only
  `{adId,dwellMs,nonce,ts}`-class fields ever leave the machine).
- **Today's radius is minimal: GA has not shipped.** `package.json` still carries
  `"private": true`; distribution is the GitHub beta only. There is **no installed GA cohort** to
  protect, so today a compromise is contained by simply re-signing with a fresh key + redeploy —
  the (b)/adoption-wait machinery only becomes load-bearing once a real GA install base exists.

---

## 5. Current concrete values (quick reference)

| Item | Value |
| --- | --- |
| CURRENT signing keyid (`src/keys/public.pem`; also legacy default `PUB`) | `8720926064dfdf50` |
| NEXT keyid (`src/keys/next.pem`; private parked at `.secrets/ed25519_next_private.pem`) | `31433cdee001fc81` |
| Live feed keyid emission | **omitted today** (`LUMALINE_ED25519_KEY_ID` unset → clients use legacy path → verify against `8720926064dfdf50`) |
| Supabase project ref (LumaLine, **not** CRM) | `prmsonskzrubqsazmpwd` |
| Live feed base URL | `https://prmsonskzrubqsazmpwd.supabase.co/functions/v1/lumaline-feed` |
| Test gate | `node --test` → **49 pass / 0 fail** (incl. `test/keyring.test.mjs`, `test/keys-bundle.test.mjs`, keyid wiring in `test/client-window.test.mjs`) |

**The exact deploy command** (Docker is unavailable in this environment → CLI `--use-api` only;
**never** the CRM-bound MCP):

```bash
supabase functions deploy lumaline-feed --project-ref prmsonskzrubqsazmpwd --use-api
```

---

## 6. Activate keyid on the live feed (one-time, additive) — **owner**

The feed code **already** emits `keyid` when `LUMALINE_ED25519_KEY_ID` is set
(`lumaline-feed/index.ts`: `const keyid = Deno.env.get("LUMALINE_ED25519_KEY_ID")?.trim().toLowerCase() || undefined`
— normalized to match the client's lower-case content fingerprint).
It is unset today, so the field is omitted and clients take the legacy-default path — which still
verifies, because the legacy default *is* the current key (`8720926064dfdf50`). To make the live
feed start stamping the keyid explicitly (turns the legacy path into the exact-select path, no
behavior change for current clients, and a prerequisite for clean future rotations):

```bash
# owner — LumaLine project, CLI only, never the CRM MCP:
supabase secrets set LUMALINE_ED25519_KEY_ID="8720926064dfdf50" --project-ref prmsonskzrubqsazmpwd
supabase functions deploy lumaline-feed --project-ref prmsonskzrubqsazmpwd --use-api

# verify the live feed now emits it:
curl -s -X POST https://prmsonskzrubqsazmpwd.supabase.co/functions/v1/lumaline-feed/window/open \
  -H 'content-type: application/json' -d '{"activitySnapshot":"session"}' \
  | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log('keyid:',JSON.parse(s).keyid))"
# -> keyid: 8720926064dfdf50
```

This is safe to do at any time and **must** be done before the first real rotation flip (§3c) so
that current clients move onto the exact-select path while they still trust the current key.

---

## 7. Pre-flight checklist (run before any flip)

- [ ] cc: `node --test` → 49 pass / 0 fail.
- [ ] cc: keyid of the key you are flipping **to** matches a `src/keys/*.pem` already in a
      **shipped** bundle (§2.1) — for a planned rotation, that means the (b) release is published
      **and adopted**; for compromise remediation, that is the pre-bundled `next.pem`.
- [ ] owner: flipping **to** key's private is in Vault and its derived public keyid equals the
      bundled one (§2.1 private-PEM check).
- [ ] owner: target is project `prmsonskzrubqsazmpwd` (LumaLine), confirmed **not** the CRM
      project; deploy via `--use-api`, never the MCP.
- [ ] owner: after deploy, `curl …/window/open` returns the **expected** keyid and a fresh client
      (`node bin/lumaline.mjs statusline` fed a sample stdin) renders the sponsored line rather
      than falling back to base status.
- [ ] cc: schedule the §3d retirement (planned) or §4.2 revocation (compromise) as a follow-up
      release, and re-seed a fresh `next.pem` so a spare is always pre-positioned.
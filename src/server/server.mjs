// src/server/server.mjs — canonical reference backend: signed feed + server-verified
// window protocol (open/beat/close) + tokenized click redirect. Zero deps (node:http).
//
// Hardened after the Phase 0 trust gate:
//   - the whole request handler is wrapped so a single bad request can never crash the
//     process (a malformed /c/ percent-encoding used to take the whole backend down);
//   - /window/open returns the ad (line, label, clickUrl) as an ed25519-SIGNED payload so
//     the client can refuse anything it cannot verify (signed-content-only invariant);
//   - beat rejections return a generic error (no tuning oracle) and fraud-relevant ones
//     (bad hmac / anti-batch) are logged server-side;
//   - clickSecret is REQUIRED (no hardcoded default).
import http from 'node:http';
import { signData } from '../lib/crypto.mjs';
import { createWindowStore } from './windows.mjs';
import { createClickTracker } from './clicks.mjs';

const readBody = async (req) => { let b = ''; for await (const c of req) b += c; try { return JSON.parse(b || '{}'); } catch { return {}; } };
const json = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

export function startServer({ port = 0, privateKeyPem, clickSecret, store, ad, log = console.log }) {
  if (!clickSecret) throw new Error('startServer requires a clickSecret');
  store = store ?? createWindowStore();
  const clicks = createClickTracker({ secret: clickSecret, isWindowKnown: (id) => store._windows.has(id) });
  const theAd = ad ?? { adId: 'matei-001', line: 'Matei is the best', label: 'sponsored', dest: 'https://example.com/matei', durationMs: 5000 };
  const label = theAd.label ?? 'sponsored';

  const server = http.createServer(async (req, res) => {
    try {
      const base = `http://${req.headers.host}`;
      const url = new URL(req.url, base);

      if (req.method === 'GET' && url.pathname === '/feed') {
        const data = JSON.stringify({ adId: theAd.adId, line: theAd.line, label, dest: theAd.dest, durationMs: theAd.durationMs, issuedAt: Date.now() });
        return json(res, 200, { data, sig: signData(data, privateKeyPem) });
      }
      if (req.method === 'POST' && url.pathname === '/window/open') {
        const win = store.open(await readBody(req));
        const token = clicks.mint({ windowId: win.windowId, adId: theAd.adId, dest: theAd.dest });
        const clickUrl = `${base}/c/${token}`;
        // The ad is signed and bound to this windowId; the client verifies before rendering.
        const adData = JSON.stringify({ windowId: win.windowId, line: theAd.line, label, clickUrl });
        return json(res, 200, { ...win, adData, sig: signData(adData, privateKeyPem) });
      }
      if (req.method === 'POST' && url.pathname === '/window/beat') {
        try { return json(res, 200, store.beat(await readBody(req))); }
        catch (e) {
          if (/hmac|anti-batch/.test(e.message)) log(`BEAT_REJECT ${e.message}`);
          return json(res, 400, { error: 'rejected' });   // generic: no oracle for an attacker
        }
      }
      if (req.method === 'POST' && url.pathname === '/window/close') {
        const r = store.close(await readBody(req));
        if (r.credited) log(`VERIFIED attentionSeconds=${r.attentionSeconds}`);
        return json(res, 200, r);
      }
      if (req.method === 'GET' && url.pathname.startsWith('/c/')) {
        let token;
        try { token = decodeURIComponent(url.pathname.slice(3)); }
        catch { res.writeHead(400); return res.end('bad token'); }
        const r = clicks.resolve(token);
        if (r.ok) { res.writeHead(302, { location: r.dest }); return res.end(); }
        log(`CLICK_REJECT ${r.reason}`);
        res.writeHead(404); return res.end('invalid click');
      }
      res.writeHead(404); res.end('not found');
    } catch (e) {
      log(`SERVER_ERROR ${e && e.message}`);
      try { json(res, 500, { error: 'internal' }); } catch { try { res.end(); } catch { /* socket gone */ } }
    }
  });

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({ server, port: server.address().port, store }));
  });
}

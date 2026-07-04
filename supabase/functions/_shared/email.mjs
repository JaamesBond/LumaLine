// Branded, self-contained payout emails + a best-effort Resend sender. Zero deps; importable by
// the Deno edge fn and `node --test`. NO external asset fetches (all inline), plain-text fallback.
const GREEN = "#16A34A";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function shell(innerHtml) {
  return `<!doctype html><html><body style="margin:0;background:#0b0f0a;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0b0f0a;padding:32px 0;"><tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#111813;border:1px solid #1e2a20;border-radius:14px;overflow:hidden;">
<tr><td style="padding:24px 28px 8px;">
<span style="font-size:20px;font-weight:700;color:#e8f5e9;letter-spacing:.3px;">Luma<span style="color:${GREEN};">Line</span></span>
</td></tr>
${innerHtml}
<tr><td style="padding:18px 28px 26px;color:#5c6b60;font-size:12px;line-height:1.5;border-top:1px solid #1e2a20;">
Transparent, signed, honest billing. You can audit every impression with <code style="color:#8fbf9a;">lumaline earnings</code>.
</td></tr>
</table></td></tr></table></body></html>`;
}

function cta(url, label) {
  return `<a href="${esc(url)}" style="display:inline-block;background:${GREEN};color:#06210f;font-weight:700;text-decoration:none;padding:11px 20px;border-radius:9px;font-size:14px;">${esc(label)}</a>`;
}

export function paidEmail({ handle, amountEur }) {
  const subject = `💸 You just got paid €${amountEur}`;
  const html = shell(`<tr><td style="padding:8px 28px 24px;color:#cfe9d4;">
<p style="font-size:26px;font-weight:700;color:#e8f5e9;margin:14px 0 6px;">💸 €${esc(amountEur)} is on its way</p>
<p style="font-size:15px;line-height:1.6;color:#b7cbbb;margin:0 0 14px;">Nice work, <b style="color:#e8f5e9;">${esc(handle)}</b>. Your LumaLine earnings just transferred to your connected bank — it lands in a couple of business days.</p>
<p style="font-size:13px;color:#7f948a;margin:0;">No action needed. Payouts run automatically every week.</p>
</td></tr>`);
  const text = `You just got paid €${amountEur}\n\nNice work, ${handle}. Your LumaLine earnings transferred to your connected bank and land in a couple of business days. No action needed — payouts run automatically each week.`;
  return { subject, html, text };
}

export function connectNudgeEmail({ handle, amountEur }) {
  const subject = `You've got €${amountEur} waiting — connect your bank`;
  const html = shell(`<tr><td style="padding:8px 28px 24px;color:#cfe9d4;">
<p style="font-size:26px;font-weight:700;color:#e8f5e9;margin:14px 0 6px;">You've earned €${esc(amountEur)} 🎉</p>
<p style="font-size:15px;line-height:1.6;color:#b7cbbb;margin:0 0 18px;">Hi <b style="color:#e8f5e9;">${esc(handle)}</b> — your earnings are ready, but we don't have anywhere to send them yet. Connect your bank once and weekly payouts turn on automatically.</p>
<p style="margin:0 0 18px;">${cta("https://feed.lumaline.dev", "Run: lumaline connect")}</p>
<p style="font-size:13px;color:#7f948a;margin:0;">In your terminal: <code style="color:#8fbf9a;">lumaline connect</code> — you'll enter your IBAN on Stripe's secure page.</p>
</td></tr>`);
  const text = `You've earned €${amountEur} 🎉\n\nHi ${handle} — your earnings are ready but we have nowhere to send them yet. Run \`lumaline connect\` in your terminal to add your bank (IBAN on Stripe's secure page). Weekly payouts then turn on automatically.`;
  return { subject, html, text };
}

// Best-effort: NEVER throws. Returns 'sent' or 'failed:<reason>'.
export async function sendEmail({ to, subject, html, text, apiKey, from, fetchImpl = fetch, timeoutMs = 10000 } = {}) {
  if (!apiKey || !to) return "failed:not_configured";
  try {
    const resp = await fetchImpl("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({ from, to: [to], subject, html, text }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    return resp.ok ? "sent" : `failed:${resp.status}`;
  } catch (err) {
    return `failed:${(err && err.message) ? "network" : "unknown"}`;
  }
}

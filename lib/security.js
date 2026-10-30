/**
 * SEOMedic — GSC OAuth Proxy: shared security helpers.
 *
 * Lives outside api/ so Vercel doesn't expose it as an endpoint.
 *
 * Why these exist (2026-10 audit): the proxy put whatever `site_url` it was
 * given into an unsigned base64 `state`, then sent the Google tokens there.
 * A phishing link could therefore get a real user to approve the genuine
 * "SEOMedic" consent screen and deliver their Search Console tokens to an
 * attacker's site. The defence has three parts, and all three are needed:
 *
 *   1. Signed state — only this proxy can mint one, so a hand-built Google URL
 *      with an attacker's site_url is rejected at /api/callback.
 *   2. A confirmation page that names the destination site before Google.
 *      Its form carries a signed token, and the POST must come from this
 *      proxy's own page (Origin check), so another site can't auto-submit it.
 *      (A SameSite=Strict cookie was tried first and failed in real browsers:
 *      Safari withholds Strict cookies from a page reached by a link from
 *      another site — which is exactly how users arrive from wp-admin.)
 *   3. Browser binding — the confirmation sets a short-lived cookie that the
 *      callback must see. Without it an attacker could confirm with THEIR
 *      site, copy the resulting (validly signed) Google link and send that to
 *      a victim; the victim's browser won't have the cookie, so it fails.
 */
import crypto from 'node:crypto';

export const STATE_TTL_SECONDS = 600;
export const BIND_COOKIE = 'seomedic_oauth_bind';

/**
 * HMAC key for state. STATE_SECRET if set; otherwise derived from the Google
 * client secret, which already exists in every deployment — so this change
 * needs no new environment variable to work.
 */
function stateKey() {
  const base = process.env.STATE_SECRET || process.env.GOOGLE_CLIENT_SECRET || '';
  if (!base) return null;
  return crypto.createHmac('sha256', base).update('seomedic-oauth-state-v1').digest();
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const fromB64url = (s) => Buffer.from(s, 'base64url');

export function randomToken(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

export function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

/**
 * True when a POST came from a page on this same host. Browsers send Origin
 * on every form POST (our pages use Referrer-Policy: same-origin so it isn't
 * blanked to "null"); Referer is the fallback. Neither present → refuse.
 */
export function isSameOriginPost(req) {
  const h = req.headers || {};
  const selves = [h.host, h['x-forwarded-host']].filter(Boolean).map((x) => `https://${x}`);
  if (!selves.length) return false;
  if (h.origin) return selves.includes(h.origin);
  if (!h.referer) return false;
  try { return selves.includes(new URL(h.referer).origin); } catch { return false; }
}

/** Constant-time string compare; false on any length or type mismatch. */
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/** payload → "<base64url json>.<base64url hmac>", with an expiry added. */
export function signState(payload, nowSeconds = Math.floor(Date.now() / 1000)) {
  const key = stateKey();
  if (!key) throw new Error('No signing key configured');
  const body = b64url(JSON.stringify({ ...payload, exp: nowSeconds + STATE_TTL_SECONDS }));
  const sig = b64url(crypto.createHmac('sha256', key).update(body).digest());
  return `${body}.${sig}`;
}

/** The payload if the signature is valid and unexpired, else null. */
export function verifyState(state, nowSeconds = Math.floor(Date.now() / 1000)) {
  const key = stateKey();
  if (!key || typeof state !== 'string' || state.length > 2048) return null;
  const dot = state.indexOf('.');
  if (dot <= 0) return null;
  const body = state.slice(0, dot);
  const sig = state.slice(dot + 1);
  const expected = b64url(crypto.createHmac('sha256', key).update(body).digest());
  if (!safeEqual(sig, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(fromB64url(body).toString('utf8'));
  } catch {
    return null;
  }
  if (!payload || typeof payload !== 'object' || typeof payload.exp !== 'number' || payload.exp < nowSeconds) return null;
  return payload;
}

const DEV_HOST_RE = /^(localhost|127\.0\.0\.1|\[::1\])$|\.(localhost|test|local)$/i;

/**
 * The only callback the plugin ever sends is its own settings page:
 *   https://<site>/<path>/wp-admin/admin.php?page=seomedic-settings
 * Anything else is refused, so the proxy can't be pointed at an arbitrary
 * token sink (a webhook, a pastebin, a non-WordPress host). Returns the
 * normalised URL or null.
 *
 * http is still accepted: some live sites run wp-admin without TLS, and
 * refusing them would break connecting for real customers. The confirmation
 * page warns instead (isInsecureSiteUrl). The phishing defence is the
 * confirmation + browser binding, not the scheme.
 */
export function validateSiteUrl(raw) {
  if (typeof raw !== 'string' || raw.length > 2048) return null;
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password || url.hash) return null;
  if (!url.pathname.endsWith('/wp-admin/admin.php')) return null;
  const keys = [...url.searchParams.keys()];
  if (keys.length !== 1 || url.searchParams.get('page') !== 'seomedic-settings') return null;
  return url.toString();
}

/** http on a non-development host: tokens would cross the network unencrypted. */
export function isInsecureSiteUrl(siteUrl) {
  const url = new URL(siteUrl);
  return url.protocol === 'http:' && !DEV_HOST_RE.test(url.hostname);
}

/** The plugin's nonce: random hex. Anything else is refused. */
export function validNonce(raw) {
  return typeof raw === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(raw) ? raw : null;
}

export function parseCookies(header) {
  const out = {};
  if (typeof header !== 'string') return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k && !(k in out)) out[k] = decodeURIComponent(v);
  }
  return out;
}

export function cookie(name, value, { path = '/', maxAge = STATE_TTL_SECONDS, sameSite = 'Lax' } = {}) {
  return `${name}=${encodeURIComponent(value)}; Path=${path}; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=${sameSite}`;
}

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Security headers for every HTML page this proxy renders. */
export function htmlHeaders(res) {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  // Clickjacking: the confirm button must not be framable.
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  // same-origin, not no-referrer: under no-referrer the browser sends
  // "Origin: null" on the confirm POST and isSameOriginPost() would refuse it.
  res.setHeader('Referrer-Policy', 'same-origin');
}

/** A minimal error page (never echoes unescaped input). */
export function sendErrorPage(res, status, message) {
  htmlHeaders(res);
  res.status(status).send(page('Can’t connect Search Console', `<p>${escapeHtml(message)}</p>`));
}

export function page(title, bodyHtml) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#1d2327;background:#f6f7f7;margin:0;padding:40px 16px}
main{max-width:520px;margin:0 auto;background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:28px}
h1{font-size:20px;margin:0 0 12px}.site{font-size:18px;font-weight:600;word-break:break-all}.warn{background:#fcf0f1;border-left:4px solid #d63638;padding:10px 12px;margin:16px 0}
button{background:#2271b1;color:#fff;border:0;border-radius:4px;padding:10px 18px;font-size:15px;cursor:pointer}small{color:#646970}</style></head>
<body><main><h1>${escapeHtml(title)}</h1>${bodyHtml}</main></body></html>`;
}

/** Form or JSON body → object (Vercel parses both; tolerate a raw string too). */
export function bodyObject(req) {
  const b = req.body;
  if (b && typeof b === 'object') return b;
  if (typeof b === 'string') {
    try { return JSON.parse(b); } catch { /* not JSON */ }
    return Object.fromEntries(new URLSearchParams(b));
  }
  return {};
}

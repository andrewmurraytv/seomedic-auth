/**
 * SEOMedic — GSC OAuth Proxy
 *
 * GET  /api/connect?site_url={wp_admin_callback_url}&state={nonce}
 *      → a confirmation page naming the WordPress site the tokens will go to.
 * POST /api/connect  (from that page's button)
 *      → binds this browser with a short-lived cookie, signs state, and
 *        redirects to Google's consent screen.
 *
 * See lib/security.js for why each step exists. The plugin's request (GET with
 * site_url + state) is unchanged, so existing installs need no update.
 */
import {
  BIND_COOKIE, CSRF_COOKIE, bodyObject, cookie, escapeHtml, htmlHeaders, page,
  parseCookies, randomToken, safeEqual, sendErrorPage, sha256Hex, signState,
  validNonce, validateSiteUrl, isInsecureSiteUrl,
} from '../lib/security.js';

export default function handler(req, res) {
  const proxyBase = process.env.PROXY_URL;
  if (!proxyBase || !process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return sendErrorPage(res, 500, 'The connection service is not configured.');
  }

  if (req.method === 'GET') return confirmPage(req, res);
  if (req.method === 'POST') return confirmed(req, res, proxyBase);
  res.setHeader('Allow', 'GET, POST');
  return sendErrorPage(res, 405, 'Method not allowed.');
}

function confirmPage(req, res) {
  const siteUrl = validateSiteUrl(req.query.site_url);
  const nonce = validNonce(req.query.state);
  if (!siteUrl || !nonce) {
    return sendErrorPage(res, 400, 'This connection link is invalid. Start again from SEOMedic → Settings in your WordPress admin.');
  }
  const host = new URL(siteUrl).host;
  // Double-submit token: SameSite=Strict cookie + hidden field. A page on
  // another site can auto-submit a POST here, but the browser won't send a
  // Strict cookie with it, so the confirmation can't be skipped.
  const csrf = randomToken(16);
  res.setHeader('Set-Cookie', cookie(CSRF_COOKIE, csrf, { path: '/api/connect', sameSite: 'Strict' }));
  htmlHeaders(res);
  return res.status(200).send(page('Connect Google Search Console', `
<p>You're about to give this WordPress site read-only access to your Google Search Console data:</p>
<p class="site">${escapeHtml(host)}</p>
${isInsecureSiteUrl(siteUrl) ? '<div class="warn"><strong>This site\'s admin isn\'t using HTTPS</strong>, so the access token will travel unencrypted. Enabling HTTPS on your site first is strongly recommended.</div>' : ''}
<div class="warn">Only continue if <strong>you</strong> started this from the SEOMedic settings page on <strong>${escapeHtml(host)}</strong>. If someone sent you this link, close this page.</div>
<form method="post" action="/api/connect">
  <input type="hidden" name="site_url" value="${escapeHtml(siteUrl)}">
  <input type="hidden" name="state" value="${escapeHtml(nonce)}">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  <button type="submit">Continue to Google</button>
</form>
<p><small>Access is read-only (Search Console data). You can disconnect at any time from SEOMedic → Settings.</small></p>`));
}

function confirmed(req, res, proxyBase) {
  const body = bodyObject(req);
  const cookies = parseCookies(req.headers.cookie);
  if (!safeEqual(String(body.csrf || ''), String(cookies[CSRF_COOKIE] || ''))) {
    return sendErrorPage(res, 403, 'This confirmation expired or came from another page. Start again from SEOMedic → Settings.');
  }
  const siteUrl = validateSiteUrl(body.site_url);
  const nonce = validNonce(body.state);
  if (!siteUrl || !nonce) {
    return sendErrorPage(res, 400, 'This connection link is invalid. Start again from SEOMedic → Settings in your WordPress admin.');
  }

  // Bind the flow to this browser: the callback only accepts a state whose
  // hash matches this cookie.
  const bind = randomToken(16);
  const state = signState({ site_url: siteUrl, nonce, b: sha256Hex(bind) });

  res.setHeader('Set-Cookie', [
    cookie(BIND_COOKIE, bind, { path: '/api/callback', sameSite: 'Lax' }),
    cookie(CSRF_COOKIE, '', { path: '/api/connect', maxAge: 0, sameSite: 'Strict' }),
  ]);

  const params = new URLSearchParams({
    client_id:     process.env.GOOGLE_CLIENT_ID,
    redirect_uri:  `${proxyBase}/api/callback`,
    response_type: 'code',
    scope:         'https://www.googleapis.com/auth/webmasters.readonly',
    access_type:   'offline',
    prompt:        'consent',   // force refresh_token on every connect
    state,
  });
  res.setHeader('Cache-Control', 'no-store');
  return res.redirect(303, `https://accounts.google.com/o/oauth2/v2/auth?${params}`);
}

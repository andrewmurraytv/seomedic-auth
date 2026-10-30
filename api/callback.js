/**
 * SEOMedic — GSC OAuth Proxy
 * GET /api/callback?code=...&state=...
 *
 * Called by Google after the user grants consent. Accepts only a state this
 * proxy signed (lib/security.js), from the browser that confirmed it on
 * /api/connect, then exchanges the code server-side (client_secret stays here)
 * and redirects back to the WordPress settings page with the tokens.
 *
 * The redirect target comes ONLY from the verified state. Before, an
 * unsigned base64 state meant any URL could receive the tokens, and the error
 * path was an open redirect.
 */
import { BIND_COOKIE, cookie, parseCookies, safeEqual, sendErrorPage, sha256Hex, verifyState } from '../lib/security.js';

export default async function handler(req, res) {
  const { code, state, error } = req.query;

  const verified = verifyState(state);
  const cookies = parseCookies(req.headers.cookie);
  const bind = cookies[BIND_COOKIE];
  // One use: clear the binding cookie whatever happens next.
  res.setHeader('Set-Cookie', cookie(BIND_COOKIE, '', { path: '/api/callback', maxAge: 0 }));

  if (!verified || typeof verified.site_url !== 'string') {
    return sendErrorPage(res, 400, 'This connection request is invalid or has expired (they last 10 minutes). Start again from SEOMedic → Settings.');
  }
  if (!bind || !safeEqual(sha256Hex(bind), String(verified.b || ''))) {
    return sendErrorPage(res, 403, 'This connection was started in a different browser, or the confirmation expired. Start again from SEOMedic → Settings on your own site.');
  }

  const siteUrl = verified.site_url;
  const nonce = verified.nonce;

  // Google sent an error (e.g. user denied access) — safe to send back now
  // that siteUrl is the verified one.
  if (error) {
    return redirectWithError(res, siteUrl, `Google authorization error: ${error}`);
  }
  if (!code) {
    return sendErrorPage(res, 400, 'Missing authorization code.');
  }

  const proxyBase = process.env.PROXY_URL;
  const missing = [];
  if (!proxyBase)                          missing.push('PROXY_URL');
  if (!process.env.GOOGLE_CLIENT_ID)       missing.push('GOOGLE_CLIENT_ID');
  if (!process.env.GOOGLE_CLIENT_SECRET)   missing.push('GOOGLE_CLIENT_SECRET');
  if (missing.length) {
    return redirectWithError(res, siteUrl, `Proxy is not fully configured. Missing: ${missing.join(', ')}`);
  }

  // Exchange authorization code for access + refresh tokens
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({
        code,
        client_id:     process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri:  `${proxyBase}/api/callback`,
        grant_type:    'authorization_code',
      }),
    });

    const tokens = await tokenRes.json();

    if (tokens.error) {
      return redirectWithError(res, siteUrl, tokens.error_description || tokens.error);
    }

    // Redirect back to the WP site with tokens as query params (the format
    // every installed plugin version expects).
    const callbackUrl = new URL(siteUrl);
    callbackUrl.searchParams.set('gsc_access_token',  tokens.access_token);
    callbackUrl.searchParams.set('gsc_refresh_token', tokens.refresh_token || '');
    callbackUrl.searchParams.set('gsc_expires_in',    String(tokens.expires_in || 3600));
    callbackUrl.searchParams.set('gsc_nonce',         nonce || '');

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    return res.redirect(302, callbackUrl.toString());
  } catch (err) {
    return redirectWithError(res, siteUrl, 'Token exchange request failed.');
  }
}

/** Only ever called with the verified site_url. */
function redirectWithError(res, siteUrl, message) {
  try {
    const url = new URL(siteUrl);
    url.searchParams.set('gsc_error', String(message).slice(0, 300));
    return res.redirect(302, url.toString());
  } catch {
    return sendErrorPage(res, 500, message);
  }
}

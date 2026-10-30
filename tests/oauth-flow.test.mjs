/**
 * End-to-end tests for the OAuth proxy's phishing defences, driving the real
 * handlers with mock req/res. Run: node --test --no-warnings tests/
 *
 * The attacks they pin down (2026-10 audit):
 *  - a hand-built Google URL with an unsigned state pointing at an attacker;
 *  - an attacker confirming with THEIR site, then sending the resulting
 *    (validly signed) Google link to a victim — must fail in the victim's browser;
 *  - a cross-site auto-POST trying to skip the confirmation page (Origin check);
 *  - site_url values that aren't a WordPress SEOMedic settings page.
 * And the normal flow must still deliver tokens exactly as installed plugins expect.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

process.env.PROXY_URL = 'https://seomedic-auth.vercel.app';
process.env.GOOGLE_CLIENT_ID = 'cid';
process.env.GOOGLE_CLIENT_SECRET = 'csecret';

const connect = (await import('../api/connect.js')).default;
const callback = (await import('../api/callback.js')).default;
const refresh = (await import('../api/refresh.js')).default;
const sec = await import('../lib/security.js');

function mockRes() {
  const r = { statusCode: 200, headers: {}, body: undefined, location: undefined };
  r.status = (c) => { r.statusCode = c; return r; };
  r.json = (b) => { r.body = b; return r; };
  r.send = (b) => { r.body = b; return r; };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.redirect = (code, url) => { r.statusCode = code; r.location = url; return r; };
  return r;
}
const cookiesFrom = (res) => [].concat(res.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
const SITE = 'https://victim.example/wp-admin/admin.php?page=seomedic-settings';
const EVIL = 'https://evil.example/wp-admin/admin.php?page=seomedic-settings';
const NONCE = 'a'.repeat(32);
const SELF = { host: 'seomedic-auth.vercel.app', origin: 'https://seomedic-auth.vercel.app' };

/** Walk the real flow in one "browser": GET confirm page → POST confirm → Google URL. */
function startFlow(siteUrl) {
  const page = mockRes();
  connect({ method: 'GET', query: { site_url: siteUrl, state: NONCE }, headers: {} }, page);
  const csrf = /name="csrf" value="([^"]+)"/.exec(page.body)?.[1];
  const post = mockRes();
  // No cookie from the confirm page: Safari withholds them, which is what broke the first version.
  connect({ method: 'POST', query: {}, headers: { ...SELF }, body: { site_url: siteUrl, state: NONCE, csrf } }, post);
  const state = new URL(post.location).searchParams.get('state');
  return { page, post, state, bindCookie: cookiesFrom(post) };
}

globalThis.fetch = async () => ({ json: async () => ({ access_token: 'AT', refresh_token: 'RT', expires_in: 3599 }) });

test('confirmation page names the destination host and is not framable', () => {
  const { page } = startFlow(SITE);
  assert.equal(page.statusCode, 200);
  assert.match(page.body, /victim\.example/);
  assert.equal(page.headers['x-frame-options'], 'DENY');
  assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
});

test('CSP lets the confirm form redirect on to Google (form-action covers redirects)', () => {
  const { page, post } = startFlow(SITE);
  const formAction = /form-action ([^;]+)/.exec(page.headers['content-security-policy'])[1].split(' ');
  assert.ok(formAction.includes(new URL(post.location).origin), formAction.join(' '));
});

test('happy path: same browser gets tokens in the format plugins expect', async () => {
  const { post, state, bindCookie } = startFlow(SITE);
  assert.equal(post.statusCode, 303);
  assert.match(post.location, /^https:\/\/accounts\.google\.com\//);
  const res = mockRes();
  await callback({ query: { code: 'c', state }, headers: { cookie: bindCookie } }, res);
  assert.equal(res.statusCode, 302);
  const back = new URL(res.location);
  assert.equal(back.origin + back.pathname, 'https://victim.example/wp-admin/admin.php');
  assert.equal(back.searchParams.get('gsc_access_token'), 'AT');
  assert.equal(back.searchParams.get('gsc_refresh_token'), 'RT');
  assert.equal(back.searchParams.get('gsc_nonce'), NONCE);
});

test('ATTACK: attacker confirms with their site, forwards the Google link — victim browser is refused', async () => {
  const { state } = startFlow(EVIL);              // attacker's browser
  const res = mockRes();
  await callback({ query: { code: 'victim-code', state }, headers: {} }, res); // victim's browser: no bind cookie
  assert.equal(res.statusCode, 403);
  assert.equal(res.location, undefined, 'tokens must not be redirected anywhere');
});

test('ATTACK: hand-built unsigned state (the old format) is rejected', async () => {
  const forged = Buffer.from(JSON.stringify({ site_url: EVIL, nonce: NONCE })).toString('base64');
  const res = mockRes();
  await callback({ query: { code: 'c', state: forged }, headers: {} }, res);
  assert.equal(res.statusCode, 400);
  assert.equal(res.location, undefined);
});

test('ATTACK: tampered signed state (site_url swapped) is rejected', async () => {
  const { state, bindCookie } = startFlow(SITE);
  const [body, sig] = state.split('.');
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
  payload.site_url = EVIL;
  const tampered = Buffer.from(JSON.stringify(payload)).toString('base64url') + '.' + sig;
  const res = mockRes();
  await callback({ query: { code: 'c', state: tampered }, headers: { cookie: bindCookie } }, res);
  assert.equal(res.statusCode, 400);
});

test('ATTACK: Google error path is no longer an open redirect', async () => {
  const forged = Buffer.from(JSON.stringify({ site_url: 'https://evil.example/' })).toString('base64');
  const res = mockRes();
  await callback({ query: { error: 'access_denied', state: forged }, headers: {} }, res);
  assert.equal(res.location, undefined);
});

/** A real confirm token for EVIL, as an attacker could fetch server-side. */
function tokenFor(siteUrl) {
  const page = mockRes();
  connect({ method: 'GET', query: { site_url: siteUrl, state: NONCE }, headers: {} }, page);
  return /name="csrf" value="([^"]+)"/.exec(page.body)[1];
}

test('ATTACK: cross-site auto-POST is refused even with a valid token', () => {
  const body = { site_url: EVIL, state: NONCE, csrf: tokenFor(EVIL) };
  for (const headers of [
    { host: SELF.host, origin: 'https://evil.example' },
    { host: SELF.host, origin: 'null' },
    { host: SELF.host },                                         // no Origin, no Referer
    { host: SELF.host, referer: 'https://evil.example/page' },
  ]) {
    const res = mockRes();
    connect({ method: 'POST', query: {}, headers, body }, res);
    assert.equal(res.statusCode, 403, JSON.stringify(headers));
    assert.equal(res.location, undefined);
  }
});

test('same-origin Referer is accepted when Origin is absent', () => {
  const res = mockRes();
  connect({ method: 'POST', query: {}, headers: { host: SELF.host, referer: 'https://seomedic-auth.vercel.app/api/connect?x=1' },
    body: { site_url: SITE, state: NONCE, csrf: tokenFor(SITE) } }, res);
  assert.equal(res.statusCode, 303);
});

test('confirm token is bound to its site_url and nonce, and is not a state', async () => {
  const res = mockRes();
  connect({ method: 'POST', query: {}, headers: { ...SELF }, body: { site_url: EVIL, state: NONCE, csrf: tokenFor(SITE) } }, res);
  assert.equal(res.statusCode, 403, 'token for SITE reused for EVIL');
  const cb = mockRes();
  await callback({ query: { code: 'c', state: tokenFor(SITE) }, headers: {} }, cb);
  assert.equal(cb.statusCode, 400, 'confirm token accepted as OAuth state');
});

test('reloading the confirm page does not invalidate the first copy', () => {
  const first = tokenFor(SITE);
  tokenFor(SITE); // second load, e.g. a reload or browser prefetch
  const res = mockRes();
  connect({ method: 'POST', query: {}, headers: { ...SELF }, body: { site_url: SITE, state: NONCE, csrf: first } }, res);
  assert.equal(res.statusCode, 303);
});

test('expired state is rejected', () => {
  const s = sec.signState({ site_url: SITE, nonce: NONCE, b: 'x' }, 1000);
  assert.equal(sec.verifyState(s, 1000 + sec.STATE_TTL_SECONDS + 1), null);
  assert.ok(sec.verifyState(s, 1000 + 5));
});

test('site_url must be a SEOMedic settings page on https (http only for dev hosts)', () => {
  assert.ok(sec.validateSiteUrl(SITE));
  assert.ok(sec.validateSiteUrl('https://example.com/blog/wp-admin/admin.php?page=seomedic-settings'), 'subdirectory installs');
  assert.ok(sec.validateSiteUrl('http://mysite.test/wp-admin/admin.php?page=seomedic-settings'), 'local dev');
  assert.ok(sec.validateSiteUrl('http://victim.example/wp-admin/admin.php?page=seomedic-settings'), 'http sites still connect');
  assert.equal(sec.isInsecureSiteUrl('http://victim.example/wp-admin/admin.php?page=seomedic-settings'), true);
  assert.equal(sec.isInsecureSiteUrl('http://mysite.test/wp-admin/admin.php?page=seomedic-settings'), false);
  for (const bad of [
    'https://evil.example/collect',
    'ftp://victim.example/wp-admin/admin.php?page=seomedic-settings',
    'https://evil.example/wp-admin/admin.php?page=seomedic-settings&x=1',
    'https://user:pw@evil.example/wp-admin/admin.php?page=seomedic-settings',
    'https://evil.example/wp-admin/admin.php?page=other',
    'javascript:alert(1)',
    '',
  ]) assert.equal(sec.validateSiteUrl(bad), null, bad);
});

test('confirmation page refuses an invalid site_url and escapes output', () => {
  const res = mockRes();
  connect({ method: 'GET', query: { site_url: 'https://evil.example/"><script>', state: NONCE }, headers: {} }, res);
  assert.equal(res.statusCode, 400);
  assert.doesNotMatch(res.body, /<script>/);
});

test('refresh: malformed tokens rejected before reaching Google; good one passes', async () => {
  let called = 0;
  globalThis.fetch = async () => { called++; return { json: async () => ({ access_token: 'NEW', expires_in: 3599 }) }; };
  const bad = mockRes();
  await refresh({ method: 'POST', headers: {}, body: { refresh_token: { $ne: 1 } } }, bad);
  assert.equal(bad.statusCode, 400);
  assert.equal(called, 0);
  const good = mockRes();
  await refresh({ method: 'POST', headers: { 'x-forwarded-for': '203.0.113.9' }, body: { refresh_token: '1//0gExampleRefreshToken-abc_123' } }, good);
  assert.equal(good.statusCode, 200);
  assert.equal(good.body.access_token, 'NEW');
});

test('refresh: per-IP throttle kicks in after 30 a minute', async () => {
  globalThis.fetch = async () => ({ json: async () => ({ access_token: 'NEW', expires_in: 3599 }) });
  let last;
  for (let i = 0; i < 31; i++) {
    last = mockRes();
    await refresh({ method: 'POST', headers: { 'x-forwarded-for': '198.51.100.7' }, body: { refresh_token: '1//0gExampleRefreshToken-abc_123' } }, last);
  }
  assert.equal(last.statusCode, 429);
});

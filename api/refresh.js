/**
 * SEOMedic — GSC OAuth Proxy
 * POST /api/refresh
 * Body: { refresh_token: "..." }
 *
 * Exchanges a refresh token for a new access token server-side,
 * keeping the client_secret off the WordPress site.
 */
const REFRESH_TOKEN_RE = /^[A-Za-z0-9._\-\/]{20,512}$/;
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 30;
const hits = new Map();

function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || (req.socket && req.socket.remoteAddress) || 'unknown';
}

function throttled(ip, now = Date.now()) {
  const entry = hits.get(ip);
  if (!entry || now - entry.start > WINDOW_MS) {
    hits.set(ip, { start: now, count: 1 });
    if (hits.size > 5000) hits.clear(); // bound memory
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_PER_WINDOW;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { refresh_token } = (req.body && typeof req.body === 'object') ? req.body : {};

  // Shape check before anything reaches Google: a refresh token is a short
  // opaque string. Rejecting junk early keeps this endpoint from being used to
  // relay arbitrary payloads under our client credentials.
  if (typeof refresh_token !== 'string' || !REFRESH_TOKEN_RE.test(refresh_token)) {
    return res.status(400).json({ error: 'Missing or malformed refresh_token' });
  }

  // Best-effort throttle per client IP. In-memory, so it is per warm instance
  // only — it blunts a single client hammering the endpoint, not a distributed
  // one. Real installs refresh about once an hour.
  if (throttled(clientIp(req))) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({ error: 'Too many requests' });
  }

  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return res.status(500).json({ error: 'Proxy not configured' });
  }

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({
        refresh_token,
        client_id:     process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        grant_type:    'refresh_token',
      }),
    });

    const data = await tokenRes.json();

    if (data.error) {
      return res.status(401).json({
        error:   data.error,
        message: data.error_description || 'Token refresh failed',
      });
    }

    return res.status(200).json({
      access_token: data.access_token,
      expires_in:   data.expires_in || 3600,
    });
  } catch (err) {
    return res.status(500).json({ error: 'Token refresh request failed' });
  }
}

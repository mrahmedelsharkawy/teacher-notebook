const CLIENT_ID = '741772805324-c1ncvlfmevuln52l9gavvk3ssm7lnvs9.apps.googleusercontent.com';
const REDIRECT_URI = 'https://teacher-notebook-sync.mrahmedelsharkawy1988.workers.dev/oauth/callback';
const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive.file';
const APP_ORIGIN = 'https://mrahmedelsharkawy.github.io';
const FILE_NAME = 'teacher-notebook-data.json';

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': APP_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders(), ...extra },
  });
}

function html(body, status = 200) {
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;max-width:720px;margin:40px auto;padding:20px">${body}</body></html>`, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function b64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomString(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return b64url(a);
}

async function sha256Base64Url(text) {
  return b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
}

async function signToken(payload, secret) {
  const data = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${b64url(mac)}`;
}

async function verifyToken(token, secret) {
  try {
    const [data, sig] = token.split('.');
    if (!data || !sig) return null;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const pad = sig.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(pad + '='.repeat((4 - pad.length % 4) % 4));
    const ok = await crypto.subtle.verify('HMAC', key, Uint8Array.from(raw, c => c.charCodeAt(0)), new TextEncoder().encode(data));
    if (!ok) return null;
    const jsonText = atob(data.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - data.length % 4) % 4));
    const payload = JSON.parse(jsonText);
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

async function exchangeCode(code, verifier, env) {
  const body = new URLSearchParams({
    code,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    grant_type: 'authorization_code',
    code_verifier: verifier,
  });
  // New Google Web OAuth clients may be public clients; if a secret exists in Cloudflare,
  // it is accepted, but the flow remains PKCE-based.
  if (env.GOOGLE_CLIENT_SECRET) body.set('client_secret', env.GOOGLE_CLIENT_SECRET);
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  return r.json();
}

async function refreshAccessToken(env) {
  if (!env.GOOGLE_REFRESH_TOKEN) throw new Error('GOOGLE_REFRESH_TOKEN is not configured in Cloudflare.');
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    refresh_token: env.GOOGLE_REFRESH_TOKEN,
    grant_type: 'refresh_token',
  });
  if (env.GOOGLE_CLIENT_SECRET) body.set('client_secret', env.GOOGLE_CLIENT_SECRET);
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const data = await r.json();
  if (!r.ok || !data.access_token) throw new Error(`Google token refresh failed: ${JSON.stringify(data)}`);
  return data.access_token;
}

async function driveFetch(path, accessToken, init = {}) {
  return fetch(`https://www.googleapis.com/drive/v3${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${accessToken}`, ...(init.headers || {}) },
  });
}

async function findDataFile(accessToken) {
  const q = encodeURIComponent(`name='${FILE_NAME}' and trashed=false`);
  const r = await driveFetch(`/files?q=${q}&spaces=drive&fields=files(id,name,mimeType,modifiedTime)&pageSize=10`, accessToken);
  if (!r.ok) throw new Error(await r.text());
  const data = await r.json();
  return data.files?.[0] || null;
}

async function readDriveData(accessToken) {
  const file = await findDataFile(accessToken);
  if (!file) return null;
  const r = await driveFetch(`/files/${file.id}?alt=media`, accessToken);
  if (!r.ok) throw new Error(await r.text());
  return { file, data: await r.json() };
}

async function writeDriveData(accessToken, data) {
  const existing = await findDataFile(accessToken);
  const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
  let r;
  if (existing) {
    r = await driveFetch(`/files/${existing.id}?uploadType=media`, accessToken, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: blob });
  } else {
    const boundary = '-------teacherNotebookBoundary' + randomString(8);
    const meta = JSON.stringify({ name: FILE_NAME, mimeType: 'application/json' });
    const multipart = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${meta}\r\n--${boundary}\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(data)}\r\n--${boundary}--`;
    r = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', { method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': `multipart/related; boundary=${boundary}` }, body: multipart });
  }
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function getBearer(request) {
  const h = request.headers.get('Authorization') || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}

async function getAccessTokenFromSession(request, env) {
  const token = getBearer(request);
  if (!token) return null;
  const payload = await verifyToken(token, env.SESSION_SECRET);
  return payload?.kind === 'session' ? await refreshAccessToken(env) : null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });

    if (url.pathname === '/' || url.pathname === '/health') {
      return json({ ok: true, service: 'teacher-notebook-sync', time: new Date().toISOString() });
    }

    if (url.pathname === '/auth') {
      const state = randomString(32);
      const verifier = randomString(48);
      const challenge = await sha256Base64Url(verifier);
      const auth = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      auth.searchParams.set('client_id', CLIENT_ID);
      auth.searchParams.set('redirect_uri', REDIRECT_URI);
      auth.searchParams.set('response_type', 'code');
      auth.searchParams.set('scope', DRIVE_SCOPE);
      auth.searchParams.set('access_type', 'offline');
      auth.searchParams.set('prompt', 'consent');
      auth.searchParams.set('include_granted_scopes', 'true');
      auth.searchParams.set('state', state);
      auth.searchParams.set('code_challenge', challenge);
      auth.searchParams.set('code_challenge_method', 'S256');
      const cookie = `tn_oauth=${encodeURIComponent(JSON.stringify({ state, verifier }))}; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax`;
      return new Response(null, { status: 302, headers: { Location: auth.toString(), 'Set-Cookie': cookie } });
    }

    if (url.pathname === '/oauth/callback') {
      const params = url.searchParams;
      if (params.get('error')) return html(`<h2>Google authorization failed</h2><p>${params.get('error_description') || params.get('error')}</p>`, 400);
      const cookies = request.headers.get('Cookie') || '';
      const match = cookies.match(/(?:^|;\s*)tn_oauth=([^;]+)/);
      if (!match) return html('<h2>Missing OAuth state</h2><p>Please start again from /auth.</p>', 400);
      let session;
      try { session = JSON.parse(decodeURIComponent(match[1])); } catch { return html('<h2>Invalid OAuth state</h2>', 400); }
      if (!params.get('state') || params.get('state') !== session.state) return html('<h2>State mismatch</h2>', 400);
      const tokens = await exchangeCode(params.get('code'), session.verifier, env);
      if (!tokens.access_token) return html(`<h2>Google token exchange failed</h2><pre>${JSON.stringify(tokens, null, 2)}</pre>`, 400);
      // First authorization may return a refresh token. Show it once so it can be stored as a Cloudflare Secret.
      if (tokens.refresh_token) {
        return html(`<h2>Google Drive authorization succeeded</h2><p>Copy the refresh token below into Cloudflare Worker Secret named <b>GOOGLE_REFRESH_TOKEN</b>. Do not share it.</p><textarea style="width:100%;height:120px" readonly>${tokens.refresh_token}</textarea><p>After saving the secret, open <a href="/auth">/auth</a> again. This page will then issue the application session.</p>`);
      }
      if (!env.GOOGLE_REFRESH_TOKEN) return html('<h2>Authorization succeeded, but no refresh token was returned.</h2><p>Add the existing Google refresh token as GOOGLE_REFRESH_TOKEN, then authorize again.</p>', 400);
      const sessionToken = await signToken({ kind: 'session', exp: Date.now() + 1000 * 60 * 60 * 24 * 30 }, env.SESSION_SECRET);
      return new Response(null, { status: 302, headers: { Location: `${APP_ORIGIN}/teacher-notebook/#drive_session=${encodeURIComponent(sessionToken)}`, 'Set-Cookie': 'tn_oauth=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax' } });
    }

    if (url.pathname === '/api/status') {
      const bearer = getBearer(request);
      const valid = bearer ? await verifyToken(bearer, env.SESSION_SECRET) : null;
      return json({ connected: !!valid && valid.kind === 'session' && valid.exp > Date.now() });
    }

    if (url.pathname === '/api/data') {
      try {
        const accessToken = await getAccessTokenFromSession(request, env);
        if (!accessToken) return json({ error: 'unauthorized' }, 401);
        if (request.method === 'GET') {
          const result = await readDriveData(accessToken);
          return json({ found: !!result, file: result?.file || null, data: result?.data || null });
        }
        if (request.method === 'PUT') {
          const data = await request.json();
          const result = await writeDriveData(accessToken, data);
          return json({ ok: true, file: result });
        }
        return json({ error: 'method_not_allowed' }, 405);
      } catch (e) {
        return json({ error: String(e?.message || e) }, 500);
      }
    }

    return json({ error: 'not_found' }, 404);
  }
};

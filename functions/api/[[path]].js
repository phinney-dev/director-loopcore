const T = {
  items: { cols: ['name','sku','qty','unit','cost','price','reorder'], order: 'name' },
  assets: { cols: ['name','category','purchased','cost','notes'], order: 'purchased DESC, id DESC' },
  expenses: { cols: ['date','category','description','amount','account_id'], order: 'date DESC, id DESC' },
  accounts: { cols: ['name','type','opening'], order: 'name' },
  transactions: { cols: ['account_id','date','description','amount'], order: 'date DESC, id DESC' },
};
const enc = new TextEncoder();
const json = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', ...h } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const sha256 = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
async function sign(msg, secret) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
const eq = (a, b) => { a = String(a); b = String(b); let r = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return r === 0; };
async function hashPw(pw, saltHex) {
  const salt = saltHex ? unhex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256);
  return hex(salt) + '$' + hex(bits);
}
const verifyPw = async (pw, stored) => eq(await hashPw(pw, stored.split('$')[0]), stored);
const getAuth = async (db, k) => { try { const r = await db.prepare('SELECT value FROM auth WHERE key=?').bind(k).first(); return r ? r.value : null; } catch { return null; } };
const checkPw = async (env, pw) => { const st = await getAuth(env.DB, 'pw'); return st ? verifyPw(pw, st) : eq(pw, String(env.ADMIN_PASSWORD).trim()); };
const setAuth = (db, k, v) => db.prepare('INSERT INTO auth(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').bind(k, v);
const mkCookie = async (env, sv) => { const exp = Date.now() + 30 * 864e5; return `s=${exp}.${sv}.${await sign(`${exp}.${sv}`, env.SESSION_SECRET)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000`; };
async function authed(req, env) {
  if ((await getAuth(env.DB, 'nopw')) === '1') return true;
  const c = (req.headers.get('cookie') || '').match(/(?:^|; )s=([^;]+)/);
  if (!c) return false;
  const [exp, sv, sig] = c[1].split('.');
  if (!exp || !sv || !sig || Date.now() > +exp) return false;
  if (!eq(sig, await sign(`${exp}.${sv}`, env.SESSION_SECRET))) return false;
  return sv === ((await getAuth(env.DB, 'sv')) || '0');
}

export async function onRequest({ request, env, params }) {
  const [res, id] = params.path || [];
  const m = request.method;
  const db = env.DB;
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({ error: 'Set ADMIN_PASSWORD and SESSION_SECRET in Cloudflare' }, 500);

  if (res === 'login' && m === 'POST') {
    const { password = '' } = await request.json().catch(() => ({}));
    if (!(await checkPw(env, String(password).trim()))) return json({ error: 'Wrong password' }, 401);
    return json({ ok: 1 }, 200, { 'set-cookie': await mkCookie(env, (await getAuth(db, 'sv')) || '0') });
  }
  if (res === 'logout') return json({ ok: 1 }, 200, { 'set-cookie': 's=; Path=/; Max-Age=0' });

  if (res === 'forgot' && m === 'POST') {
    const key = String(env.RESEND_API_KEY || '').trim(), to = String(env.RESET_EMAIL || '').trim();
    if (!key || !to) return json({ error: 'Password reset email is not set up yet' }, 503);
    const now = Date.now();
    try {
      const r = await db.prepare('SELECT COUNT(*) n, COALESCE(MAX(created),0) last FROM resets WHERE created>?').bind(now - 3600e3).first();
      if (r.n >= 5 || now - r.last < 60e3) return json({ error: 'Please wait a minute before asking again' }, 429);
      const token = hex(crypto.getRandomValues(new Uint8Array(32)));
      await db.prepare('INSERT INTO resets(token_hash,created,expires) VALUES(?,?,?)').bind(await sha256(token), now, now + 15 * 60e3).run();
      const link = `${String(env.APP_URL || new URL(request.url).origin).trim()}/#reset=${token}`;
      const mail = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          from: String(env.RESET_FROM || 'BizLedger <onboarding@resend.dev>').trim(), to: [to],
          subject: 'Reset your BizLedger password',
          html: `<p>Someone asked to reset the BizLedger password.</p><p><a href="${link}">Set a new password</a></p><p>The link works once and expires in 15 minutes. If this was not you, ignore this email.</p>`,
          text: `Reset your BizLedger password (works once, expires in 15 minutes): ${link}`,
        }),
      });
      if (!mail.ok) { const d = await mail.json().catch(() => ({})); return json({ error: 'Could not send the email: ' + (d.message || mail.status) }, 502); }
      return json({ ok: 1 });
    } catch { return json({ error: 'Reset is not ready: run schema.sql on the database again' }, 500); }
  }

  if (res === 'reset' && m === 'POST') {
    const { token = '', password = '' } = await request.json().catch(() => ({}));
    const pw = String(password).trim();
    if (pw.length < 10) return json({ error: 'Use at least 10 characters' }, 400);
    try {
      const row = await db.prepare('SELECT id FROM resets WHERE token_hash=? AND used=0 AND expires>?').bind(await sha256(String(token)), Date.now()).first();
      if (!row) return json({ error: 'This link is invalid or has expired. Ask for a new one.' }, 400);
      const up = (k, v) => db.prepare('INSERT INTO auth(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').bind(k, v);
      await db.batch([up('pw', await hashPw(pw)), up('sv', String(Date.now())), db.prepare('DELETE FROM resets')]);
      return json({ ok: 1 });
    } catch { return json({ error: 'Reset is not ready: run schema.sql on the database again' }, 500); }
  }

  if (!(await authed(request, env))) return json({ error: 'Login required' }, 401);

  if (res === 'password' && m === 'POST') {
    const { current = '', password = '' } = await request.json().catch(() => ({}));
    const pw = String(password).trim();
    if (pw.length < 10) return json({ error: 'Use at least 10 characters' }, 400);
    if (!(await checkPw(env, String(current).trim()))) return json({ error: 'Current password is wrong' }, 403);
    const sv = String(Date.now());
    await db.batch([setAuth(db, 'pw', await hashPw(pw)), setAuth(db, 'sv', sv)]);
    return json({ ok: 1 }, 200, { 'set-cookie': await mkCookie(env, sv) });
  }
  if (res === 'security') {
    if (m === 'GET') return json({ protected: (await getAuth(db, 'nopw')) !== '1' });
    if (m === 'POST') {
      const { enable, current = '' } = await request.json().catch(() => ({}));
      if (enable) { await db.prepare("DELETE FROM auth WHERE key='nopw'").run(); return json({ protected: true }); }
      if (!(await checkPw(env, String(current).trim()))) return json({ error: 'Current password is wrong' }, 403);
      await setAuth(db, 'nopw', '1').run();
      return json({ protected: false });
    }
  }

  if (res === 'summary') {
    const month = new Date().toISOString().slice(0, 8) + '01';
    const [a, b, c, d] = await db.batch([
      db.prepare('SELECT COALESCE(SUM(qty*cost),0) stock, COALESCE(SUM(CASE WHEN reorder>0 AND qty<=reorder THEN 1 ELSE 0 END),0) low FROM items'),
      db.prepare('SELECT COALESCE(SUM(cost),0) assets FROM assets'),
      db.prepare('SELECT COALESCE(SUM(amount),0) spent FROM expenses WHERE date>=?').bind(month),
      db.prepare(`SELECT a.id,a.name,a.type, a.opening + COALESCE((SELECT SUM(amount) FROM transactions WHERE account_id=a.id),0) - COALESCE((SELECT SUM(amount) FROM expenses WHERE account_id=a.id),0) AS balance FROM accounts a ORDER BY a.name`),
    ]);
    return json({ ...a.results[0], ...b.results[0], ...c.results[0], accounts: d.results });
  }

  const t = T[res];
  if (!t) return json({ error: 'Not found' }, 404);
  if (m === 'GET') return json((await db.prepare(`SELECT * FROM ${res} ORDER BY ${t.order}`).all()).results);

  const body = await request.json().catch(() => ({}));
  const cols = t.cols.filter(c => c in body);
  const vals = cols.map(c => (body[c] === '' ? null : body[c]));
  try {
    if (m === 'POST') {
      const r = await db.prepare(`INSERT INTO ${res}(${cols.join(',')}) VALUES(${cols.map(() => '?').join(',')})`).bind(...vals).run();
      return json({ id: r.meta.last_row_id }, 201);
    }
    if (m === 'PUT' && id) {
      await db.prepare(`UPDATE ${res} SET ${cols.map(c => c + '=?').join(',')} WHERE id=?`).bind(...vals, id).run();
      return json({ ok: 1 });
    }
    if (m === 'DELETE' && id) {
      await db.prepare(`DELETE FROM ${res} WHERE id=?`).bind(id).run();
      return json({ ok: 1 });
    }
  } catch (e) {
    return json({ error: 'Could not save: check required fields' }, 400);
  }
  return json({ error: 'Bad request' }, 400);
}

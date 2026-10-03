/* ============================================================================
   backend.js : SERVEUR DE COMPTES DE BLM · SUPERBOTS
   Inscription, connexion, abonnements (Freemium · Pro · VIP) et paiements PayPal.
   Un seul fichier, aucune dépendance. Séparé de index.html.

   Il tourne à deux endroits, sans rien changer au fichier :
   A) Supabase Edge Functions (gratuit, pas besoin de PC allumé) : les comptes vont
      dans la table « comptes » de la base Supabase (voir SQL plus bas).
   B) Node 18+ sur un ordinateur ou un serveur : « node backend.js », les comptes vont
      dans comptes.json à côté du fichier (sauf si SUPABASE_URL est défini).

   VARIABLES (secrets Supabase « Edge Functions → Secrets », ou fichier .env avec Node)
     PAYPAL_CLIENT_ID      Client ID de l'app PayPal (public)
     PAYPAL_SECRET         Secret de l'app PayPal  ← JAMAIS dans index.html ni sur GitHub
     PAYPAL_ENV            live (vrais paiements) ou sandbox (essais) — défaut : live
     PAYPAL_PLAN_WEEK      Plan ID P-… de l'abonnement Pro 3 €/semaine
     PAYPAL_PLAN_MONTH     Plan ID P-… de l'abonnement Pro 12,75 €/mois
     VIP_PRICE / VIP_CURRENCY   défaut 55.00 / USD (achat unique)
     ALLOW_ORIGIN          adresse de la page, ex. https://samuelhaihornberg.github.io (défaut : *)
     AUTH_SECRET           facultatif (sinon dérivé de la clé de service Supabase)
     SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY   fournis automatiquement dans Supabase

   SQL À LANCER UNE FOIS dans Supabase (SQL Editor) :
     create table if not exists comptes (
       id uuid primary key default gen_random_uuid(),
       pk text unique not null,          -- pseudo en minuscules
       pseudo text not null,
       salt text not null, h text not null, h2 text,   -- codes hachés (PBKDF2), jamais en clair
       logo text, tier text not null default 'free',
       pro_until timestamptz, sub_id text, vip_ref text,
       created timestamptz not null default now());
     alter table comptes enable row level security;     -- aucune règle : seul ce backend lit la table

   ROUTES (JSON, POST sauf indication)
     GET  /config        Client ID PayPal, Plan IDs, prix VIP (rien de secret)
     POST /signup        { pseudo, code, code2?, logo?, majeur:true }  → { token, user }
     POST /login         { pseudo, code }                              → { token, user }
     GET  /me            (Authorization: Bearer <token>)               → { user }
     POST /recover       { pseudo, code2, nouveau }  code oublié, avec le code secondaire
     POST /profile       { logo?, code2? }  (connecté)
     POST /delete        { code }  supprime le compte (connecté)
     POST /pro/activate  { subscriptionID }  vérifie l'abonnement chez PayPal → Pro
     POST /vip/order     crée la commande VIP chez PayPal → { id }
     POST /vip/capture   { orderID }  encaisse chez PayPal et vérifie le montant → VIP

   Le statut Pro/VIP n'est JAMAIS décidé par la page : le backend interroge PayPal avec
   son secret. Pro dure jusqu'à la prochaine échéance PayPal (+2 jours) ; à l'expiration,
   le backend redemande à PayPal si l'abonnement est toujours actif (pas besoin de webhook).
   ============================================================================ */
'use strict';

const IS_DENO = typeof Deno !== 'undefined';
const env = k => (IS_DENO ? Deno.env.get(k) : process.env[k]) || '';
const VERSION = 'comptes-1.0';

/* ------------------------------------------------------------- outils */
const enc = new TextEncoder();
const b64u = buf => { let s = ''; new Uint8Array(buf).forEach(b => s += String.fromCharCode(b)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const uuid = () => crypto.randomUUID();
class Err extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (m, c = 400) => { throw new Err(c, m); };

async function pbkdf2(code, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(String(code)), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 120000 }, key, 256));
}
function same(a, b) { if (!a || !b || a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }

let HKEY = null;
async function hmacKey() {
  if (HKEY) return HKEY;
  let s = env('AUTH_SECRET');
  if (!s) { const base = env('SUPABASE_SERVICE_ROLE_KEY') || env('PAYPAL_SECRET'); if (!base) bad('Serveur mal configuré : définis AUTH_SECRET.', 500); s = hex(await crypto.subtle.digest('SHA-256', enc.encode('blm-auth:' + base))); }
  return HKEY = await crypto.subtle.importKey('raw', enc.encode(s), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function makeToken(id) {
  const body = b64u(enc.encode(JSON.stringify({ id, exp: Date.now() + 30 * 864e5 })));
  return body + '.' + b64u(await crypto.subtle.sign('HMAC', await hmacKey(), enc.encode(body)));
}
async function readToken(req) {
  const t = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const [body, sig] = t.split('.'); if (!body || !sig) bad('Connecte-toi.', 401);
  const want = b64u(await crypto.subtle.sign('HMAC', await hmacKey(), enc.encode(body)));
  if (!same(want, sig)) bad('Session invalide, reconnecte-toi.', 401);
  const p = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
  if (!p.exp || p.exp < Date.now()) bad('Session expirée, reconnecte-toi.', 401);
  const u = await DB.byId(p.id); if (!u) bad('Compte introuvable.', 401);
  return u;
}

/* ---------------------------------------------- anti-essais (par instance) */
const TRIES = new Map();
function throttle(key) {
  const now = Date.now(), t = TRIES.get(key) || { n: 0, at: now };
  if (now - t.at > 15 * 60e3) { t.n = 0; t.at = now; }
  if (t.n >= 8) bad('Trop d’essais. Réessaie dans 15 minutes.', 429);
  t.n++; TRIES.set(key, t);
  if (TRIES.size > 5000) TRIES.clear();
}
const okTry = key => TRIES.delete(key);

/* ------------------------------------------------------------- stockage */
const DB = (() => {
  const SU = env('SUPABASE_URL').replace(/\/$/, ''), SK = env('SUPABASE_SERVICE_ROLE_KEY');
  if (SU && SK) {
    const H = { apikey: SK, authorization: 'Bearer ' + SK, 'content-type': 'application/json', prefer: 'return=representation' };
    const q = async (path, init = {}) => {
      const r = await fetch(SU + '/rest/v1/comptes' + path, { ...init, headers: { ...H, ...(init.headers || {}) } });
      if (r.status === 409) bad('Ce pseudo est déjà pris.', 409);
      if (!r.ok) { console.error('supabase', r.status, await r.text()); bad('Base de données indisponible.', 503); }
      return r.status === 204 ? [] : r.json();
    };
    return {
      kind: 'supabase',
      byPk: async pk => (await q('?select=*&pk=eq.' + encodeURIComponent(pk)))[0] || null,
      byId: async id => /^[0-9a-f-]{36}$/.test(id) ? (await q('?select=*&id=eq.' + id))[0] || null : null,
      insert: async u => (await q('', { method: 'POST', body: JSON.stringify(u) }))[0],
      update: async (id, p) => (await q('?id=eq.' + id, { method: 'PATCH', body: JSON.stringify(p) }))[0],
      remove: async id => { await q('?id=eq.' + id, { method: 'DELETE' }); }
    };
  }
  // fichier JSON (Node seulement)
  let file = null, data = null, fs = null;
  const load = async () => { if (data) return data; fs = await import('node:fs'); const path = await import('node:path'); file = env('DATA_FILE') || path.join(process.cwd(), 'comptes.json'); try { data = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { data = {}; } return data; };
  const save = () => { fs.writeFileSync(file + '.tmp', JSON.stringify(data)); fs.renameSync(file + '.tmp', file); };
  return {
    kind: 'fichier',
    byPk: async pk => Object.values(await load()).find(u => u.pk === pk) || null,
    byId: async id => (await load())[id] || null,
    insert: async u => { await load(); if (Object.values(data).some(x => x.pk === u.pk)) bad('Ce pseudo est déjà pris.', 409); u.id = uuid(); u.created = new Date().toISOString(); data[u.id] = u; save(); return u; },
    update: async (id, p) => { await load(); Object.assign(data[id], p); save(); return data[id]; },
    remove: async id => { await load(); delete data[id]; save(); }
  };
})();

/* ------------------------------------------------------------- comptes */
function plan(u) {
  if (u.tier === 'vip') return 'vip';
  if (u.tier === 'pro' && u.pro_until && Date.parse(u.pro_until) > Date.now()) return 'pro';
  return 'freemium';
}
const pub = u => ({ id: u.id, pseudo: u.pseudo, logo: u.logo || '', plan: plan(u), pro_until: plan(u) === 'pro' ? u.pro_until : null, code2: !!u.h2 });
const pkOf = p => String(p || '').trim().toLowerCase();
function checkPseudo(p) { p = String(p || '').trim(); if (!/^[\p{L}\p{N}_.\-]{3,24}$/u.test(p)) bad('Pseudo : 3 à 24 caractères (lettres, chiffres, _ . -).'); return p; }
function checkCode(c, label = 'Code') { c = String(c || ''); if (c.length < 4 || c.length > 128) bad(label + ' : 4 caractères minimum.'); return c; }
function checkLogo(l) { if (!l) return ''; l = String(l); if (!/^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(l) || l.length > 80000) bad('Logo : image trop lourde ou format non accepté.'); return l; }

/* ------------------------------------------------------------- PayPal */
const PP = {
  base: () => env('PAYPAL_API_BASE') || (env('PAYPAL_ENV') === 'sandbox' ? 'https://api-m.sandbox.paypal.com' : 'https://api-m.paypal.com'),
  tok: null, exp: 0,
  async token() {
    if (this.tok && Date.now() < this.exp) return this.tok;
    const id = env('PAYPAL_CLIENT_ID'), sec = env('PAYPAL_SECRET'); if (!id || !sec) bad('Paiement pas encore configuré sur le serveur.', 503);
    const r = await fetch(this.base() + '/v1/oauth2/token', { method: 'POST', headers: { authorization: 'Basic ' + btoa(id + ':' + sec), 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=client_credentials' });
    if (!r.ok) { console.error('paypal token', r.status, await r.text()); bad('PayPal refuse la connexion du serveur (vérifie Client ID / Secret / PAYPAL_ENV).', 502); }
    const j = await r.json(); this.tok = j.access_token; this.exp = Date.now() + (j.expires_in - 120) * 1000; return this.tok;
  },
  async call(path, init = {}) {
    const r = await fetch(this.base() + path, { ...init, headers: { authorization: 'Bearer ' + await this.token(), 'content-type': 'application/json', ...(init.headers || {}) } });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { console.error('paypal', path, r.status, JSON.stringify(j).slice(0, 500)); bad(r.status === 404 ? 'Paiement introuvable chez PayPal.' : 'PayPal : ' + (j.details && j.details[0] && j.details[0].description || j.message || 'erreur ' + r.status), 402); }
    return j;
  }
};
const plans = () => [env('PAYPAL_PLAN_WEEK'), env('PAYPAL_PLAN_MONTH')].filter(Boolean);
async function syncSub(u) { // relit l'abonnement chez PayPal et met à jour pro_until
  const s = await PP.call('/v1/billing/subscriptions/' + encodeURIComponent(u.sub_id));
  if (s.custom_id !== u.id) bad('Cet abonnement appartient à un autre compte.', 403);
  if (!plans().includes(s.plan_id)) bad('Cet abonnement ne correspond pas à l’offre Pro.', 403);
  const next = s.billing_info && s.billing_info.next_billing_time;
  const active = s.status === 'ACTIVE' && next;
  const until = active ? new Date(Date.parse(next) + 2 * 864e5).toISOString() : u.pro_until;
  return DB.update(u.id, { tier: u.tier === 'vip' ? 'vip' : 'pro', pro_until: until });
}

/* ------------------------------------------------------------- routes */
const R = {
  'GET /health': async () => ({ ok: true, version: VERSION, stockage: DB.kind, paypal: !!(env('PAYPAL_CLIENT_ID') && env('PAYPAL_SECRET')) }),
  'GET /config': async () => ({
    paypalClientId: env('PAYPAL_CLIENT_ID'), plans: { week: env('PAYPAL_PLAN_WEEK'), month: env('PAYPAL_PLAN_MONTH') },
    vip: { price: env('VIP_PRICE') || '55.00', currency: env('VIP_CURRENCY') || 'USD' }, devise: 'EUR', sandbox: env('PAYPAL_ENV') === 'sandbox'
  }),
  'POST /signup': async (b, req, ip) => {
    throttle('up:' + ip);
    if (b.majeur !== true) bad('Il faut avoir 18 ans ou plus.');
    const pseudo = checkPseudo(b.pseudo), code = checkCode(b.code), code2 = b.code2 ? checkCode(b.code2, 'Code secondaire') : '';
    if (code2 && code2 === code) bad('Le code secondaire doit être différent du code.');
    if (await DB.byPk(pkOf(pseudo))) bad('Ce pseudo est déjà pris.', 409);
    const salt = randHex(16);
    const u = await DB.insert({ pk: pkOf(pseudo), pseudo, salt, h: await pbkdf2(code, salt), h2: code2 ? await pbkdf2(code2, salt + ':2') : null, logo: checkLogo(b.logo), tier: 'free' });
    return { token: await makeToken(u.id), user: pub(u) };
  },
  'POST /login': async (b, req, ip) => {
    const pk = pkOf(b.pseudo); throttle('in:' + ip + ':' + pk);
    const u = await DB.byPk(pk), h = u ? await pbkdf2(String(b.code || ''), u.salt) : await pbkdf2('x', 'x');
    if (!u || !same(h, u.h)) bad('Pseudo ou code incorrect.', 401);
    okTry('in:' + ip + ':' + pk);
    return { token: await makeToken(u.id), user: pub(await refresh(u)) };
  },
  'GET /me': async (b, req) => ({ user: pub(await refresh(await readToken(req))) }),
  'POST /recover': async (b, req, ip) => {
    const pk = pkOf(b.pseudo); throttle('rc:' + ip + ':' + pk);
    const u = await DB.byPk(pk);
    if (!u || !u.h2 || !same(await pbkdf2(String(b.code2 || ''), u.salt + ':2'), u.h2)) bad('Pseudo ou code secondaire incorrect.', 401);
    const salt = randHex(16), nouveau = checkCode(b.nouveau, 'Nouveau code');
    const v = await DB.update(u.id, { salt, h: await pbkdf2(nouveau, salt), h2: await pbkdf2(String(b.code2), salt + ':2') });
    okTry('rc:' + ip + ':' + pk);
    return { token: await makeToken(v.id), user: pub(v) };
  },
  'POST /profile': async (b, req) => {
    const u = await readToken(req), p = {};
    if ('logo' in b) p.logo = checkLogo(b.logo);
    if (b.code2) p.h2 = await pbkdf2(checkCode(b.code2, 'Code secondaire'), u.salt + ':2');
    return { user: pub(await DB.update(u.id, p)) };
  },
  'POST /delete': async (b, req, ip) => {
    const u = await readToken(req); throttle('del:' + ip);
    if (!same(await pbkdf2(String(b.code || ''), u.salt), u.h)) bad('Code incorrect.', 401);
    await DB.remove(u.id); return { ok: true };
  },
  'POST /pro/activate': async (b, req) => {
    const u = await readToken(req), id = String(b.subscriptionID || '');
    if (!/^I-[A-Z0-9]{6,30}$/.test(id)) bad('Identifiant d’abonnement invalide.');
    const v = await syncSub({ ...u, sub_id: id });
    if (plan(v) === 'freemium') bad('PayPal n’indique pas encore l’abonnement comme actif. Réessaie dans une minute.', 402);
    return { user: pub(await DB.update(u.id, { sub_id: id })) };
  },
  'POST /vip/order': async (b, req) => {
    const u = await readToken(req);
    if (u.tier === 'vip') bad('Tu es déjà VIP.');
    const o = await PP.call('/v2/checkout/orders', { method: 'POST', body: JSON.stringify({ intent: 'CAPTURE', purchase_units: [{ custom_id: u.id, description: 'BLM SuperBots VIP — Earn Infinite Power, Infinite Using', amount: { currency_code: env('VIP_CURRENCY') || 'USD', value: env('VIP_PRICE') || '55.00' } }] }) });
    return { id: o.id };
  },
  'POST /vip/capture': async (b, req) => {
    const u = await readToken(req), id = String(b.orderID || '');
    if (!/^[A-Z0-9]{10,30}$/.test(id)) bad('Commande invalide.');
    let o = await PP.call('/v2/checkout/orders/' + id);
    if (o.status === 'APPROVED') o = await PP.call('/v2/checkout/orders/' + id + '/capture', { method: 'POST', body: '{}' });
    const pu = o.purchase_units && o.purchase_units[0], cap = pu && pu.payments && pu.payments.captures && pu.payments.captures[0];
    const amount = cap && cap.amount;
    if (o.status !== 'COMPLETED' || !cap || cap.status !== 'COMPLETED') bad('Le paiement n’est pas encaissé.', 402);
    if ((cap.custom_id || pu.custom_id) !== u.id) bad('Ce paiement appartient à un autre compte.', 403);
    if (!amount || amount.currency_code !== (env('VIP_CURRENCY') || 'USD') || parseFloat(amount.value) < parseFloat(env('VIP_PRICE') || '55')) bad('Montant incorrect.', 402);
    return { user: pub(await DB.update(u.id, { tier: 'vip', vip_ref: cap.id })) };
  }
};
async function refresh(u) { // Pro expiré mais abonnement connu : on redemande à PayPal
  if (u.tier === 'pro' && u.sub_id && plan(u) === 'freemium') { try { return await syncSub(u); } catch (e) { console.error('sync', e.message); } }
  return u;
}

/* ------------------------------------------------------------- serveur */
async function handle(req, ip) {
  const origin = env('ALLOW_ORIGIN') || '*';
  const cors = { 'access-control-allow-origin': origin, 'access-control-allow-headers': 'authorization, content-type, apikey, x-client-info', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-max-age': '86400', vary: 'origin' };
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  const path = new URL(req.url).pathname.replace(/\/+$/, '');
  const key = Object.keys(R).find(k => { const [m, p] = k.split(' '); return m === req.method && path.endsWith(p); });
  const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...cors, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
  if (!key) return json({ error: 'Route inconnue. Routes : ' + Object.keys(R).join(', ') }, 404);
  try {
    let body = {};
    if (req.method === 'POST') { const t = await req.text(); if (t.length > 120000) bad('Requête trop lourde.', 413); body = t ? JSON.parse(t) : {}; }
    return json(await R[key](body, req, ip || 'x'));
  } catch (e) {
    if (e instanceof Err) return json({ error: e.message }, e.code);
    if (e instanceof SyntaxError) return json({ error: 'JSON invalide.' }, 400);
    console.error(e); return json({ error: 'Erreur du serveur.' }, 500);
  }
}

if (IS_DENO) {
  Deno.serve((req, info) => handle(req, req.headers.get('x-forwarded-for')?.split(',')[0].trim() || info?.remoteAddr?.hostname));
} else {
  (async () => {
    const fs = await import('node:fs'), path = await import('node:path'), http = await import('node:http');
    try { // .env facultatif à côté du fichier
      fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => { const m = /^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(l); if (m && !l.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, ''); });
    } catch (e) { }
    if (!process.env.AUTH_SECRET && !process.env.SUPABASE_SERVICE_ROLE_KEY && !process.env.PAYPAL_SECRET) { process.env.AUTH_SECRET = randHex(32); console.log('⚠️  AUTH_SECRET absent : secret temporaire (les sessions tombent au redémarrage).'); }
    const PORT = +(process.env.PORT || 8788), HOST = process.env.HOST || '127.0.0.1';
    http.createServer(async (rq, rs) => {
      const chunks = []; for await (const c of rq) chunks.push(c);
      const req = new Request('http://x' + rq.url, { method: rq.method, headers: rq.headers, body: ['GET', 'HEAD', 'OPTIONS'].includes(rq.method) ? undefined : Buffer.concat(chunks) });
      const ip = process.env.TRUST_PROXY === '1' ? String(rq.headers['x-forwarded-for'] || '').split(',')[0].trim() : rq.socket.remoteAddress;
      const r = await handle(req, ip);
      rs.writeHead(r.status, Object.fromEntries(r.headers)); rs.end(Buffer.from(await r.arrayBuffer()));
    }).listen(PORT, HOST, () => console.log('Serveur de comptes BLM · http://' + HOST + ':' + PORT + ' · stockage : ' + DB.kind));
  })();
}

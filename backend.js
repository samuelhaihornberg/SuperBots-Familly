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
     PAYPAL_CLIENT_ID      Client ID de l'app REST PayPal (commence par A…, public) : sert à VÉRIFIER
                           les paiements et au bouton VIP. developer.paypal.com → Apps & Credentials → Live
     PAYPAL_SECRET         Secret de cette app REST  ← JAMAIS dans index.html ni sur GitHub
     PAYPAL_ENV            live (vrais paiements) ou sandbox (essais) — défaut : live
     PAYPAL_SDK_CLIENT_ID  client-id du bouton d'abonnement (Button Factory) — déjà mis par défaut
     PAYPAL_PLAN_MONTH     Plan ID de l'abonnement Pro — défaut : P-5HH23920L98176507NLAGCGQ (55 ₪ / mois)
     PRO_PRICE / PRO_CURRENCY   prix affiché du Pro, défaut 55 / ILS (PayPal facture le montant du plan)
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
     create table if not exists tts_items (               -- Tricks, Trocks and Services
       id uuid primary key default gen_random_uuid(),
       kind text not null,               -- post, comment, offer, profile, report
       owner uuid not null references comptes(id) on delete cascade,
       ref text, data jsonb not null default '{}', created timestamptz not null default now());
     create index if not exists tts_items_kind on tts_items(kind, created desc);
     alter table tts_items enable row level security;

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
     TRICKS, TROCKS AND SERVICES (voir le bloc plus bas)
     GET  /tts/rules · GET /tts/wall?q=&type=&mode=&sort= · GET /tts/post?id= · GET /tts/profile?pseudo=
     POST /tts/post · /tts/post/delete · /tts/comment · /tts/profile · /tts/offer · /tts/offer/step · /tts/report
     GET  /tts/offers (connecté) · GET /tts/fees (seulement le compte TTS_ADMIN : taxes dues)
     TTS_ADMIN             pseudo du propriétaire de la plateforme (voit les taxes dues, peut retirer une annonce)

   Le statut Pro/VIP n'est JAMAIS décidé par la page : le backend interroge PayPal avec
   son secret. Pro dure jusqu'à la prochaine échéance PayPal (+2 jours) ; à l'expiration,
   le backend redemande à PayPal si l'abonnement est toujours actif (pas besoin de webhook).
   ============================================================================ */
'use strict';

const IS_DENO = typeof Deno !== 'undefined';
const env = k => (IS_DENO ? Deno.env.get(k) : process.env[k]) || '';
const VERSION = 'comptes-1.2';
// valeurs publiques par défaut (elles sont déjà visibles dans le bouton PayPal)
const DEF = { PAYPAL_SDK_CLIENT_ID: 'BAAh2U6i_k7evwM-u5s193_Ylttp4v_5FvZ18Qg-kQwAxAhSLQBoBFsz37eS4zJC4JtYxASiha9wHno6PM', PAYPAL_PLAN_MONTH: 'P-5HH23920L98176507NLAGCGQ', PRO_PRICE: '55', PRO_CURRENCY: 'ILS', VIP_PRICE: '55.00', VIP_CURRENCY: 'USD' };
const cfg = k => env(k) || DEF[k] || '';

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
const pub = u => ({ id: u.id, pseudo: u.pseudo, logo: u.logo || '', plan: plan(u), pro_until: plan(u) === 'pro' ? u.pro_until : null, code2: !!u.h2, pending: !!u.sub_id && plan(u) === 'freemium' });
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
const plans = () => [cfg('PAYPAL_PLAN_MONTH'), env('PAYPAL_PLAN_WEEK')].filter(Boolean);
const canVerify = () => !!(env('PAYPAL_CLIENT_ID') && env('PAYPAL_SECRET'));
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
  'GET /health': async () => ({ ok: true, version: VERSION, stockage: DB.kind, paypal: canVerify() }),
  'GET /config': async () => ({
    paypalClientId: env('PAYPAL_CLIENT_ID'), sdkClientId: cfg('PAYPAL_SDK_CLIENT_ID') || env('PAYPAL_CLIENT_ID'), verify: canVerify(),
    plans: { month: cfg('PAYPAL_PLAN_MONTH') }, pro: { price: cfg('PRO_PRICE'), currency: cfg('PRO_CURRENCY') },
    vip: { price: cfg('VIP_PRICE'), currency: cfg('VIP_CURRENCY') }, sandbox: env('PAYPAL_ENV') === 'sandbox'
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
    if (!canVerify()) { // paiement reçu mais vérification pas encore branchée : on garde l'ID, l'accès s'ouvrira tout seul
      const w = await DB.update(u.id, { sub_id: id });
      return { pending: true, message: 'Paiement reçu (abonnement ' + id + '). La vérification PayPal n’est pas encore branchée sur le serveur : ton Pro s’activera tout seul dès qu’elle le sera.', user: pub(w) };
    }
    const v = await syncSub({ ...u, sub_id: id });
    if (plan(v) === 'freemium') bad('PayPal n’indique pas encore l’abonnement comme actif. Réessaie dans une minute.', 402);
    return { user: pub(await DB.update(u.id, { sub_id: id })) };
  },
  'POST /vip/order': async (b, req) => {
    const u = await readToken(req);
    if (u.tier === 'vip') bad('Tu es déjà VIP.');
    if (!canVerify()) bad('Achat VIP pas encore branché sur le serveur (identifiants REST PayPal manquants).', 503);
    const o = await PP.call('/v2/checkout/orders', { method: 'POST', body: JSON.stringify({ intent: 'CAPTURE', purchase_units: [{ custom_id: u.id, description: 'BLM SuperBots VIP — Earn Infinite Power, Infinite Using', amount: { currency_code: cfg('VIP_CURRENCY'), value: cfg('VIP_PRICE') } }] }) });
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
    if (!amount || amount.currency_code !== cfg('VIP_CURRENCY') || parseFloat(amount.value) < parseFloat(cfg('VIP_PRICE'))) bad('Montant incorrect.', 402);
    return { user: pub(await DB.update(u.id, { tier: 'vip', vip_ref: cap.id })) };
  }
};
/* ======================================================= TRICKS, TROCKS AND SERVICES
   Mur commun, profils et boutiques, recherche, échanges (trick ↔ trick, trock, service ou argent).
   Prix en dollars US : trick 1 $ minimum, trock 10 $ minimum, service 10 $ minimum.
   Étapes (tricks et services) : 3 comprises dans le prix minimum ; ensuite +1 à +5 $ par paire
   d'étapes en plus (au choix de celui qui propose, demande ou exige).
   Taxe de la plateforme : 1 $ par échange terminé (enregistrée « due » ; le paiement réel
   entre utilisateurs n'est PAS encore branché : les deux parties règlent entre elles).
   =================================================================================== */
const TTS = { MIN: { trick: 1, trock: 10, service: 10 }, TAX: 1, CUR: 'USD', STEPS_IN: 3, BUMP: [1, 5], PAY: ['PayPal', 'Bit', 'Virement bancaire', 'Crypto', 'Échange sans argent'],
  BAN: /\b(armes?|munitions?|drogues?|coca[ïi]ne|h[ée]ro[ïi]ne|cannabis|faux papiers|faux documents?|pirat(age|er) de comptes?|carte bancaire vol[ée]e|escort|prostitution)\b/i };
const minPrice = (type, steps, bump) => TTS.MIN[type] + (type === 'trock' ? 0 : Math.ceil(Math.max(0, steps - TTS.STEPS_IN) / 2) * bump);
const txt = (v, max, label, min = 0) => { const s = String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim(); if (s.length < min) bad(label + ' : ' + min + ' caractères minimum.'); if (s.length > max) bad(label + ' : ' + max + ' caractères maximum.'); return s; };
const TS = (() => {   // stockage des objets du mur (table tts_items dans Supabase, sinon tts.json)
  const SU = env('SUPABASE_URL').replace(/\/$/, ''), SK = env('SUPABASE_SERVICE_ROLE_KEY');
  if (SU && SK) {
    const H = { apikey: SK, authorization: 'Bearer ' + SK, 'content-type': 'application/json', prefer: 'return=representation' };
    const q = async (path, init = {}) => { const r = await fetch(SU + '/rest/v1/tts_items' + path, { ...init, headers: { ...H, ...(init.headers || {}) } }); if (!r.ok) { console.error('supabase tts', r.status, await r.text()); bad('Base de données indisponible.', 503); } return r.status === 204 ? [] : r.json(); };
    const flat = x => x && Object.assign({}, x.data, { id: x.id, kind: x.kind, owner: x.owner, ref: x.ref, created: x.created });
    return {
      insert: async (kind, owner, ref, data) => flat((await q('', { method: 'POST', body: JSON.stringify({ kind, owner, ref: ref || null, data }) }))[0]),
      get: async id => /^[0-9a-f-]{36}$/.test(id) ? flat((await q('?select=*&id=eq.' + id))[0]) : null,
      update: async (id, data) => flat((await q('?id=eq.' + id, { method: 'PATCH', body: JSON.stringify({ data }) }))[0]),
      remove: async id => { await q('?id=eq.' + id, { method: 'DELETE' }); },
      list: async (kind, f = {}) => (await q('?select=*&kind=eq.' + kind + (f.ref ? '&ref=eq.' + encodeURIComponent(f.ref) : '') + (f.owner ? '&owner=eq.' + f.owner : '') + '&order=created.desc&limit=' + (f.limit || 500))).map(flat)
    };
  }
  let file = null, data = null, fs = null;
  const load = async () => { if (data) return data; fs = await import('node:fs'); const path = await import('node:path'); file = env('TTS_FILE') || path.join(process.cwd(), 'tts.json'); try { data = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { data = {}; } return data; };
  const save = () => { fs.writeFileSync(file + '.tmp', JSON.stringify(data)); fs.renameSync(file + '.tmp', file); };
  const flat = x => x && Object.assign({}, x.data, { id: x.id, kind: x.kind, owner: x.owner, ref: x.ref, created: x.created });
  return {
    insert: async (kind, owner, ref, d) => { await load(); const x = { id: uuid(), kind, owner, ref: ref || null, data: d, created: new Date().toISOString() }; data[x.id] = x; save(); return flat(x); },
    get: async id => flat((await load())[id]),
    update: async (id, d) => { await load(); if (!data[id]) return null; data[id].data = d; save(); return flat(data[id]); },
    remove: async id => { await load(); delete data[id]; save(); },
    list: async (kind, f = {}) => Object.values(await load()).filter(x => x.kind === kind && (!f.ref || x.ref === f.ref) && (!f.owner || x.owner === f.owner)).sort((a, b) => b.created.localeCompare(a.created)).slice(0, f.limit || 500).map(flat)
  };
})();
const strip = o => { const { kind, ref, ...r } = o; return r; };
const dataOf = o => { const { id, kind, owner, ref, created, ...d } = o; return d; };
async function who(id) { const u = await DB.byId(id); return u ? { pseudo: u.pseudo, logo: u.logo || '' } : { pseudo: 'compte supprimé', logo: '' }; }
async function profOf(owner) { return (await TS.list('profile', { owner, limit: 1 }))[0] || null; }
async function recent(kind, owner, ms) { const t = Date.now() - ms; return (await TS.list(kind, { owner, limit: 200 })).filter(x => Date.parse(x.created) > t).length; }
async function postOut(p, withPay) {
  const w = await who(p.owner), pr = await profOf(p.owner);
  const o = { id: p.id, owner: p.owner, pseudo: w.pseudo, logo: w.logo, shop: pr && pr.kind === 'pro' ? pr.shop || '' : '', pro: !!(pr && pr.kind === 'pro'), type: p.type, mode: p.mode, title: p.title, body: p.body, price: p.price, steps: p.steps, stepBump: p.stepBump, accepts: p.accepts, pay: p.pay, cat: p.cat, created: p.created, updated: p.updated || p.created, comments: p.ncom || 0, total: p.price + TTS.TAX };
  return o;
}
function checkPost(b) {
  const type = ['trick', 'trock', 'service'].includes(b.type) ? b.type : bad('Type : trick, trock ou service.');
  const mode = ['offre', 'demande', 'exige'].includes(b.mode) ? b.mode : 'offre';
  const title = txt(b.title, 90, 'Titre', 4), body = txt(b.body, 2000, 'Description');
  const steps = (Array.isArray(b.steps) ? b.steps : []).map(s => txt(s, 200, 'Étape')).filter(Boolean).slice(0, 30);
  if (type !== 'trock' && !steps.length) bad('Un ' + type + ' demande au moins une étape (3 sont comprises dans le prix minimum).');
  const bump = Math.round(+b.stepBump || 1); if (bump < TTS.BUMP[0] || bump > TTS.BUMP[1]) bad('Prix par paire d’étapes en plus : de 1 à 5 $.');
  const price = Math.round((+b.price || 0) * 100) / 100, min = minPrice(type, steps.length, bump);
  if (!(price >= min)) bad('Prix minimum pour ce ' + type + ' : ' + min + ' $ (' + TTS.MIN[type] + ' $' + (min > TTS.MIN[type] ? ' + ' + (min - TTS.MIN[type]) + ' $ pour les étapes au-delà de 3' : '') + ').');
  if (price > 100000) bad('Prix trop élevé.');
  const accepts = (Array.isArray(b.accepts) ? b.accepts : ['argent']).filter(x => ['argent', 'trick', 'trock', 'service'].includes(x)); if (!accepts.length) accepts.push('argent');
  const pay = (Array.isArray(b.pay) ? b.pay : []).filter(x => TTS.PAY.includes(x));
  const cat = txt(b.cat, 40, 'Catégorie');
  if (TTS.BAN.test(title + ' ' + body + ' ' + steps.join(' '))) bad('Cette annonce touche à un domaine interdit sur la plateforme (armes, drogues, faux documents, piratage, prostitution…).', 422);
  return { type, mode, title, body, steps, stepBump: bump, price, accepts, pay, cat };
}
const qs = req => Object.fromEntries(new URL(req.url).searchParams);
const ADMIN = () => pkOf(env('TTS_ADMIN'));
Object.assign(R, {
  'GET /tts/rules': async () => ({ min: TTS.MIN, tax: TTS.TAX, currency: TTS.CUR, stepsIncluded: TTS.STEPS_IN, bumpPer2Steps: TTS.BUMP, pay: TTS.PAY, paymentLive: false }),
  'GET /tts/wall': async (b, req) => {
    const f = qs(req), q = String(f.q || '').toLowerCase().trim().slice(0, 80), max = Math.min(100, +f.max || 40);
    let a = (await TS.list('post', { limit: 500 })).filter(p => !p.hidden);
    if (['trick', 'trock', 'service'].includes(f.type)) a = a.filter(p => p.type === f.type);
    if (['offre', 'demande', 'exige'].includes(f.mode)) a = a.filter(p => p.mode === f.mode);
    if (f.owner) a = a.filter(p => p.owner === f.owner);
    if (q) a = a.filter(p => (p.title + ' ' + p.body + ' ' + p.cat + ' ' + (p.steps || []).join(' ')).toLowerCase().includes(q));
    if (f.sort === 'prix') a.sort((x, y) => x.price - y.price); else if (f.sort === 'prix-') a.sort((x, y) => y.price - x.price);
    return { posts: await Promise.all(a.slice(0, max).map(p => postOut(p))), total: a.length };
  },
  'GET /tts/post': async (b, req) => {
    const p = await TS.get(String(qs(req).id || '')); if (!p || p.kind !== 'post' || p.hidden) bad('Annonce introuvable.', 404);
    const com = await TS.list('comment', { ref: p.id, limit: 200 });
    return { post: await postOut(p), comments: await Promise.all(com.reverse().map(async c => ({ id: c.id, pseudo: (await who(c.owner)).pseudo, text: c.text, created: c.created }))) };
  },
  'POST /tts/post': async (b, req) => {
    const u = await readToken(req), d = checkPost(b);
    if (b.id) { const p = await TS.get(String(b.id)); if (!p || p.kind !== 'post' || p.owner !== u.id) bad('Annonce introuvable.', 404); return { post: await postOut(await TS.update(p.id, Object.assign(dataOf(p), d, { updated: new Date().toISOString() }))) }; }
    if (await recent('post', u.id, 864e5) >= 20) bad('20 annonces par jour au maximum.', 429);
    return { post: await postOut(await TS.insert('post', u.id, null, Object.assign(d, { ncom: 0, reports: [] }))) };
  },
  'POST /tts/post/delete': async (b, req) => { const u = await readToken(req), p = await TS.get(String(b.id || '')); if (!p || p.kind !== 'post' || (p.owner !== u.id && u.pk !== ADMIN())) bad('Annonce introuvable.', 404); await TS.remove(p.id); return { ok: true }; },
  'POST /tts/comment': async (b, req) => {
    const u = await readToken(req), p = await TS.get(String(b.post || '')); if (!p || p.kind !== 'post' || p.hidden) bad('Annonce introuvable.', 404);
    if (await recent('comment', u.id, 864e5) >= 60) bad('60 messages par jour au maximum.', 429);
    const text = txt(b.text, 600, 'Message', 1); if (TTS.BAN.test(text)) bad('Message refusé : domaine interdit.', 422);
    const c = await TS.insert('comment', u.id, p.id, { text }); await TS.update(p.id, Object.assign(dataOf(p), { ncom: (p.ncom || 0) + 1 }));
    return { comment: { id: c.id, pseudo: u.pseudo, text, created: c.created } };
  },
  'GET /tts/profile': async (b, req) => {
    const u = await DB.byPk(pkOf(qs(req).pseudo)); if (!u) bad('Profil introuvable.', 404);
    const pr = await profOf(u.id), posts = (await TS.list('post', { owner: u.id, limit: 100 })).filter(p => !p.hidden);
    return { profile: { pseudo: u.pseudo, logo: u.logo || '', kind: pr ? pr.kind : 'particulier', shop: pr ? pr.shop || '' : '', bio: pr ? pr.bio || '' : '', links: pr ? pr.links || '' : '' }, posts: await Promise.all(posts.map(p => postOut(p))) };
  },
  'POST /tts/profile': async (b, req) => {
    const u = await readToken(req), pr = await profOf(u.id);
    const d = { kind: b.kind === 'pro' ? 'pro' : 'particulier', shop: txt(b.shop, 60, 'Nom de boutique'), bio: txt(b.bio, 4000, 'Présentation'), links: txt(b.links, 300, 'Liens'), payInfo: txt(b.payInfo, 300, 'Comment te payer') };
    if (d.kind === 'pro' && d.shop.length < 2) bad('Donne un nom à ta boutique.');
    if (TTS.BAN.test(d.bio + ' ' + d.shop)) bad('Présentation refusée : domaine interdit.', 422);
    const x = pr ? await TS.update(pr.id, d) : await TS.insert('profile', u.id, null, d);
    return { profile: Object.assign({ pseudo: u.pseudo }, dataOf(x)) };
  },
  'POST /tts/offer': async (b, req) => {
    const u = await readToken(req), p = await TS.get(String(b.post || '')); if (!p || p.kind !== 'post' || p.hidden) bad('Annonce introuvable.', 404);
    if (p.owner === u.id) bad('C’est ton annonce.');
    if (await recent('offer', u.id, 864e5) >= 30) bad('30 propositions par jour au maximum.', 429);
    const kind = ['argent', 'trick', 'trock', 'service'].includes(b.give && b.give.kind) ? b.give.kind : bad('Que donnes-tu en échange ?');
    if (!p.accepts.includes(kind)) bad('Cette annonce n’accepte pas : ' + kind + '. Elle accepte : ' + p.accepts.join(', ') + '.');
    const amount = kind === 'argent' ? Math.round((+b.give.amount || 0) * 100) / 100 : 0;
    if (kind === 'argent' && amount < p.price) bad('Le prix demandé est ' + p.price + ' $ (plus 1 $ de taxe).');
    const give = { kind, amount, text: txt(b.give.text, 400, 'Ce que tu proposes', kind === 'argent' ? 0 : 3) }, message = txt(b.message, 600, 'Message');
    if (TTS.BAN.test(give.text + ' ' + message)) bad('Proposition refusée : domaine interdit.', 422);
    const o = await TS.insert('offer', u.id, p.id, { to: p.owner, post: { id: p.id, title: p.title, type: p.type, price: p.price }, give, message, status: 'proposé', doneFrom: false, doneTo: false, paid: false, tax: TTS.TAX, taxStatus: 'en attente' });
    return { offer: strip(o) };
  },
  'GET /tts/offers': async (b, req) => {
    const u = await readToken(req), out = (await TS.list('offer', { owner: u.id, limit: 200 })), inc = (await TS.list('offer', { limit: 2000 })).filter(o => o.to === u.id);
    const view = async (o, mine) => { const other = await who(mine ? o.to : o.owner), opr = ['accepté', 'terminé'].includes(o.status) ? await profOf(mine ? o.to : o.owner) : null; return Object.assign(strip(o), { side: mine ? 'envoyée' : 'reçue', other: other.pseudo, otherPay: opr ? opr.payInfo || '' : '' }); };
    return { sent: await Promise.all(out.map(o => view(o, true))), received: await Promise.all(inc.map(o => view(o, false))) };
  },
  'POST /tts/offer/step': async (b, req) => {
    const u = await readToken(req), o = await TS.get(String(b.id || '')); if (!o || o.kind !== 'offer' || (o.owner !== u.id && o.to !== u.id)) bad('Proposition introuvable.', 404);
    const d = dataOf(o), me = o.owner === u.id ? 'from' : 'to', a = String(b.action || '');
    if (a === 'accepter' || a === 'refuser') { if (me !== 'to' || d.status !== 'proposé') bad('Action impossible.'); d.status = a === 'accepter' ? 'accepté' : 'refusé'; }
    else if (a === 'annuler') { if (!['proposé', 'accepté'].includes(d.status) || d.doneFrom || d.doneTo) bad('Action impossible.'); d.status = 'annulé'; }
    else if (a === 'payé') { if (me !== 'from' || d.status !== 'accepté' || d.give.kind !== 'argent') bad('Action impossible.'); d.paid = true; }
    else if (a === 'fait') { if (d.status !== 'accepté') bad('Action impossible.'); d[me === 'from' ? 'doneFrom' : 'doneTo'] = true; if (d.doneFrom && d.doneTo) { d.status = 'terminé'; d.taxStatus = 'due'; d.ended = new Date().toISOString(); } }
    else bad('Action inconnue.');
    return { offer: strip(await TS.update(o.id, d)) };
  },
  'POST /tts/report': async (b, req) => {
    const u = await readToken(req), p = await TS.get(String(b.post || '')); if (!p || p.kind !== 'post') bad('Annonce introuvable.', 404);
    const d = dataOf(p); d.reports = [...new Set((d.reports || []).concat(u.id))]; if (d.reports.length >= 3) d.hidden = true;
    await TS.insert('report', u.id, p.id, { reason: txt(b.reason, 300, 'Raison') }); await TS.update(p.id, d); return { ok: true, hidden: !!d.hidden };
  },
  'GET /tts/fees': async (b, req) => {
    const u = await readToken(req); if (!ADMIN() || u.pk !== ADMIN()) bad('Réservé au propriétaire de la plateforme (TTS_ADMIN).', 403);
    const all = (await TS.list('offer', { limit: 5000 })).filter(o => o.status === 'terminé');
    return { count: all.length, due: all.filter(o => o.taxStatus === 'due').length * TTS.TAX, currency: TTS.CUR };
  }
});

async function refresh(u) { // Pro expiré mais abonnement connu : on redemande à PayPal
  if (u.tier !== 'vip' && u.sub_id && plan(u) === 'freemium' && canVerify()) { try { return await syncSub(u); } catch (e) { console.error('sync', e.message); } }
  return u;
}

/* ------------------------------------------------------------- serveur */
async function handle(req, ip) {
  const origin = env('ALLOW_ORIGIN') || '*';
  const cors = { 'access-control-allow-origin': origin, 'access-control-allow-headers': 'authorization, content-type, apikey, x-client-info', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-max-age': '86400', vary: 'origin' };
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  const path = new URL(req.url).pathname.replace(/\/+$/, '');
  const key = Object.keys(R).filter(k => { const [m, p] = k.split(' '); return m === req.method && (path === p || (path.endsWith(p) && !path.slice(0, -p.length).endsWith('/tts'))); }).sort((x, y) => y.length - x.length)[0];
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

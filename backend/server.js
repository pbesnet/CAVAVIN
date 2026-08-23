// ═══════════════════════════════════════════════════════════════
// CAVAVIN — Backend Node.js pour AIVEN PostgreSQL
// v3 : lazy loading des photos.
//   - GET /api/data ne renvoie plus les photos (juste hasPhoto)
//   - GET /api/photo/:id renvoie une photo à la demande
//   - POST & PATCH préservent la photo en base si le payload n'en fournit pas
//   Contrat inchangé pour tout le reste.
// ═══════════════════════════════════════════════════════════════
'use strict';

const express  = require('express');
const { Pool } = require('pg');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const fetch    = require('node-fetch');

const app = express();

// ── Config ────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'changez-moi-en-prod';
const JWT_TTL    = '7d';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

const pool = new Pool({
  connectionString: process.env.AIVEN_PG_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
});

// ── Middlewares ───────────────────────────────────────────────
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Non authentifié' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
}

// ═══════════════════════════════════════════════════════════════
// HELPERS de mapping
// ═══════════════════════════════════════════════════════════════
// data = le vin SANS la photo (la photo vit dans sa colonne)
function wineDataOnly(w) { const { photo, ...rest } = w; return rest; }
// true si le payload fournit explicitement une clé "photo" (même null = effacement voulu)
function photoProvided(w) { return Object.prototype.hasOwnProperty.call(w, 'photo'); }
function rowToCave(row)   { return { ...row.data, id: row.id }; }

// Upsert d'un vin en préservant la photo si le payload n'en fournit pas.
async function upsertWine(client, w) {
  const data = JSON.stringify(wineDataOnly(w));
  const caveId = w.caveId ?? null;
  if (photoProvided(w)) {
    // Le front fournit la photo (nouvelle, inchangée, ou null=effacement) → on l'applique.
    await client.query(
      `INSERT INTO wines (id, cave_id, photo, data, updated_at)
       VALUES ($1,$2,$3,$4::jsonb,NOW())
       ON CONFLICT (id) DO UPDATE
         SET cave_id=EXCLUDED.cave_id, photo=EXCLUDED.photo, data=EXCLUDED.data, updated_at=NOW()`,
      [w.id, caveId, w.photo ?? null, data]
    );
  } else {
    // Pas de photo dans le payload (cas lazy) → on NE TOUCHE PAS la colonne photo existante.
    await client.query(
      `INSERT INTO wines (id, cave_id, photo, data, updated_at)
       VALUES ($1,$2,NULL,$3::jsonb,NOW())
       ON CONFLICT (id) DO UPDATE
         SET cave_id=EXCLUDED.cave_id, data=EXCLUDED.data, updated_at=NOW()`,
      [w.id, caveId, data]
    );
  }
}

// Journal d'activité : enregistre qui a fait quoi. Ne casse JAMAIS la mutation
// en cas d'échec (ex: table absente) — le log est secondaire.
async function logActivity(client, email, action, wineId, label){
  try{
    await client.query(
      'INSERT INTO activity (user_email, action, wine_id, label) VALUES ($1,$2,$3,$4)',
      [email || '?', action, wineId || null, label || null]
    );
  }catch(_){ /* silencieux : la mutation prime sur le log */ }
}
function wineLabel(w){ return `${w.nom||'(sans nom)'}${w.millesime?' '+w.millesime:''}`; }

// ── Health check ──────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ═══════════════════════════════════════════════════════════════
// AUTH  (inchangé)
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  try {
    const { rows } = await pool.query(
      'SELECT id, email, password_hash, role, api_key, demo_only FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Identifiants incorrects' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok)  return res.status(401).json({ error: 'Identifiants incorrects' });
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    const demoOnly = user.demo_only === true || user.demo_only === 't' || user.demo_only === 'true';
    const payload = { sub: user.id, email: user.email, role: user.role, demo_only: demoOnly };
    const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_TTL });
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, demo_only: demoOnly }, api_key: user.api_key || null });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/auth/session', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.sub, email: req.user.email, role: req.user.role, demo_only: req.user.demo_only || false } });
});

app.post('/api/auth/logout', requireAuth, (req, res) => res.json({ ok: true }));

app.post('/api/auth/reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email requis' });
  const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
  if (!rows.length) return res.json({ ok: true, message: 'Si ce compte existe, un email a été envoyé' });
  res.json({ ok: true, message: 'Contacte l\'administrateur pour réinitialiser ton mot de passe' });
});

// ═══════════════════════════════════════════════════════════════
// DONNÉES — v3 (photos en lazy)
// ═══════════════════════════════════════════════════════════════

// GET /api/data → vins SANS photo (hasPhoto seulement) : réponse légère
app.get('/api/data', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const t0 = Date.now();
  try {
    const [caves, wines, journal, meta] = await Promise.all([
      pool.query('SELECT id, data FROM caves ORDER BY id'),
      pool.query('SELECT id, cave_id, (photo IS NOT NULL) AS has_photo, data FROM wines ORDER BY id'),
      pool.query('SELECT entry FROM journal ORDER BY created_at, id'),
      pool.query("SELECT ncave, nwine, stats FROM app_meta WHERE id='main'"),
    ]);
    const m = meta.rows[0] || { ncave: 1, nwine: 1, stats: {} };
    const data = {
      caves:   caves.rows.map(rowToCave),
      wines:   wines.rows.map(r => ({ ...r.data, id: r.id, caveId: r.cave_id, hasPhoto: r.has_photo })),
      journal: journal.rows.map(r => r.entry),
      nCave:   m.ncave,
      nWine:   m.nwine,
      statsAnnuelles: m.stats || {},
    };
    let api_key = null;
    if (req.user.role === 'admin') {
      const { rows: urows } = await pool.query('SELECT api_key FROM users WHERE id=$1', [req.user.sub]);
      api_key = urows[0]?.api_key || null;
    }
    console.log(`[DB] loadData: ${Date.now() - t0}ms (${data.wines.length}w ${data.caves.length}c, no-photos)`);
    res.json({ data, api_key });
  } catch (e) {
    console.error('getData error:', e);
    res.status(500).json({ error: 'Erreur lecture données' });
  }
});

// GET /api/photo/:id → une seule photo, à la demande
app.get('/api/photo/:id', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'id invalide' });
  try {
    const { rows } = await pool.query('SELECT photo FROM wines WHERE id=$1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Vin introuvable' });
    res.json({ photo: rows[0].photo || null });
  } catch (e) {
    console.error('getPhoto error:', e);
    res.status(500).json({ error: 'Erreur lecture photo' });
  }
});

// GET /api/activity → journal "qui a fait quoi" (100 dernières actions)
app.get('/api/activity', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  try {
    const { rows } = await pool.query(
      'SELECT id, ts, user_email, action, wine_id, label FROM activity ORDER BY ts DESC LIMIT 100'
    );
    res.json({ activity: rows });
  } catch (e) {
    console.error('getActivity error:', e);
    res.status(500).json({ error: 'Erreur lecture activité' });
  }
});

// POST /api/data → resync complet, SANS TRUNCATE (préserve les photos), en transaction.
app.post('/api/data', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const { data } = req.body || {};
  if (!data) return res.status(400).json({ error: 'data manquant' });

  const inWines = Array.isArray(data.wines) ? data.wines : [];
  const inCaves = Array.isArray(data.caves) ? data.caves : [];
  const inJournal = Array.isArray(data.journal) ? data.journal : [];

  const client = await pool.connect();
  try {
    // 🛡️ GARDE-FOU anti-écrasement (incident du 03/06/2026).
    if (inWines.length === 0 && inCaves.length === 0) {
      const { rows } = await client.query('SELECT (SELECT count(*) FROM wines) w, (SELECT count(*) FROM caves) c');
      if (Number(rows[0].w) > 0 || Number(rows[0].c) > 0) {
        console.warn(`[GARDE-FOU] POST vide REFUSE : 0 vin/0 cave alors que la base contient ${rows[0].w} vins / ${rows[0].c} caves.`);
        return res.status(409).json({ error: 'Sauvegarde vide refusée : la base contient déjà des données. Rechargez l’application avant de sauvegarder.' });
      }
    }

    const t0 = Date.now();
    await client.query('BEGIN');

    for (const c of inCaves) {
      await client.query(
        `INSERT INTO caves (id, data, updated_at) VALUES ($1,$2::jsonb,NOW())
         ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()`,
        [c.id, JSON.stringify(c)]
      );
    }
    const caveIds = inCaves.map(c => c.id);
    if (caveIds.length) await client.query('DELETE FROM caves WHERE id <> ALL($1)', [caveIds]);
    else                await client.query('DELETE FROM caves');

    for (const w of inWines) await upsertWine(client, w);
    const wineIds = inWines.map(w => w.id);
    if (wineIds.length) await client.query('DELETE FROM wines WHERE id <> ALL($1)', [wineIds]);
    else                await client.query('DELETE FROM wines');

    for (const j of inJournal) {
      await client.query(
        `INSERT INTO journal (id, entry) VALUES ($1,$2::jsonb)
         ON CONFLICT (id) DO UPDATE SET entry=EXCLUDED.entry`,
        [String(j.id), JSON.stringify(j)]
      );
    }
    const jIds = inJournal.map(j => String(j.id));
    if (jIds.length) await client.query('DELETE FROM journal WHERE id <> ALL($1)', [jIds]);
    else             await client.query('DELETE FROM journal');

    await client.query(
      `INSERT INTO app_meta (id, ncave, nwine, stats, updated_at)
       VALUES ('main',$1,$2,$3::jsonb,NOW())
       ON CONFLICT (id) DO UPDATE SET ncave=EXCLUDED.ncave, nwine=EXCLUDED.nwine, stats=EXCLUDED.stats, updated_at=NOW()`,
      [data.nCave ?? 1, data.nWine ?? 1, JSON.stringify(data.statsAnnuelles || {})]
    );

    await client.query('COMMIT');
    console.log(`[DB] saveData(full,no-truncate): ${Date.now() - t0}ms`);
    res.json({ ok: true, updated_at: new Date().toISOString() });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('saveData error:', e);
    res.status(500).json({ error: 'Erreur sauvegarde données' });
  } finally {
    client.release();
  }
});

// PATCH /api/data → updates ciblés (photo préservée si absente du payload)
app.patch('/api/data', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const { meta, wines, deletedWineIds, caves, deletedCaveIds, journal } = req.body || {};
  const t0 = Date.now();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (Array.isArray(wines) && wines.length) {
      // Distinguer ajout vs modification : quels ids existent déjà ?
      const existing = new Set(
        (await client.query('SELECT id FROM wines WHERE id = ANY($1)', [wines.map(w=>w.id)])).rows.map(r=>r.id)
      );
      for (const w of wines) {
        await upsertWine(client, w);
        await logActivity(client, req.user.email, existing.has(w.id)?'edit':'add', w.id, wineLabel(w));
      }
    }
    if (Array.isArray(deletedWineIds) && deletedWineIds.length) {
      // Récupérer les noms AVANT suppression pour un journal lisible
      const del = (await client.query('SELECT id, data FROM wines WHERE id = ANY($1)', [deletedWineIds])).rows;
      for (const r of del) {
        const nom = (r.data && r.data.nom) || '(sans nom)';
        const mil = (r.data && r.data.millesime) ? ' '+r.data.millesime : '';
        await logActivity(client, req.user.email, 'remove', r.id, nom+mil);
      }
      await client.query('DELETE FROM wines WHERE id = ANY($1)', [deletedWineIds]);
    }

    if (Array.isArray(caves) && caves.length) {
      const existingC = new Set(
        (await client.query('SELECT id FROM caves WHERE id = ANY($1)', [caves.map(c=>c.id)])).rows.map(r=>r.id)
      );
      for (const c of caves) {
        await client.query(
          `INSERT INTO caves (id, data, updated_at) VALUES ($1,$2::jsonb,NOW())
           ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()`,
          [c.id, JSON.stringify(c)]
        );
        await logActivity(client, req.user.email, existingC.has(c.id)?'cave_edit':'cave_add', c.id, c.name||('Cave '+c.id));
      }
    }
    if (Array.isArray(deletedCaveIds) && deletedCaveIds.length) {
      const delc = (await client.query('SELECT id, data FROM caves WHERE id = ANY($1)', [deletedCaveIds])).rows;
      for (const r of delc) await logActivity(client, req.user.email, 'cave_remove', r.id, (r.data&&r.data.name)||('Cave '+r.id));
      await client.query('DELETE FROM caves WHERE id = ANY($1)', [deletedCaveIds]);
    }

    if (Array.isArray(journal) && journal.length) {
      for (const j of journal) {
        await client.query(
          `INSERT INTO journal (id, entry) VALUES ($1,$2::jsonb)
           ON CONFLICT (id) DO UPDATE SET entry=EXCLUDED.entry`,
          [String(j.id), JSON.stringify(j)]
        );
      }
    }

    if (meta) {
      const { rows } = await client.query("SELECT ncave, nwine, stats FROM app_meta WHERE id='main'");
      const cur = rows[0] || { ncave: 1, nwine: 1, stats: {} };
      const nCave = meta.nCave !== undefined ? meta.nCave : cur.ncave;
      const nWine = meta.nWine !== undefined ? meta.nWine : cur.nwine;
      const stats = cur.stats || {};
      if (meta.statsAnnuelles && typeof meta.statsAnnuelles === 'object') {
        for (const [yr, months] of Object.entries(meta.statsAnnuelles)) {
          stats[yr] = stats[yr] || {};
          for (const [mo, d] of Object.entries(months)) {
            const c = stats[yr][mo] || { e: 0, s: 0 };
            stats[yr][mo] = { e: Math.max(c.e || 0, d.e || 0), s: Math.max(c.s || 0, d.s || 0) };
          }
        }
      }
      await client.query(
        `INSERT INTO app_meta (id, ncave, nwine, stats, updated_at)
         VALUES ('main',$1,$2,$3::jsonb,NOW())
         ON CONFLICT (id) DO UPDATE SET ncave=EXCLUDED.ncave, nwine=EXCLUDED.nwine, stats=EXCLUDED.stats, updated_at=NOW()`,
        [nCave, nWine, JSON.stringify(stats)]
      );
    }

    await client.query('COMMIT');
    console.log(`[DB] patchData: ${Date.now()-t0}ms (w:${wines?.length||0} dw:${deletedWineIds?.length||0} c:${caves?.length||0} j:${journal?.length||0})`);
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('patchData error:', e);
    res.status(500).json({ error: 'Erreur patch données' });
  } finally {
    client.release();
  }
});

// POST /api/admin/api-key (inchangé)
app.post('/api/admin/api-key', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Réservé à l\'admin' });
  const { api_key } = req.body || {};
  await pool.query('UPDATE users SET api_key = $1 WHERE id = $2', [api_key || null, req.user.sub]);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════
// PROXY IA (inchangé)
// ═══════════════════════════════════════════════════════════════
app.post('/api/ai', requireAuth, async (req, res) => {
  const { messages, system, maxTokens = 800 } = req.body || {};
  if (!messages?.length) return res.status(400).json({ error: 'messages requis' });
  let anthropicKey = process.env.ANTHROPIC_API_KEY || '';
  if (!anthropicKey) {
    const { rows } = await pool.query(`SELECT u.api_key FROM users u WHERE u.role='admin' AND u.api_key IS NOT NULL LIMIT 1`);
    anthropicKey = rows[0]?.api_key || '';
  }
  if (!anthropicKey) return res.status(503).json({ error: 'Clé API Anthropic non configurée' });
  try {
    const body = { model: 'claude-opus-4-5', max_tokens: maxTokens, temperature: 0, messages, ...(system ? { system } : {}) };
    const t0 = Date.now();
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': anthropicKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify(body),
    });
    console.log(`[AI] proxy: ${Date.now() - t0}ms, status=${r.status}`);
    if (!r.ok) { const err = await r.text(); return res.status(r.status).json({ error: `Anthropic error: ${err}` }); }
    const json = await r.json();
    res.json({ content: json.content?.[0]?.text || '' });
  } catch (e) {
    console.error('ai proxy error:', e);
    res.status(500).json({ error: 'Erreur proxy IA' });
  }
});

// ── Démarrage ─────────────────────────────────────────────────
pool.connect()
  .then(c => { c.release(); console.log('✅ Connecté à AIVEN PostgreSQL'); app.listen(PORT, () => console.log(`🍷 CAVAVIN backend v4 (activité) démarré sur le port ${PORT}`)); })
  .catch(e => { console.error('❌ Impossible de se connecter à la base :', e.message); process.exit(1); });

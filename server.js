// ═══════════════════════════════════════════════════════════════
// CAVAVIN — Backend Node.js pour AIVEN PostgreSQL
// v2 : couche données relationnelle (caves / wines / journal / app_meta)
//      Même contrat d'API que la v1 → le front (index.html) ne change pas.
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
// HELPERS de mapping table <-> objet attendu par le front
// ═══════════════════════════════════════════════════════════════
// Vin : la photo vit dans sa colonne ; le reste dans data.
function rowToWine(row)  { return { ...row.data, id: row.id, caveId: row.cave_id, photo: row.photo ?? null }; }
function wineToRow(w)    { const { photo, ...rest } = w; return { id: w.id, cave_id: w.caveId ?? null, photo: photo ?? null, data: rest }; }
function rowToCave(row)  { return { ...row.data, id: row.id }; }

// ── Health check ──────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ═══════════════════════════════════════════════════════════════
// AUTH  (inchangé par rapport à la v1)
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
// DONNÉES — v2 relationnelle
// ═══════════════════════════════════════════════════════════════

// GET /api/data → recompose l'objet { data:{caves,wines,journal,nCave,nWine,statsAnnuelles}, api_key }
app.get('/api/data', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const t0 = Date.now();
  try {
    const [caves, wines, journal, meta] = await Promise.all([
      pool.query('SELECT id, data FROM caves ORDER BY id'),
      pool.query('SELECT id, cave_id, photo, data FROM wines ORDER BY id'),
      pool.query('SELECT entry FROM journal ORDER BY created_at, id'),
      pool.query("SELECT ncave, nwine, stats FROM app_meta WHERE id='main'"),
    ]);
    const m = meta.rows[0] || { ncave: 1, nwine: 1, stats: {} };
    const data = {
      caves:   caves.rows.map(rowToCave),
      wines:   wines.rows.map(rowToWine),
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
    console.log(`[DB] loadData: ${Date.now() - t0}ms (${data.wines.length}w ${data.caves.length}c)`);
    res.json({ data, api_key });
  } catch (e) {
    console.error('getData error:', e);
    res.status(500).json({ error: 'Erreur lecture données' });
  }
});

// POST /api/data → remplacement complet (premier sync / restauration), en transaction.
app.post('/api/data', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const { data } = req.body || {};
  if (!data) return res.status(400).json({ error: 'data manquant' });

  const incWines = Array.isArray(data.wines) ? data.wines.length : 0;
  const incCaves = Array.isArray(data.caves) ? data.caves.length : 0;

  const client = await pool.connect();
  try {
    // 🛡️ GARDE-FOU anti-écrasement (incident du 03/06/2026 : base vidée par un device au cache vide).
    if (incWines === 0 && incCaves === 0) {
      const { rows } = await client.query('SELECT (SELECT count(*) FROM wines) w, (SELECT count(*) FROM caves) c');
      if (Number(rows[0].w) > 0 || Number(rows[0].c) > 0) {
        console.warn(`[GARDE-FOU] POST vide REFUSÉ : payload 0 vin/0 cave alors que la base contient ${rows[0].w} vins / ${rows[0].c} caves.`);
        return res.status(409).json({ error: 'Sauvegarde vide refusée : la base contient déjà des données. Rechargez l’application avant de sauvegarder.' });
      }
    }

    const t0 = Date.now();
    await client.query('BEGIN');
    await client.query('TRUNCATE journal, wines, caves CASCADE');

    for (const c of (data.caves || [])) {
      await client.query('INSERT INTO caves (id, data) VALUES ($1, $2::jsonb)', [c.id, JSON.stringify(c)]);
    }
    for (const w of (data.wines || [])) {
      const r = wineToRow(w);
      await client.query('INSERT INTO wines (id, cave_id, photo, data) VALUES ($1,$2,$3,$4::jsonb)',
        [r.id, r.cave_id, r.photo, JSON.stringify(r.data)]);
    }
    for (const j of (data.journal || [])) {
      await client.query('INSERT INTO journal (id, entry) VALUES ($1,$2::jsonb) ON CONFLICT (id) DO UPDATE SET entry=EXCLUDED.entry',
        [String(j.id), JSON.stringify(j)]);
    }
    await client.query(
      `INSERT INTO app_meta (id, ncave, nwine, stats, updated_at)
       VALUES ('main',$1,$2,$3::jsonb,NOW())
       ON CONFLICT (id) DO UPDATE SET ncave=EXCLUDED.ncave, nwine=EXCLUDED.nwine, stats=EXCLUDED.stats, updated_at=NOW()`,
      [data.nCave ?? 1, data.nWine ?? 1, JSON.stringify(data.statsAnnuelles || {})]
    );
    await client.query('COMMIT');
    console.log(`[DB] saveData(full): ${Date.now() - t0}ms`);
    res.json({ ok: true, updated_at: new Date().toISOString() });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('saveData error:', e);
    res.status(500).json({ error: 'Erreur sauvegarde données' });
  } finally {
    client.release();
  }
});

// PATCH /api/data → mises à jour CIBLÉES (le cœur du gain anti-bloat)
app.patch('/api/data', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const { meta, wines, deletedWineIds, caves, deletedCaveIds, journal } = req.body || {};
  const t0 = Date.now();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Vins : upsert ciblé (une ligne chacun, la photo n'est réécrite que si elle change côté vin)
    if (Array.isArray(wines) && wines.length) {
      for (const w of wines) {
        const r = wineToRow(w);
        await client.query(
          `INSERT INTO wines (id, cave_id, photo, data, updated_at)
           VALUES ($1,$2,$3,$4::jsonb,NOW())
           ON CONFLICT (id) DO UPDATE
             SET cave_id=EXCLUDED.cave_id, photo=EXCLUDED.photo, data=EXCLUDED.data, updated_at=NOW()`,
          [r.id, r.cave_id, r.photo, JSON.stringify(r.data)]
        );
      }
    }
    if (Array.isArray(deletedWineIds) && deletedWineIds.length)
      await client.query('DELETE FROM wines WHERE id = ANY($1)', [deletedWineIds]);

    // Caves
    if (Array.isArray(caves) && caves.length) {
      for (const c of caves) {
        await client.query(
          `INSERT INTO caves (id, data, updated_at) VALUES ($1,$2::jsonb,NOW())
           ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()`,
          [c.id, JSON.stringify(c)]
        );
      }
    }
    if (Array.isArray(deletedCaveIds) && deletedCaveIds.length)
      await client.query('DELETE FROM caves WHERE id = ANY($1)', [deletedCaveIds]);

    // Journal : upsert par id (édition d'un motif/commentaire ou nouvelle entrée)
    if (Array.isArray(journal) && journal.length) {
      for (const j of journal) {
        await client.query(
          `INSERT INTO journal (id, entry) VALUES ($1,$2::jsonb)
           ON CONFLICT (id) DO UPDATE SET entry=EXCLUDED.entry`,
          [String(j.id), JSON.stringify(j)]
        );
      }
    }

    // Meta : compteurs + merge statsAnnuelles (max par mois, comme la v1)
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
  .then(c => { c.release(); console.log('✅ Connecté à AIVEN PostgreSQL'); app.listen(PORT, () => console.log(`🍷 CAVAVIN backend v2 démarré sur le port ${PORT}`)); })
  .catch(e => { console.error('❌ Impossible de se connecter à la base :', e.message); process.exit(1); });
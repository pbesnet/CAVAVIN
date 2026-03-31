// ═══════════════════════════════════════════════════════════════
// CAVAVIN — Backend Node.js pour AIVEN PostgreSQL
// Remplace Supabase : auth + données + proxy IA
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
const JWT_TTL    = '7d';   // durée de vie des tokens
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

// Pool PostgreSQL AIVEN
const pool = new Pool({
  connectionString: process.env.AIVEN_PG_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
});

// ── Middlewares ───────────────────────────────────────────────
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));

// FORCE la limite à 50mb pour le JSON (données + photos)
app.use(express.json({ limit: '50mb' }));

// Ajoute aussi celle-ci pour gérer les formulaires volumineux
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Middleware auth : vérifie le JWT dans Authorization: Bearer <token>
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

// ── Health check ──────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// ═══════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════

// POST /api/auth/login  →  { token, user: { id, email, role } }
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'Email et mot de passe requis' });

  try {
    const { rows } = await pool.query(
      'SELECT id, email, password_hash, role, api_key, demo_only FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Identifiants incorrects' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok)  return res.status(401).json({ error: 'Identifiants incorrects' });

    // Mettre à jour last_login
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    const demoOnly = user.demo_only === true || user.demo_only === 't' || user.demo_only === 'true';
    const payload = { sub: user.id, email: user.email, role: user.role, demo_only: demoOnly };
    const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_TTL });

    res.json({
      token,
      user: { id: user.id, email: user.email, role: user.role, demo_only: demoOnly },
      api_key: user.api_key || null,
    });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/auth/session  →  { user } ou 401
app.get('/api/auth/session', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.sub, email: req.user.email, role: req.user.role, demo_only: req.user.demo_only || false } });
});

// POST /api/auth/logout  (côté serveur, rien à faire — le client supprime le token)
app.post('/api/auth/logout', requireAuth, (req, res) => {
  res.json({ ok: true });
});

// POST /api/auth/reset  →  email de réinitialisation
// (simple : retourne 200 sans envoyer d'email si pas configuré)
app.post('/api/auth/reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email requis' });

  // Vérifie que l'email existe (sans révéler si oui ou non)
  const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
  if (!rows.length) {
    // On répond quand même 200 pour ne pas révéler les comptes
    return res.json({ ok: true, message: 'Si ce compte existe, un email a été envoyé' });
  }

  // TODO: intégrer un service d'email (SendGrid, Mailgun, Resend…)
  // Pour l'instant, l'admin peut changer les mots de passe via create-admin.js
  res.json({ ok: true, message: 'Contacte l\'administrateur pour réinitialiser ton mot de passe' });
});

// ═══════════════════════════════════════════════════════════════
// DONNÉES (shared_data)
// ═══════════════════════════════════════════════════════════════

// GET /api/data  →  { data, api_key? }
app.get('/api/data', requireAuth, async (req, res) => {
  // Bloquer les comptes demo_only : ils n'ont pas accès aux données de production
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const t0 = Date.now();
  try {
    const { rows } = await pool.query('SELECT data FROM shared_data WHERE id = $1', ['main']);
    const data = rows[0]?.data || {};
    console.log(`[DB] loadData: ${Date.now() - t0}ms`);

    // Récupérer la clé API de l'admin si c'est un admin
    let api_key = null;
    if (req.user.role === 'admin') {
      const { rows: urows } = await pool.query('SELECT api_key FROM users WHERE id=$1', [req.user.sub]);
      api_key = urows[0]?.api_key || null;
    }

    res.json({ data, api_key });
  } catch (e) {
    console.error('getData error:', e);
    res.status(500).json({ error: 'Erreur lecture données' });
  }
});

// POST /api/data  →  { ok, updated_at }
app.post('/api/data', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const { data } = req.body || {};
  if (!data) return res.status(400).json({ error: 'data manquant' });

  const t0 = Date.now();
  try {
    const { rows } = await pool.query(
      `INSERT INTO shared_data (id, data, updated_at)
       VALUES ('main', $1::jsonb, NOW())
       ON CONFLICT (id)
       DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
       RETURNING updated_at`,
      [JSON.stringify(data)]
    );
    console.log(`[DB] saveData: ${Date.now() - t0}ms`);
    res.json({ ok: true, updated_at: rows[0].updated_at });
  } catch (e) {
    console.error('saveData error:', e);
    res.status(500).json({ error: 'Erreur sauvegarde données' });
  }
});

// PATCH /api/data — Mise à jour incrémentale (delta sync)
app.patch('/api/data', requireAuth, async (req, res) => {
  if (req.user.demo_only) return res.status(403).json({ error: 'Accès réservé au mode démo' });
  const { meta, wines, deletedWineIds, caves, deletedCaveIds, journal } = req.body || {};
  const t0 = Date.now();
  try {
    const { rows } = await pool.query('SELECT data FROM shared_data WHERE id=$1', ['main']);
    const current = rows[0]?.data || { caves: [], wines: [], journal: [], nCave: 1, nWine: 1 };
    current.wines   = current.wines   || [];
    current.caves   = current.caves   || [];
    current.journal = current.journal || [];

    if (Array.isArray(wines) && wines.length) {
      wines.forEach(w => {
        const idx = current.wines.findIndex(x => x.id === w.id);
        if (idx >= 0) current.wines[idx] = w; else current.wines.push(w);
      });
    }
    if (Array.isArray(deletedWineIds) && deletedWineIds.length)
      current.wines = current.wines.filter(w => !deletedWineIds.includes(w.id));

    if (Array.isArray(caves) && caves.length) {
      caves.forEach(c => {
        const idx = current.caves.findIndex(x => x.id === c.id);
        if (idx >= 0) current.caves[idx] = c; else current.caves.push(c);
      });
    }
    if (Array.isArray(deletedCaveIds) && deletedCaveIds.length)
      current.caves = current.caves.filter(c => !deletedCaveIds.includes(c.id));

    if (Array.isArray(journal) && journal.length) {
      // Déduplication par ID : évite les entrées en double si PATCH envoyé deux fois
      const existingIds = new Set((current.journal || []).map(j => String(j.id)));
      const newEntries = journal.filter(j => !existingIds.has(String(j.id)));
      current.journal = [...(current.journal || []), ...newEntries];
    }

    if (meta) {
      if (meta.nCave !== undefined) current.nCave = meta.nCave;
      if (meta.nWine !== undefined) current.nWine = meta.nWine;
      // Merge statsAnnuelles : prendre le max pour chaque mois (évite perte de données)
      if (meta.statsAnnuelles && typeof meta.statsAnnuelles === 'object') {
        current.statsAnnuelles = current.statsAnnuelles || {};
        for (const [yr, months] of Object.entries(meta.statsAnnuelles)) {
          current.statsAnnuelles[yr] = current.statsAnnuelles[yr] || {};
          for (const [mo, data] of Object.entries(months)) {
            const cur = current.statsAnnuelles[yr][mo] || { e: 0, s: 0 };
            current.statsAnnuelles[yr][mo] = {
              e: Math.max(cur.e || 0, data.e || 0),
              s: Math.max(cur.s || 0, data.s || 0)
            };
          }
        }
      }
    }

    await pool.query(
      'UPDATE shared_data SET data=$1::jsonb, updated_at=NOW() WHERE id=$2',
      [JSON.stringify(current), 'main']
    );
    console.log(`[DB] patchData: ${Date.now()-t0}ms (w:${wines?.length||0} dw:${deletedWineIds?.length||0} c:${caves?.length||0} j:${journal?.length||0})`);
    res.json({ ok: true });
  } catch (e) {
    console.error('patchData error:', e);
    res.status(500).json({ error: 'Erreur patch données' });
  }
});

// POST /api/admin/api-key  (admin seulement) — Sauvegarder la clé Anthropic
app.post('/api/admin/api-key', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Réservé à l\'admin' });
  const { api_key } = req.body || {};
  await pool.query('UPDATE users SET api_key = $1 WHERE id = $2', [api_key || null, req.user.sub]);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════
// PROXY IA (Anthropic Claude)
// ═══════════════════════════════════════════════════════════════

// POST /api/ai  →  { content: string }
app.post('/api/ai', requireAuth, async (req, res) => {
  const { messages, system, maxTokens = 800 } = req.body || {};
  if (!messages?.length) return res.status(400).json({ error: 'messages requis' });

  // Récupérer la clé Anthropic (stockée chez l'admin)
  let anthropicKey = process.env.ANTHROPIC_API_KEY || '';
  if (!anthropicKey) {
    const { rows } = await pool.query(
      `SELECT u.api_key FROM users u WHERE u.role = 'admin' AND u.api_key IS NOT NULL LIMIT 1`
    );
    anthropicKey = rows[0]?.api_key || '';
  }
  if (!anthropicKey)
    return res.status(503).json({ error: 'Clé API Anthropic non configurée' });

  try {
    const body = {
      model: 'claude-opus-4-5',
      max_tokens: maxTokens,
      temperature: 0,   // déterministe — évite les variations entre deux appels identiques
      messages,
      ...(system ? { system } : {}),
    };
    const t0 = Date.now();
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': anthropicKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
    });
    console.log(`[AI] proxy: ${Date.now() - t0}ms, status=${r.status}`);
    if (!r.ok) {
      const err = await r.text();
      return res.status(r.status).json({ error: `Anthropic error: ${err}` });
    }
    const json = await r.json();
    const content = json.content?.[0]?.text || '';
    res.json({ content });
  } catch (e) {
    console.error('ai proxy error:', e);
    res.status(500).json({ error: 'Erreur proxy IA' });
  }
});

// ── Démarrage ─────────────────────────────────────────────────
pool.connect()
  .then(() => {
    console.log('✅ Connecté à AIVEN PostgreSQL');
    app.listen(PORT, () => console.log(`🍷 CAVAVIN backend démarré sur le port ${PORT}`));
  })
  .catch(e => {
    console.error('❌ Impossible de se connecter à la base :', e.message);
    process.exit(1);
  });

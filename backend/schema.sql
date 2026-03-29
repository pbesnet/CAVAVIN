-- ═══════════════════════════════════════════════════════════════
-- CAVAVIN — Schéma PostgreSQL pour AIVEN
-- Exécuter via PG Studio (AIVEN Console) ou psql
-- ═══════════════════════════════════════════════════════════════

-- ── Nettoyage (ré-exécution sûre) ────────────────────────────
DROP TABLE IF EXISTS shared_data;
DROP TABLE IF EXISTS users;

-- ── Table utilisateurs ────────────────────────────────────────
CREATE TABLE users (
  id           SERIAL PRIMARY KEY,
  email        TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'user',   -- 'admin' | 'user'
  api_key      TEXT,                            -- Clé Anthropic (admin uniquement)
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login   TIMESTAMPTZ
);

-- ── Table données partagées (une ligne 'main' pour toute la cave) ──
CREATE TABLE shared_data (
  id           TEXT PRIMARY KEY DEFAULT 'main',
  data         JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Index utile ───────────────────────────────────────────────
CREATE INDEX idx_users_email ON users(email);

-- ── Ligne de données initiale (vide) ─────────────────────────
INSERT INTO shared_data (id, data)
VALUES ('main', '{"caves":[],"wines":[],"journal":[],"nCave":0,"nWine":0,"statsAnnuelles":{}}'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ══════════════════════════════════════════════════════════════
-- CRÉER LE COMPTE ADMIN
-- Remplace 'MON_EMAIL' et 'MON_MOT_DE_PASSE_HASHÉ'
-- Le hash est généré par le script create-admin.js (voir README)
-- ══════════════════════════════════════════════════════════════
-- INSERT INTO users (email, password_hash, role)
-- VALUES ('pbesnet@yahoo.fr', '$2b$12$HASH_ICI', 'admin');

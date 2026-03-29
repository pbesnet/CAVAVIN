#!/usr/bin/env node
/**
 * setup-db.js — Initialise le schéma AIVEN PostgreSQL
 * Usage: AIVEN_PG_URL="postgres://avnadmin:MOT_DE_PASSE@..." node setup-db.js
 */
const { Pool } = require('pg');

const url = process.env.AIVEN_PG_URL;
if (!url) {
  console.error('❌ Variable AIVEN_PG_URL manquante');
  console.error('   Usage: AIVEN_PG_URL="postgres://avnadmin:PASS@host:port/defaultdb?sslmode=require" node setup-db.js');
  process.exit(1);
}

const pool = new Pool({ connectionString: url, ssl: { rejectUnauthorized: false } });

const statements = [
  {
    label: 'CREATE TABLE users',
    sql: `CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',
  api_key       TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login    TIMESTAMPTZ
)`
  },
  {
    label: 'CREATE TABLE shared_data',
    sql: `CREATE TABLE IF NOT EXISTS shared_data (
  id         TEXT PRIMARY KEY DEFAULT 'main',
  data       JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`
  },
  {
    label: 'CREATE INDEX idx_users_email',
    sql: `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`
  },
  {
    label: 'INSERT shared_data ligne initiale',
    sql: `INSERT INTO shared_data (id, data)
VALUES ('main', '{"caves":[],"wines":[],"journal":[],"nCave":1,"nWine":1}'::jsonb)
ON CONFLICT DO NOTHING`
  }
];

async function run() {
  const client = await pool.connect();
  try {
    for (const { label, sql } of statements) {
      try {
        await client.query(sql);
        console.log(`✅ ${label}`);
      } catch (e) {
        console.error(`❌ ${label}: ${e.message}`);
      }
    }

    // Vérification
    const res = await client.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name"
    );
    console.log('\nTables créées :', res.rows.map(r => r.table_name).join(', '));
    console.log('\n✅ Base de données initialisée. Lance maintenant : node create-admin.js');
  } finally {
    client.release();
    await pool.end();
  }
}

run().catch(e => { console.error('Erreur fatale:', e.message); process.exit(1); });

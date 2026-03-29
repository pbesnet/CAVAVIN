// ═══════════════════════════════════════════════════════════════
// Script de migration : Supabase → AIVEN PostgreSQL
//
// Prérequis :
//   export SUPABASE_URL="https://jokxzcawdfhmcrnivbnh.supabase.co"
//   export SUPABASE_SERVICE_KEY="eyJ..."   ← clé service Supabase (pas anon)
//   export AIVEN_PG_URL="postgres://avnadmin:PASS@pg-eed0e02-pbesnet-4cb8.e.aivencloud.com:28140/defaultdb?sslmode=require"
//
// Usage : node migrate-from-supabase.js
// ═══════════════════════════════════════════════════════════════
'use strict';

const { Pool } = require('pg');
const fetch    = require('node-fetch');

const SB_URL  = process.env.SUPABASE_URL;
const SB_KEY  = process.env.SUPABASE_SERVICE_KEY;  // service_role key (pas anon)
const PG_URL  = process.env.AIVEN_PG_URL;

if (!SB_URL || !SB_KEY || !PG_URL) {
  console.error('❌ Variables d\'environnement manquantes.');
  console.error('   SUPABASE_URL, SUPABASE_SERVICE_KEY, AIVEN_PG_URL');
  process.exit(1);
}

const pool = new Pool({ connectionString: PG_URL, ssl: { rejectUnauthorized: false } });

async function sbGet(path) {
  const r = await fetch(`${SB_URL}/rest/v1/${path}`, {
    headers: {
      'apikey': SB_KEY,
      'Authorization': `Bearer ${SB_KEY}`,
      'Content-Type': 'application/json',
    }
  });
  if (!r.ok) throw new Error(`Supabase ${r.status}: ${await r.text()}`);
  return r.json();
}

async function main() {
  console.log('\n🍷 CAVAVIN — Migration Supabase → AIVEN\n');

  // ── 1. Lire les données depuis Supabase ──────────────────────
  console.log('📥 Lecture des données Supabase…');
  const rows = await sbGet('shared_data?select=id,data,api_key&id=eq.main');
  if (!rows.length) {
    console.log('⚠️  Aucune donnée trouvée dans Supabase (table shared_data, id=main)');
    process.exit(0);
  }
  const { data, api_key } = rows[0];
  console.log(`   Caves : ${data.caves?.length || 0}`);
  console.log(`   Vins  : ${data.wines?.length || 0}`);
  console.log(`   Journal : ${data.journal?.length || 0}`);

  // ── 2. Insérer dans AIVEN ─────────────────────────────────────
  console.log('\n📤 Insertion dans AIVEN PostgreSQL…');
  await pool.query(
    `INSERT INTO shared_data (id, data, updated_at)
     VALUES ('main', $1::jsonb, NOW())
     ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
    [JSON.stringify(data)]
  );

  // Stocker la clé Anthropic dans le compte admin si elle existe
  if (api_key) {
    console.log('   Clé Anthropic trouvée — mise à jour du compte admin…');
    const { rowCount } = await pool.query(
      `UPDATE users SET api_key = $1 WHERE role = 'admin' RETURNING email`,
      [api_key]
    );
    if (rowCount > 0) console.log('   ✅ Clé Anthropic migrée vers le compte admin');
    else console.log('   ⚠️  Aucun compte admin trouvé — crée-le d\'abord avec create-admin.js');
  }

  // ── 3. Vérification ──────────────────────────────────────────
  const { rows: check } = await pool.query('SELECT data FROM shared_data WHERE id=$1', ['main']);
  const d = check[0]?.data;
  console.log('\n✅ Migration terminée !');
  console.log(`   Caves : ${d?.caves?.length || 0}`);
  console.log(`   Vins  : ${d?.wines?.length || 0}`);
  console.log(`   Journal : ${d?.journal?.length || 0}`);

  await pool.end();
}

main().catch(e => { console.error('❌ Erreur :', e.message); process.exit(1); });

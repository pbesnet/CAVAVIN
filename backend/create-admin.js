// ═══════════════════════════════════════════════════════════════
// Script utilitaire : crée ou modifie un compte admin dans AIVEN
// Usage : node create-admin.js
// ═══════════════════════════════════════════════════════════════
'use strict';

const { Pool } = require('pg');
const bcrypt   = require('bcrypt');
const readline = require('readline');

const pool = new Pool({
  connectionString: process.env.AIVEN_PG_URL,
  ssl: { rejectUnauthorized: false },
});

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = q => new Promise(r => rl.question(q, r));

async function main() {
  console.log('\n🍷 CAVAVIN — Création/modification de compte admin\n');

  const email    = await ask('Email : ');
  const password = await ask('Mot de passe : ');
  const role     = await ask('Rôle (admin/user) [admin] : ') || 'admin';

  const hash = await bcrypt.hash(password, 12);

  const { rows } = await pool.query(`
    INSERT INTO users (email, password_hash, role)
    VALUES ($1, $2, $3)
    ON CONFLICT (email)
    DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
    RETURNING id, email, role
  `, [email.toLowerCase().trim(), hash, role]);

  console.log('\n✅ Compte créé/mis à jour :', rows[0]);
  rl.close();
  await pool.end();
}

main().catch(e => { console.error('❌', e.message); process.exit(1); });

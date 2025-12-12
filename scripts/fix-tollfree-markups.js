#!/usr/bin/env node

// One-off script to correct mislabelled/mispriced toll-free DID monthly fee rows
// in billing_history. It looks for rows like:
//   "Number monthly service fee - Local <DID> (period ending YYYY-MM-DD)"
// where <DID> is a US/CA toll-free prefix (800/833/844/855/866/877/888), and
// updates the amount to the toll-free monthly markup and the label to
// "Toll-Free".

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

// Load environment similar to server.js (.env.local preferred, else .env)
(function loadEnv() {
  const root = path.join(__dirname, '..');
  const envLocal = path.join(root, '.env.local');
  if (fs.existsSync(envLocal)) {
    require('dotenv').config({ path: envLocal });
    console.log('Loaded environment from .env.local');
  } else {
    require('dotenv').config({ path: path.join(root, '.env') });
  }
})();

async function main() {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) {
    throw new Error('DATABASE_URL is not set; cannot connect to MySQL');
  }

  const u = new URL(dsn);
  const dbName = u.pathname.replace(/^\//, '');

  // Optional SSL, mirrored from server.js logic
  const sslMode = (u.searchParams.get('ssl-mode') || u.searchParams.get('sslmode') || '').toUpperCase();
  const caPath = process.env.DATABASE_CA_CERT;
  let sslOptions;
  if (caPath && fs.existsSync(caPath)) {
    sslOptions = { ca: fs.readFileSync(caPath, 'utf8'), rejectUnauthorized: true };
  } else if (sslMode === 'REQUIRED') {
    // Encrypted but without full verification (same compromise as server.js)
    sslOptions = { rejectUnauthorized: false };
  }

  const pool = await mysql.createPool({
    host: u.hostname,
    port: Number(u.port) || 3306,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: dbName,
    ssl: sslOptions,
    connectionLimit: 5,
    waitForConnections: true,
    queueLimit: 0
  });

  const tollfreeMarkup = parseFloat(process.env.DID_TOLLFREE_MONTHLY_MARKUP || '25.20') || 25.20;
  console.log('Using toll-free monthly markup:', tollfreeMarkup.toFixed(2));

  // Find candidate rows that look like Local monthly DID fees
  const [rows] = await pool.query(
    "SELECT id, user_id, amount, description, created_at FROM billing_history WHERE description LIKE 'Number monthly service fee - Local %' ORDER BY created_at DESC"
  );

  if (!rows.length) {
    console.log('No Local monthly DID fee rows found in billing_history. Nothing to do.');
    await pool.end();
    return;
  }

  const tollfreeNpas = new Set(['800', '833', '844', '855', '866', '877', '888']);
  let updated = 0;

  for (const row of rows) {
    const desc = row.description || '';

    // Extract DID number from the description
    // Expected pattern: "Number monthly service fee - Local <digits> (period ending YYYY-MM-DD)"
    const m = desc.match(/Number monthly service fee - Local\s+(\d+)\s+\(period ending\s+(\d{4}-\d{2}-\d{2})\)/);
    if (!m) continue;

    const did = m[1];
    const digits = did.replace(/\D/g, '');
    if (!digits) continue;

    // Normalize to last 11 digits (strip possible country prefix), then derive NPA
    const d11 = digits.length > 11 ? digits.slice(-11) : digits;
    const npa = d11.startsWith('1') ? d11.slice(1, 4) : d11.slice(0, 3);

    // Only fix rows where the DID is clearly toll-free by NPA
    if (!tollfreeNpas.has(npa)) continue;

    const currentAbs = Math.abs(Number(row.amount));
    if (!currentAbs) continue;

    // If already at or above toll-free markup, skip
    if (Math.abs(currentAbs - tollfreeMarkup) < 0.005 || currentAbs > tollfreeMarkup + 0.005) {
      continue;
    }

    console.log(`Fixing row id=${row.id}, user_id=${row.user_id}, did=${did}, oldAmount=${row.amount}, created_at=${row.created_at.toISOString()}`);

    const newAmount = -tollfreeMarkup;
    const newDesc = desc.replace('Number monthly service fee - Local', 'Number monthly service fee - Toll-Free');

    await pool.execute(
      'UPDATE billing_history SET amount = ?, description = ? WHERE id = ?',
      [newAmount, newDesc, row.id]
    );

    console.log(`  -> new amount=${newAmount.toFixed(2)}, new description="${newDesc}"`);
    updated++;
  }

  if (!updated) {
    console.log('No mislabelled toll-free rows were updated.');
  } else {
    console.log(`Updated ${updated} billing_history row(s).`);
  }

  await pool.end();
}

main().catch(err => {
  console.error('fix-tollfree-markups failed:', err);
  process.exit(1);
});

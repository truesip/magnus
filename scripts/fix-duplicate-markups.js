// Detect and mark duplicate DID monthly service fee rows in billing_history.
// This is a one-time cleanup tool to fix historical duplicates caused by
// markup cycles being billed more than once.
//
// What it does:
//   - Looks for rows where description starts with "Number monthly service fee -"
//     and amount is negative, grouped by (user_id, amount, description).
//   - For any group with more than one non-failed row, it keeps the earliest
//     row as the "real" charge and marks the rest as status='failed'.
//   - Prints a summary per user with how many duplicate rows were fixed and
//     the total overcharge amount that should be refunded in MagnusBilling.
//
// NOTE: This script ONLY updates the local portal database. You must apply
//       any corresponding credit adjustments in MagnusBilling separately.

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

// Load .env or .env.local like server.js does
(function loadEnv() {
  const envLocalPath = path.join(__dirname, '..', '.env.local');
  if (fs.existsSync(envLocalPath)) {
    require('dotenv').config({ path: envLocalPath });
    console.log('Loaded environment from .env.local');
  } else {
    require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
  }
})();

async function main() {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) {
    console.error('DATABASE_URL is not set in .env – cannot connect to MySQL.');
    process.exit(1);
  }

  const u = new URL(dsn);
  const dbName = u.pathname.replace(/^\//, '');

  // TLS options (match initDb() logic in server.js)
  const sslMode = (u.searchParams.get('ssl-mode') || u.searchParams.get('sslmode') || '').toUpperCase();
  const caPath = process.env.DATABASE_CA_CERT;
  let sslOptions;
  if (caPath && fs.existsSync(caPath)) {
    sslOptions = { ca: fs.readFileSync(caPath, 'utf8'), rejectUnauthorized: true };
  } else if (sslMode === 'REQUIRED') {
    // Encrypted, non-verified fallback (same as server.js)
    sslOptions = { rejectUnauthorized: false };
  }

  const connection = await mysql.createConnection({
    host: u.hostname,
    port: Number(u.port) || 3306,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: dbName,
    ssl: sslOptions,
  });

  console.log('Connected to MySQL database:', dbName);
  console.log('Scanning for duplicate DID monthly service fee rows...');

  try {
    // Find groups of potential duplicates: same user_id, amount, description,
    // more than one row, and at least two rows that are not already failed.
    const [groups] = await connection.execute(
      `SELECT user_id, amount, description, COUNT(*) AS cnt,
              SUM(CASE WHEN status != 'failed' THEN 1 ELSE 0 END) AS non_failed_cnt
         FROM billing_history
        WHERE description LIKE 'Number monthly service fee - %'
          AND amount < 0
        GROUP BY user_id, amount, description
       HAVING non_failed_cnt > 1`
    );

    if (!groups || groups.length === 0) {
      console.log('No duplicate DID monthly service fee rows found.');
      await connection.end();
      return;
    }

    console.log(`Found ${groups.length} group(s) with potential duplicates.`);

    const perUserRefund = new Map(); // user_id -> total refund (positive number)
    let totalDuplicateRows = 0;

    for (const g of groups) {
      const userId = g.user_id;
      const amount = Number(g.amount); // negative
      const description = g.description;

      const [rows] = await connection.execute(
        `SELECT id, status, created_at
           FROM billing_history
          WHERE user_id = ?
            AND amount = ?
            AND description = ?
            AND status != 'failed'
          ORDER BY created_at ASC, id ASC`,
        [userId, amount, description]
      );

      if (!rows || rows.length <= 1) {
        continue; // Nothing to fix for this group
      }

      const keepRow = rows[0];
      const duplicateRows = rows.slice(1);
      const duplicateIds = duplicateRows.map(r => r.id);

      if (duplicateIds.length === 0) continue;

      // Mark duplicates as failed
      const [updateRes] = await connection.execute(
        `UPDATE billing_history
            SET status = 'failed'
          WHERE id IN (${duplicateIds.map(() => '?').join(',')})`,
        duplicateIds
      );

      const changed = updateRes.affectedRows || 0;
      totalDuplicateRows += changed;

      // Track overcharge (amount is negative; refund is positive)
      const refund = Math.abs(amount) * changed;
      perUserRefund.set(userId, (perUserRefund.get(userId) || 0) + refund);

      console.log(
        `User ${userId}: kept row ${keepRow.id}, marked ${changed} duplicate row(s) as failed for description "${description}" (refund $${refund.toFixed(
          2
        )})`
      );
    }

    console.log('\nSummary:');
    console.log(`  Duplicate rows marked as failed: ${totalDuplicateRows}`);

    if (perUserRefund.size === 0) {
      console.log('  No monetary overcharges detected.');
    } else {
      console.log('  Suggested MagnusBilling credit adjustments:');
      for (const [userId, refund] of perUserRefund.entries()) {
        console.log(`    - User ${userId}: refund $${refund.toFixed(2)}`);
      }
      console.log('\nIMPORTANT: Apply these refunds manually in MagnusBilling; this script only');
      console.log('           updates the local billing_history table.');
    }

    await connection.end();
  } catch (e) {
    console.error('fix-duplicate-markups failed:', e.message || e);
    try { await connection.end(); } catch (_) {}
    process.exit(1);
  }
}

main().catch((e) => {
  console.error('Fatal error:', e.message || e);
  process.exit(1);
});

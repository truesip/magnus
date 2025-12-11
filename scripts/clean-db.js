// Clean local portal tables without touching MagnusBilling itself
// WARNING: This will DELETE local data (signups, sessions, billing history, etc.).

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
    ssl: sslOptions
  });

  console.log('Connected to MySQL database:', dbName);
  console.log('*** WARNING *** This will TRUNCATE local portal tables.');

  const tablesInOrder = [
    // Child tables first
    'did_purchase_receipts',
    'pending_orders',
    'nowpayments_payments',
    'square_payments',
    'user_did_cdrs',
    'user_did_markup_cycles',
    'user_did_markups',
    'user_dids',
    'user_trunks',
    // Main entities
    'billing_history',
    'email_verifications',
    'signup_users',
    'sessions'
  ];

  try {
    await connection.query('SET FOREIGN_KEY_CHECKS = 0');

    for (const table of tablesInOrder) {
      try {
        console.log('Truncating table:', table);
        await connection.query(`TRUNCATE TABLE \`${table}\``);
      } catch (err) {
        // Ignore missing tables, but log others
        if (err && err.code === 'ER_NO_SUCH_TABLE') {
          console.log(`Table ${table} does not exist, skipping.`);
        } else {
          console.warn(`Failed to truncate ${table}:`, err.message || err);
        }
      }
    }

    await connection.query('SET FOREIGN_KEY_CHECKS = 1');
    console.log('Database cleanup complete.');
  } catch (e) {
    console.error('Cleanup failed:', e.message || e);
    process.exitCode = 1;
  } finally {
    try { await connection.end(); } catch (_) {}
  }
}

main().catch((e) => {
  console.error('Fatal error:', e.message || e);
  process.exit(1);
});

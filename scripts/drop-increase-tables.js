#!/usr/bin/env node
'use strict';

// Lists and (optionally) drops legacy increase_* tables.
// Safe-by-default: it will only DROP when run with --yes (or --apply / -y).

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

function usage(exitCode = 0) {
  console.log('Usage:');
  console.log('  node scripts/drop-increase-tables.js            # list matching tables');
  console.log('  node scripts/drop-increase-tables.js --yes      # drop matching tables');
  console.log('');
  console.log('Flags:');
  console.log('  --yes, --apply, -y    Actually perform the DROP');
  process.exit(exitCode);
}

function quoteIdent(name) {
  // Backtick-escape identifier (defensive; names come from information_schema)
  return `\`${String(name).replace(/`/g, '``')}\``;
}

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has('--help') || args.has('-h')) usage(0);

  const apply = args.has('--yes') || args.has('--apply') || args.has('-y');

  const dsn = process.env.DATABASE_URL;
  if (!dsn) {
    console.error('DATABASE_URL is not set in .env – cannot connect to MySQL.');
    process.exit(1);
  }

  const u = new URL(dsn);
  const dbName = u.pathname.replace(/^\//, '');
  if (!dbName) {
    console.error('DATABASE_URL does not include a database name (expected /dbname in the URL path).');
    process.exit(1);
  }

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

  try {
    console.log('Connected to MySQL database:', dbName);

    const [rows] = await connection.execute(
      `SELECT TABLE_NAME
         FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = ?
          AND TABLE_TYPE = 'BASE TABLE'
          AND TABLE_NAME REGEXP '^increase_'
        ORDER BY TABLE_NAME ASC`,
      [dbName]
    );

    const tables = (rows || []).map((r) => r.TABLE_NAME).filter(Boolean);

    if (tables.length === 0) {
      console.log('No increase_* tables found. Nothing to do.');
      return;
    }

    console.log('Found increase_* tables:');
    for (const t of tables) console.log(`  - ${t}`);

    if (!apply) {
      console.log('');
      console.log('Dry run only. Re-run with --yes to DROP these tables.');
      return;
    }

    console.log('');
    console.log('Dropping increase_* tables...');

    await connection.query('SET FOREIGN_KEY_CHECKS = 0');

    const dropSql = `DROP TABLE IF EXISTS ${tables.map(quoteIdent).join(', ')};`;
    await connection.query(dropSql);

    await connection.query('SET FOREIGN_KEY_CHECKS = 1');

    const [afterRows] = await connection.execute(
      `SELECT TABLE_NAME
         FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = ?
          AND TABLE_TYPE = 'BASE TABLE'
          AND TABLE_NAME REGEXP '^increase_'
        ORDER BY TABLE_NAME ASC`,
      [dbName]
    );

    const afterTables = (afterRows || []).map((r) => r.TABLE_NAME).filter(Boolean);

    if (afterTables.length === 0) {
      console.log('Done. All increase_* tables dropped.');
    } else {
      console.warn('Some increase_* tables still exist after DROP:');
      for (const t of afterTables) console.warn(`  - ${t}`);
      process.exitCode = 1;
    }
  } finally {
    try { await connection.end(); } catch (_) {}
  }
}

main().catch((e) => {
  if (e && e.code === 'ER_ACCESS_DENIED_ERROR') {
    console.error('MySQL access denied. Check DATABASE_URL username/password and permissions.');
  } else if (e && e.code === 'ECONNREFUSED') {
    console.error('MySQL connection refused. Check host/port in DATABASE_URL and network/firewall access.');
  } else {
    console.error('Failed:', e.message || e);
  }
  process.exit(1);
});

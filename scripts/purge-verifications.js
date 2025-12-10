#!/usr/bin/env node
'use strict';
require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');

(async () => {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) throw new Error('DATABASE_URL not set');
  const u = new URL(dsn);
  const sslMode = (u.searchParams.get('ssl-mode') || u.searchParams.get('sslmode') || '').toUpperCase();
  const caPath = process.env.DATABASE_CA_CERT;
  let sslOptions;
  if (caPath && fs.existsSync(caPath)) {
    sslOptions = { ca: fs.readFileSync(caPath, 'utf8'), rejectUnauthorized: true };
  } else if (sslMode === 'REQUIRED') {
    sslOptions = { rejectUnauthorized: false };
  }
  const pool = await mysql.createPool({
    host: u.hostname,
    port: Number(u.port) || 3306,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: u.pathname.replace(/^\//, ''),
    ssl: sslOptions,
    connectionLimit: 4
  });

  const now = Date.now();
  const [[totalRow]] = await pool.query('SELECT COUNT(*) AS c FROM email_verifications');
  const [[oldRow]] = await pool.query('SELECT COUNT(*) AS c FROM email_verifications WHERE used=1 OR expires_at < ?', [now]);
  const [delRes] = await pool.execute('DELETE FROM email_verifications WHERE used=1 OR expires_at < ?', [now]);
  const [[afterRow]] = await pool.query('SELECT COUNT(*) AS c FROM email_verifications');
  await pool.end();

  console.log(JSON.stringify({ total_before: totalRow.c, purge_candidates: oldRow.c, deleted: delRes.affectedRows ?? null, total_after: afterRow.c }, null, 2));
})();

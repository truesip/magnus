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

  const [pre] = await pool.query('SELECT COUNT(*) as c FROM signup_users');
  const before = pre[0].c;
  const [res] = await pool.execute('DELETE FROM signup_users');
  const [post] = await pool.query('SELECT COUNT(*) as c FROM signup_users');
  await pool.end();
  console.log(JSON.stringify({ before, deleted: res.affectedRows ?? null, after: post[0].c }, null, 2));
})();

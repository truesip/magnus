#!/usr/bin/env node
'use strict';
require('dotenv').config();
const mysql = require('mysql2/promise');
const axios = require('axios');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');

function joinUrl(base, p){ if (!base) return p||''; let b=String(base); let s=String(p||''); if (b.endsWith('/')) b=b.slice(0,-1); if (s && !s.startsWith('/')) s='/'+s; return b+s; }

async function main(){
  const dsn = process.env.DATABASE_URL; if (!dsn) throw new Error('DATABASE_URL not set');
  const u = new URL(dsn);
  const sslMode = (u.searchParams.get('ssl-mode') || u.searchParams.get('sslmode') || '').toUpperCase();
  const caPath = process.env.DATABASE_CA_CERT;
  let sslOptions; if (caPath && fs.existsSync(caPath)) { sslOptions = { ca: fs.readFileSync(caPath,'utf8'), rejectUnauthorized:true }; } else if (sslMode==='REQUIRED'){ sslOptions = { rejectUnauthorized:false }; }
  const pool = await mysql.createPool({ host:u.hostname, port:Number(u.port)||3306, user:decodeURIComponent(u.username), password:decodeURIComponent(u.password), database:u.pathname.replace(/^\//,''), ssl:sslOptions, connectionLimit:4 });

  const [rows] = await pool.query('SELECT id, magnus_user_id, username, email FROM signup_users ORDER BY id DESC LIMIT 1');
  if (!rows.length) { console.log('No users found in signup_users. Nothing to delete.'); await pool.end(); return; }
  const row = rows[0];

  const apiKey = process.env.MAGNUSBILLING_API_KEY; const apiSecret = process.env.MAGNUSBILLING_API_SECRET; const base = process.env.MAGNUSBILLING_URL;
  if (!apiKey || !apiSecret || !base) throw new Error('Missing MagnusBilling credentials in env');
  const httpsAgent = new https.Agent({ rejectUnauthorized: !(process.env.MAGNUSBILLING_TLS_INSECURE==='1'), ...(process.env.MAGNUSBILLING_TLS_SERVERNAME? {servername: process.env.MAGNUSBILLING_TLS_SERVERNAME}: {})});
  const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER || undefined;

  async function signPost(url, params){ const body = params.toString(); const sign = crypto.createHmac('sha512', apiSecret).update(body).digest('hex');
    const resp = await axios.post(url, body, { headers:{ 'Content-Type':'application/x-www-form-urlencoded', ...(hostHeader? {'Host':hostHeader}:{}), 'Key': apiKey, 'Sign': sign }, httpsAgent, validateStatus:()=>true, timeout:30000 });
    return resp;
  }

  let id = row.magnus_user_id && String(row.magnus_user_id).trim();
  if (!id) {
    // try to look up by username via read
    const readUrl = joinUrl(base, '/index.php/user/read');
    const params = new URLSearchParams();
    params.append('module','user'); params.append('action','read'); params.append('page','1'); params.append('start','0'); params.append('limit','1');
    params.append('filter', JSON.stringify([{ type:'string', field:'username', value: row.username, comparison:'eq' }]));
    const r = await signPost(readUrl, params);
    if (r.status>=200 && r.status<300 && r.data && r.data.rows && r.data.rows[0] && r.data.rows[0].id){ id = String(r.data.rows[0].id); }
  }

  if (!id) { console.log('Could not find MagnusBilling user id for', row.username); await pool.end(); return; }

  const destroyUrl = joinUrl(base, '/index.php/user/destroy');
  const dParams = new URLSearchParams(); dParams.append('module','user'); dParams.append('action','destroy'); dParams.append('id', id);
  const del = await signPost(destroyUrl, dParams);
  console.log('MB destroy status:', del.status, typeof del.data==='string'? del.data.slice(0,200): del.data);

  // Remove from local DB
  await pool.execute('DELETE FROM signup_users WHERE id=?', [row.id]);
  await pool.end();
  console.log('Local row deleted:', row.username);
}

main().catch(e=>{ console.error(e.message||e); process.exit(1); });

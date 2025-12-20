// Utility: test MagnusBilling /call/read filtering behavior.
// Usage:
//   node scripts/test-magnus-cdr-filter.js <magnusUserId> [username]

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');

// Load .env.local first (for local development), fallback to .env
const envLocalPath = path.join(__dirname, '..', '.env.local');
if (fs.existsSync(envLocalPath)) {
  require('dotenv').config({ path: envLocalPath });
} else {
  require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
}

const magnusUserId = process.argv[2];
const username = process.argv[3];

if (!magnusUserId) {
  console.error('Usage: node scripts/test-magnus-cdr-filter.js <magnusUserId> [username]');
  process.exit(1);
}

const apiKey = process.env.MAGNUSBILLING_API_KEY;
const apiSecret = process.env.MAGNUSBILLING_API_SECRET;
const baseUrl = process.env.MAGNUSBILLING_URL;
if (!apiKey || !apiSecret || !baseUrl) {
  console.error('Missing MAGNUSBILLING_* env vars');
  process.exit(1);
}

function joinUrl(base, p) {
  if (!base) return p || '';
  let b = String(base);
  let s = String(p || '');
  if (b.endsWith('/')) b = b.slice(0, -1);
  if (s && !s.startsWith('/')) s = '/' + s;
  return b + s;
}

function buildNonce() {
  const nowSec = Math.floor(Date.now() / 1000);
  const micro = String(Number(process.hrtime.bigint() % 1000000n)).padStart(6, '0');
  return String(nowSec) + micro;
}

async function signedPost(relPath, params) {
  const p = params instanceof URLSearchParams ? params : new URLSearchParams(params || {});
  if (!p.get('nonce')) p.append('nonce', buildNonce());
  const postData = p.toString();
  const sign = crypto.createHmac('sha512', apiSecret).update(postData).digest('hex');
  const url = joinUrl(baseUrl, relPath);
  return axios.post(url, postData, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Key: apiKey, Sign: sign },
    timeout: 30000,
    validateStatus: () => true
  });
}

function summarize(label, resp) {
  const data = resp && resp.data ? resp.data : {};
  const rows = data.rows || data.data || [];
  const idCounts = new Map();
  for (const r of rows) {
    const id = String(r?.id_user ?? r?.user_id ?? '');
    idCounts.set(id, (idCounts.get(id) || 0) + 1);
  }
  const top = [...idCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);

  console.log('\n== ' + label + ' ==');
  console.log('HTTP', resp.status, 'success', data.success, 'rows', rows.length);
  console.log('top id_user values:', top);
  if (rows[0]) {
    console.log('sample row fields:', {
      id_user: rows[0].id_user,
      idUserusername: rows[0].idUserusername,
      username: rows[0].username,
      user: rows[0].user,
      accountcode: rows[0].accountcode
    });
  }
}

(async () => {
  const baseParams = {
    module: 'call',
    action: 'read',
    start: '0',
    limit: '50',
    id_user: String(magnusUserId),
    idUser: String(magnusUserId),
    userid: String(magnusUserId)
  };
  if (username) {
    baseParams.username = String(username);
    baseParams.user = String(username);
  }

  const resp1 = await signedPost('/index.php/call/read', baseParams);
  summarize('no filter param', resp1);

  // Candidate formats (some Magnus/ExtJS backends expect these)
  const f1 = JSON.stringify([{ type: 'numeric', field: 'id_user', value: String(magnusUserId) }]);
  const resp2 = await signedPost('/index.php/call/read', { ...baseParams, filter: f1 });
  summarize('filter=[{type,field,value}]', resp2);

  const f2 = JSON.stringify([{ property: 'id_user', value: String(magnusUserId) }]);
  const resp3 = await signedPost('/index.php/call/read', { ...baseParams, filter: f2 });
  summarize('filter=[{property,value}]', resp3);

  const resp4 = await signedPost('/index.php/call/read', {
    ...baseParams,
    'filter[0][field]': 'id_user',
    'filter[0][type]': 'numeric',
    'filter[0][value]': String(magnusUserId)
  });
  summarize('filter[0][field/type/value]', resp4);

  const resp5 = await signedPost('/index.php/call/read', {
    ...baseParams,
    'filter[0][property]': 'id_user',
    'filter[0][value]': String(magnusUserId)
  });
  summarize('filter[0][property/value]', resp5);

  // Some backends accept query-style params
  const resp6 = await signedPost('/index.php/call/read', {
    ...baseParams,
    query: String(magnusUserId),
    field: 'id_user'
  });
  summarize('query/field', resp6);
})().catch((e) => {
  console.error('Error:', e && e.message ? e.message : e);
  process.exit(1);
});

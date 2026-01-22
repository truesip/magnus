#!/usr/bin/env node
'use strict';

// Create a "quick" voice broadcast campaign in MagnusBilling via the signed HTTP API.
//
// What this script does (happy path):
//  1) Creates a Phonebook
//  2) Adds Phone Numbers into that Phonebook
//  3) Creates a Campaign linked to the Phonebook
//  4) Optionally attempts to start/activate the campaign
//
// NOTE:
// - MagnusBilling module names/field names can vary by version/customization.
//   Many installs expose phonebook modules as camelCase (phoneBook / phoneNumber).
//   This script will auto-detect common variants.
// - If your install uses pkg_* modules, pass --phonebook-module pkg_phonebook etc.
// - If your voice broadcast install requires additional campaign fields (trunk, IVR, audio file id/path, etc),
//   supply them via --extra '{"some_field":123}' or extend createCampaign() below.

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const axios = require('axios');

// Load .env.local first (for local dev), fallback to .env (match other scripts)
(function loadEnv() {
  const envLocalPath = path.join(__dirname, '..', '.env.local');
  if (fs.existsSync(envLocalPath)) {
    require('dotenv').config({ path: envLocalPath });
  } else {
    require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
  }
})();

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
  return `${nowSec}${micro}`;
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a) continue;

    // Collect positional args (useful on Windows where npm may swallow unknown --flags)
    if (!String(a).startsWith('--')) {
      out._.push(a);
      continue;
    }

    // Ignore option separator if it somehow reaches us
    if (a === '--') continue;

    const eq = a.indexOf('=');
    if (eq !== -1) {
      const k = a.slice(2, eq);
      const v = a.slice(eq + 1);
      out[k] = v;
      continue;
    }

    const k = a.slice(2);
    const next = argv[i + 1];
    if (next && !String(next).startsWith('--')) {
      out[k] = next;
      i += 1;
    } else {
      out[k] = '1';
    }
  }
  return out;
}

function looksLikeModuleTriple(pos) {
  if (!Array.isArray(pos) || pos.length < 3) return false;
  const a = String(pos[0] || '').toLowerCase();
  const b = String(pos[1] || '').toLowerCase();
  const c = String(pos[2] || '').toLowerCase();
  return a.includes('phonebook') && b.includes('phonenumber') && c.includes('campaign');
}

function applyPositionalFallback(args) {
  // If npm/Windows stripped --flags, values may arrive as positional args.
  const pos = Array.isArray(args?._) ? [...args._] : [];
  if (!pos.length) return;

  // If the first 3 positional args look like module names (e.g. pkg_phonebook pkg_phonenumber pkg_campaign)
  // treat them as module overrides.
  if (!args['phonebook-module'] && !args['phonenumber-module'] && !args['campaign-module'] && looksLikeModuleTriple(pos)) {
    args['phonebook-module'] = pos[0];
    args['phonenumber-module'] = pos[1];
    args['campaign-module'] = pos[2];
    pos.splice(0, 3);
  }

  // Positional format fallback:
  //   <name...> <numbers> <userId> [trunkId] [ivrId] [start]
  // We parse from the end so multi-word names work.

  // start (0/1)
  if (!args.start && pos.length && (pos[pos.length - 1] === '0' || pos[pos.length - 1] === '1')) {
    args.start = pos.pop();
  }

  // Trailing numeric ids (1-9 digits) represent: userId, trunkId, ivrId (in that order)
  // We intentionally do NOT consume 10+ digit numeric tokens here to avoid eating phone numbers.
  const ids = [];
  while (pos.length && /^\d{1,9}$/.test(String(pos[pos.length - 1] || ''))) {
    ids.unshift(String(pos.pop()));
  }
  if (!args['user-id'] && ids[0]) args['user-id'] = ids[0];
  if (!args['trunk-id'] && ids[1]) args['trunk-id'] = ids[1];
  if (!args['ivr-id'] && !args['audio-id'] && ids[2]) args['ivr-id'] = ids[2];

  // numbers
  if (!args.numbers && pos.length) {
    args.numbers = String(pos.pop());
  }

  // name
  if (!args.name && pos.length) {
    args.name = pos.join(' ');
  }
}

function usage(exitCode = 0) {
  const msg = `
Usage:
  node scripts/mb-voice-broadcast-quick-campaign.js \
    --name "My Broadcast" \
    --numbers "+15551234567,+15557654321" \
    --user-id 4 \
    --tts "Hello, this is a test broadcast" \
    --start 0

Required env vars (.env or .env.local):
  MAGNUSBILLING_URL
  MAGNUSBILLING_API_KEY
  MAGNUSBILLING_API_SECRET

Common options:
  --name                  Campaign name (default: VoiceBroadcast-YYYYMMDD-HHMMSS)
  --user-id               Magnus user id (pkg_user.id) to own the objects (required)
  --numbers               Comma/newline separated list of destination numbers
  --numbers-file          Path to text file with one number per line
  --phonebook-id          Use existing phonebook id (skip creating one)
  --startingdate          Campaign startingdate. Formats: "YYYY-MM-DD HH:MM:SS" | YYYY-MM-DD | now | today
                          Default: now
  --tts                   Optional: set campaign tts_audio (text-to-speech message)
  --tts2                  Optional: set campaign tts_audio2
  --start                 1 to attempt to start/activate the campaign (default: 0)

Advanced:
  --phonebook-module      Default: auto (tries phoneBook, phonebook, pkg_phonebook)
  --phonenumber-module    Default: auto (tries phoneNumber, phonenumber, pkg_phonenumber)
  --campaign-module       Default: campaign
  --extra                 JSON object of extra campaign fields, merged into save params
                           Example: --extra '{"max_retry":3,"retry_time":60}'

Notes:
  - If your MagnusBilling uses pkg_* modules, try:
      --phonebook-module pkg_phonebook --phonenumber-module pkg_phonenumber --campaign-module pkg_campaign
  - If you get a "module not found" style error, your module names differ.
  - If you get a validation error, your instance requires additional campaign fields.

Helper commands:
  --list-users [N]         List first N users (prints id + username only)
  --list-trunks [N]        List first N trunks
  --list-ivrs [N]          List first N IVRs
`;
  // eslint-disable-next-line no-console
  console.log(msg.trim());
  process.exit(exitCode);
}

function digitsOnly(s) {
  return String(s || '').replace(/[^0-9]/g, '');
}

function parseNumbers({ raw, filePath }) {
  const out = [];

  const add = (v) => {
    const d = digitsOnly(v);
    if (!d) return;
    out.push(d);
  };

  if (raw) {
    const parts = String(raw)
      .split(/[\n,]/g)
      .map((x) => x.trim())
      .filter(Boolean);
    for (const p of parts) add(p);
  }

  if (filePath) {
    const txt = fs.readFileSync(String(filePath), 'utf8');
    const lines = String(txt)
      .split(/\r?\n/g)
      .map((x) => x.trim())
      .filter(Boolean);
    for (const line of lines) add(line);
  }

  // De-dup while preserving order
  const seen = new Set();
  const uniq = [];
  for (const n of out) {
    if (seen.has(n)) continue;
    seen.add(n);
    uniq.push(n);
  }
  return uniq;
}

function safePreview(data, max = 400) {
  try {
    if (data == null) return '';
    if (typeof data === 'string') return data.slice(0, max);
    return JSON.stringify(data).slice(0, max);
  } catch {
    return '';
  }
}

function truncateText(s, maxLen) {
  const str = String(s ?? '');
  const max = Math.max(1, parseInt(String(maxLen || 0), 10) || 1);
  if (str.length <= max) return str;
  return str.slice(0, max);
}

function formatMbDateTimeLocal(d) {
  const dt = d instanceof Date ? d : new Date(d);
  if (!Number.isFinite(dt.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  const y = dt.getFullYear();
  const m = pad(dt.getMonth() + 1);
  const day = pad(dt.getDate());
  const hh = pad(dt.getHours());
  const mm = pad(dt.getMinutes());
  const ss = pad(dt.getSeconds());
  return `${y}-${m}-${day} ${hh}:${mm}:${ss}`;
}

function normalizeMbDateTimeInput(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return '';
  const low = s.toLowerCase();
  if (low === 'now') return formatMbDateTimeLocal(new Date());
  if (low === 'today') {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    return formatMbDateTimeLocal(d);
  }
  // Accept YYYY-MM-DD by expanding to midnight
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return `${s} 00:00:00`;
  // Accept full datetime as-is (MagnusBilling format)
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/.test(s)) return s;
  return s; // pass through; MagnusBilling will validate/normalize if it can
}

function extractMbErrors(data) {
  try {
    if (!data) return null;
    if (typeof data === 'string') return data;
    if (typeof data === 'object') return data.errors ?? data.error ?? data.message ?? null;
  } catch {}
  return null;
}

function mbErrorText(data) {
  const e = extractMbErrors(data);
  if (e == null) return '';
  if (typeof e === 'string') return e;
  try { return JSON.stringify(e); } catch { return String(e); }
}

function mbLooksLikeForeignKeyViolation(data) {
  const s = mbErrorText(data);
  return /Integrity constraint violation:\s*1452/i.test(s) || /foreign key constraint fails/i.test(s);
}

function mbLooksLikeMissingIdUserDefault(data) {
  const s = mbErrorText(data);
  return /Field 'id_user' doesn't have a default value/i.test(s);
}

function isLikelySuccess(resp) {
  const status = Number(resp?.status || 0);
  if (!(status >= 200 && status < 300)) return false;

  const d = resp?.data;
  if (d == null) return true;
  if (typeof d === 'string') {
    // Some installs return plain text; treat 2xx as success unless it clearly says error.
    return !/\berror\b|\bfail\b|\bexception\b/i.test(d);
  }
  if (typeof d === 'object') {
    if (d.success === true) return true;
    if (d.success === false) return false;
    if (String(d.status || '').toLowerCase() === 'success') return true;
    if (d.errors) return false;
    return true;
  }
  return true;
}

function extractIdFromSaveResponse(data) {
  try {
    if (!data) return null;
    if (typeof data === 'object') {
      // Common patterns
      const direct = data.id ?? data.insertId ?? data.insert_id ?? data.last_id;
      if (direct != null && String(direct).trim() !== '') return String(direct).trim();

      const nested = data.data?.id ?? data.data?.insertId;
      if (nested != null && String(nested).trim() !== '') return String(nested).trim();

      // Sometimes rows[0].id is returned
      const rows = data.rows || data.data || [];
      if (Array.isArray(rows) && rows[0]) {
        const r = rows[0];
        const rid = r.id ?? r.id_campaign ?? r.idCampaign ?? r.id_phonebook ?? r.idPhonebook;
        if (rid != null && String(rid).trim() !== '') return String(rid).trim();
      }
    }
  } catch {}
  return null;
}

function getHttpAgentFromEnv() {
  const tlsInsecure = String(process.env.MAGNUSBILLING_TLS_INSECURE || '0') === '1';
  const tlsServername = process.env.MAGNUSBILLING_TLS_SERVERNAME;
  return new https.Agent({
    rejectUnauthorized: !tlsInsecure,
    ...(tlsServername ? { servername: tlsServername } : {})
  });
}

async function mbSignedPost({ relPath, params, validateStatus }) {
  const apiKey = process.env.MAGNUSBILLING_API_KEY;
  const apiSecret = process.env.MAGNUSBILLING_API_SECRET;
  const baseUrl = process.env.MAGNUSBILLING_URL;
  if (!apiKey || !apiSecret || !baseUrl) {
    throw new Error('Missing MAGNUSBILLING_URL / MAGNUSBILLING_API_KEY / MAGNUSBILLING_API_SECRET in env');
  }

  const p = params instanceof URLSearchParams ? params : new URLSearchParams(params || {});
  if (!p.get('nonce')) p.append('nonce', buildNonce());

  const body = p.toString();
  const sign = crypto.createHmac('sha512', apiSecret).update(body).digest('hex');

  const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
  const httpsAgent = getHttpAgentFromEnv();

  const url = joinUrl(baseUrl, relPath);
  return axios.post(url, body, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(hostHeader ? { Host: hostHeader } : {}),
      Key: apiKey,
      Sign: sign
    },
    httpsAgent,
    timeout: 30000,
    validateStatus: validateStatus || (() => true)
  });
}

async function mbCall({ module, action, fields, validateStatus }) {
  const m = String(module || '').trim();
  const a = String(action || '').trim();
  if (!m || !a) throw new Error('mbCall missing module/action');

  const p = new URLSearchParams();
  p.append('module', m);
  p.append('action', a);

  const obj = fields && typeof fields === 'object' ? fields : {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    p.append(String(k), String(v));
  }

  return mbSignedPost({ relPath: `/index.php/${m}/${a}`, params: p, validateStatus });
}

async function probeReadModule(moduleName) {
  const m = String(moduleName || '').trim();
  if (!m) return { ok: false, status: null };
  try {
    const resp = await mbCall({
      module: m,
      action: 'read',
      fields: { start: '0', limit: '1' },
      validateStatus: () => true
    });
    return { ok: resp.status !== 404, status: resp.status };
  } catch (e) {
    return { ok: false, status: null, error: e?.message || e };
  }
}

function parseListLimit(val, defaultLimit = 20) {
  const s = String(val ?? '').trim();
  if (!s || s === '1' || s.toLowerCase() === 'true') return defaultLimit;
  const n = parseInt(s, 10);
  return Number.isFinite(n) ? Math.max(1, Math.min(5000, n)) : defaultLimit;
}

async function resolveModuleName({ preferred, candidates }) {
  const uniq = [];
  const push = (v) => {
    const s = String(v || '').trim();
    if (!s) return;
    if (!uniq.includes(s)) uniq.push(s);
  };

  push(preferred);
  for (const c of (candidates || [])) push(c);

  const tried = [];

  for (const m of uniq) {
    const pr = await probeReadModule(m);
    tried.push({ module: m, status: pr.status });
    if (pr.ok) return { module: m, tried, unresolved: false };
  }

  // Fall back to preferred (or first candidate) even if probing failed.
  return { module: String(preferred || (candidates && candidates[0]) || '').trim(), tried, unresolved: true };
}

async function createPhonebook({ module, userId, name }) {
  const safeName = truncateText(String(name || '').trim(), 30);

  // Try a couple of common field variants
  const attempts = [
    { label: 'id_user', build: () => ({ id: '0', status: '1', name: safeName, id_user: userId }) },
    { label: 'idUser', build: () => ({ id: '0', status: '1', name: safeName, idUser: userId }) },
    { label: 'no_user', build: () => ({ id: '0', status: '1', name: safeName }) }
  ];

  const errors = [];
  for (const a of attempts) {
    const fields = a.build();
    try {
      const resp = await mbCall({ module, action: 'save', fields, validateStatus: () => true });

      if (isLikelySuccess(resp)) {
        const id = extractIdFromSaveResponse(resp.data);
        return { ok: true, id, resp };
      }

      // If we got a foreign key violation, id_user *was* applied but refers to a non-existent user.
      // Do not continue trying other keys (they will only hide the root cause).
      if (mbLooksLikeForeignKeyViolation(resp.data)) {
        errors.push({ attempt: a.label, status: resp.status, data: resp.data, fatal: true });
        return { ok: false, errors };
      }

      errors.push({ attempt: a.label, status: resp.status, data: resp.data });

      // If we're missing id_user default, try the next alias.
      // Otherwise, continuing likely won't help.
      if (!mbLooksLikeMissingIdUserDefault(resp.data)) {
        // Keep going only if the userId wasn't provided (maybe module assigns it implicitly).
        // If userId was provided, stop and surface this error.
        if (userId) {
          return { ok: false, errors };
        }
      }
    } catch (e) {
      errors.push({ attempt: a.label, error: e?.message || e });
    }
  }

  return { ok: false, errors };
}

async function addPhoneNumber({ module, userId, phonebookId, number }) {
  // Try common variants
  const attempts = [
    () => ({ id: '0', status: '1', id_phonebook: phonebookId, number, name: number, id_user: userId }),
    () => ({ id: '0', status: '1', idPhonebook: phonebookId, number, name: number, idUser: userId }),
    () => ({ id: '0', status: '1', id_phonebook: phonebookId, phonenumber: number, name: number, id_user: userId }),
    () => ({ id: '0', status: '1', id_phonebook: phonebookId, number, name: number })
  ];

  const errors = [];
  for (const build of attempts) {
    const fields = build();
    try {
      const resp = await mbCall({ module, action: 'save', fields });
      if (isLikelySuccess(resp)) {
        const id = extractIdFromSaveResponse(resp.data);
        return { ok: true, id, resp };
      }
      errors.push({ status: resp.status, data: resp.data });
    } catch (e) {
      errors.push({ error: e?.message || e });
    }
  }

  return { ok: false, errors };
}

async function createCampaign({ module, userId, name, phonebookId, startingdate, tts, tts2, extra }) {
  const safeName = String(name || '').trim();
  const startDt = normalizeMbDateTimeInput(startingdate || '');

  // MagnusBilling campaign module commonly uses id_phonebook as an array.
  // The ExtJS backend accepts bracket syntax: id_phonebook[0]=<id>
  const baseFields = {
    id: '0',
    status: '1',
    name: safeName,
    id_user: userId,
    // Important: campaigns with startingdate=0000-00-00 00:00:00 may not run on some installs.
    // Default to a real datetime unless the caller overrides.
    ...(startDt ? { startingdate: startDt } : { startingdate: formatMbDateTimeLocal(new Date()) }),

    type: '1',
    frequency: '10',
    max_frequency: '10',

    // Default window: allow running at any time.
    daily_start_time: '00:00:00',
    daily_stop_time: '23:59:59',
    monday: '1',
    tuesday: '1',
    wednesday: '1',
    thursday: '1',
    friday: '1',
    saturday: '1',
    sunday: '1',

    ...(phonebookId ? { 'id_phonebook[0]': String(phonebookId) } : {}),
    ...(tts ? { tts_audio: String(tts) } : {}),
    ...(tts2 ? { tts_audio2: String(tts2) } : {}),
    ...(extra || {})
  };

  const attempts = [
    { label: 'id_user', fields: baseFields },
    // Fallback alias (some installs accept idUser)
    { label: 'idUser', fields: { ...baseFields, idUser: baseFields.id_user } }
  ];

  const errors = [];
  for (const a of attempts) {
    try {
      const resp = await mbCall({ module, action: 'save', fields: a.fields, validateStatus: () => true });
      if (isLikelySuccess(resp)) {
        const id = extractIdFromSaveResponse(resp.data);
        return { ok: true, id, resp };
      }
      // If foreign key violation, surface immediately
      if (mbLooksLikeForeignKeyViolation(resp.data)) {
        errors.push({ attempt: a.label, status: resp.status, data: resp.data, fatal: true });
        return { ok: false, errors };
      }
      errors.push({ attempt: a.label, status: resp.status, data: resp.data });
    } catch (e) {
      errors.push({ attempt: a.label, error: e?.message || e });
    }
  }

  return { ok: false, errors };
}

async function tryStartCampaign({ module, campaignId }) {
  if (!campaignId) return { ok: false, reason: 'missing_campaign_id' };

  // Different installs expose different start verbs.
  const actions = [
    { action: 'start', fields: { id: campaignId } },
    { action: 'run', fields: { id: campaignId } },
    { action: 'process', fields: { id: campaignId } },
    // Fallback: ensure status=1 and set a real startingdate in case the campaign was created with 0000-00-00...
    { action: 'save', fields: { id: campaignId, status: '1', startingdate: formatMbDateTimeLocal(new Date()) } }
  ];

  const attempts = [];
  for (const a of actions) {
    try {
      const resp = await mbCall({ module, action: a.action, fields: a.fields });
      attempts.push({ action: a.action, status: resp.status, preview: safePreview(resp.data) });
      if (isLikelySuccess(resp)) return { ok: true, action: a.action, resp, attempts };
    } catch (e) {
      attempts.push({ action: a.action, error: e?.message || e });
    }
  }

  return { ok: false, attempts };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  applyPositionalFallback(args);

  // Support "help" in positional form as well
  if (args.help || args.h || (Array.isArray(args._) && args._.some(v => ['help', '-h', '/?'].includes(String(v || '').toLowerCase())))) {
    usage(0);
  }

  const phonebookModuleRaw = args['phonebook-module'] || process.env.MB_PHONEBOOK_MODULE || '';
  const phonenumberModuleRaw = args['phonenumber-module'] || process.env.MB_PHONENUMBER_MODULE || '';
  const campaignModule = args['campaign-module'] || process.env.MB_CAMPAIGN_MODULE || 'campaign';

  // Auto-detect phonebook/number modules (many MagnusBilling installs use camelCase controller ids)
  const phonebookResolved = await resolveModuleName({
    preferred: phonebookModuleRaw,
    candidates: ['phoneBook', 'phonebook', 'pkg_phonebook']
  });
  const phonenumberResolved = await resolveModuleName({
    preferred: phonenumberModuleRaw,
    candidates: ['phoneNumber', 'phonenumber', 'pkg_phonenumber']
  });

  const phonebookModule = phonebookResolved.module || 'phoneBook';
  const phonenumberModule = phonenumberResolved.module || 'phoneNumber';

  // Helper commands (do not create anything)
  if (args['list-users'] !== undefined) {
    const limit = parseListLimit(args['list-users'], 25);
    const resp = await mbCall({ module: 'user', action: 'read', fields: { start: '0', limit: String(limit) }, validateStatus: () => true });
    const rows = (resp?.data && typeof resp.data === 'object') ? (resp.data.rows || resp.data.data || []) : [];
    const arr = Array.isArray(rows) ? rows : [];
    // Print only safe fields (do not print passwords)
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ users: arr.map(u => ({ id: u?.id, username: u?.username, id_group: u?.id_group })) }, null, 2));
    return;
  }
  if (args['list-trunks'] !== undefined) {
    const limit = parseListLimit(args['list-trunks'], 50);
    const resp = await mbCall({ module: 'trunk', action: 'read', fields: { start: '0', limit: String(limit) }, validateStatus: () => true });
    const rows = (resp?.data && typeof resp.data === 'object') ? (resp.data.rows || resp.data.data || []) : [];
    const arr = Array.isArray(rows) ? rows : [];
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ trunks: arr.map(t => ({ id: t?.id, trunkcode: t?.trunkcode, trunkprefix: t?.trunkprefix, providertech: t?.providertech })) }, null, 2));
    return;
  }
  if (args['list-ivrs'] !== undefined) {
    const limit = parseListLimit(args['list-ivrs'], 50);
    const resp = await mbCall({ module: 'ivr', action: 'read', fields: { start: '0', limit: String(limit) }, validateStatus: () => true });
    const rows = (resp?.data && typeof resp.data === 'object') ? (resp.data.rows || resp.data.data || []) : [];
    const arr = Array.isArray(rows) ? rows : [];
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ ivrs: arr.map(v => ({ id: v?.id, name: v?.name, description: v?.description })) }, null, 2));
    return;
  }

  const now = new Date();
  const stamp = now.toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const campaignName = (args.name || `VoiceBroadcast-${stamp}`).trim();

  const userId = String(args['user-id'] || process.env.MB_USER_ID || '').trim();
  if (!userId) {
    // eslint-disable-next-line no-console
    console.error('Missing --user-id. Use: node scripts/mb-voice-broadcast-quick-campaign.js --list-users 25');
    process.exit(1);
  }

  const numbers = parseNumbers({ raw: args.numbers, filePath: args['numbers-file'] });
  if (!numbers.length) {
    // eslint-disable-next-line no-console
    console.error('No numbers provided. Use --numbers or --numbers-file.');
    usage(1);
  }

  const phonebookIdArg = String(args['phonebook-id'] || '').trim();
  const shouldStart = String(args.start || '0') === '1';
  const startingdateRaw = args.startingdate || args['start-date'] || args['start-at'] || '';
  const startingdate = normalizeMbDateTimeInput(startingdateRaw || 'now');
  const tts = (args.tts != null) ? String(args.tts) : '';
  const tts2 = (args.tts2 != null) ? String(args.tts2) : '';

  let extra = null;
  if (args.extra) {
    try {
      extra = JSON.parse(String(args.extra));
      if (!extra || typeof extra !== 'object' || Array.isArray(extra)) extra = null;
    } catch {
      // eslint-disable-next-line no-console
      console.error('Invalid --extra JSON. Example: --extra "{\\"max_retry\\":3}"');
      process.exit(1);
    }
  }

  // eslint-disable-next-line no-console
  console.log('MagnusBilling quick campaign:');
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({
    campaignName,
    numbersCount: numbers.length,
    userId: userId || null,
    modules: { phonebook: phonebookModule, phonenumber: phonenumberModule, campaign: campaignModule },
    phonebookId: phonebookIdArg || null,
    startingdate: startingdate || null,
    tts: tts ? '[set]' : null,
    tts2: tts2 ? '[set]' : null,
    start: shouldStart
  }, null, 2));

  // 1) Phonebook
  let phonebookId = phonebookIdArg;
  if (!phonebookId) {
    const pbName = `${campaignName} Phonebook`;
    const pb = await createPhonebook({ module: phonebookModule, userId: userId || undefined, name: pbName });
    if (!pb.ok) {
      const attempts = (pb.errors || []).map(e => ({
        attempt: e.attempt || null,
        status: e.status || null,
        fatal: Boolean(e.fatal),
        errorPreview: safePreview(e.data || e.error)
      }));

      // eslint-disable-next-line no-console
      console.error('Failed to create phonebook. Attempts:', attempts);

      if (pb.errors && pb.errors.some(e => mbLooksLikeForeignKeyViolation(e.data))) {
        // eslint-disable-next-line no-console
        console.error('TIP: The --user-id you provided does not exist in MagnusBilling (pkg_user.id). Use the MagnusBilling user ID (not a local portal DB id).');
      }

      // eslint-disable-next-line no-console
      console.error('TIP: Your MagnusBilling likely uses camelCase modules. Try: --phonebook-module phoneBook --phonenumber-module phoneNumber');
      process.exit(1);
    }
    phonebookId = pb.id;
    // eslint-disable-next-line no-console
    console.log('Phonebook created:', { id: phonebookId || null, httpStatus: pb.resp?.status, preview: safePreview(pb.resp?.data) });
    if (!phonebookId) {
      // eslint-disable-next-line no-console
      console.warn('WARNING: Phonebook save succeeded but no id was detected in response. You may need to fetch it manually from the response.');
    }
  } else {
    // eslint-disable-next-line no-console
    console.log('Using existing phonebook id:', phonebookId);
  }

  if (!phonebookId) {
    // eslint-disable-next-line no-console
    console.error('Phonebook id is required to continue (could not detect it).');
    process.exit(1);
  }

  // 2) Add numbers
  let added = 0;
  let failed = 0;
  for (const n of numbers) {
    const r = await addPhoneNumber({ module: phonenumberModule, userId: userId || undefined, phonebookId, number: n });
    if (r.ok) {
      added += 1;
    } else {
      failed += 1;
      // eslint-disable-next-line no-console
      console.warn('Failed to add number:', n, 'preview:', safePreview(r.errors?.slice(-1)?.[0]));
    }
  }

  // eslint-disable-next-line no-console
  console.log('Phone numbers:', { added, failed, total: numbers.length });

  if (added === 0) {
    // eslint-disable-next-line no-console
    console.error('No phone numbers were added. Aborting.');
    process.exit(1);
  }

  // 3) Campaign
  const camp = await createCampaign({
    module: campaignModule,
    userId: userId || undefined,
    name: campaignName,
    phonebookId,
    startingdate,
    tts: tts || undefined,
    tts2: tts2 || undefined,
    extra
  });

  if (!camp.ok) {
    const attempts = (camp.errors || []).map(e => ({
      attempt: e.attempt || null,
      status: e.status || null,
      fatal: Boolean(e.fatal),
      errorPreview: safePreview(e.data || e.error)
    }));

    // eslint-disable-next-line no-console
    console.error('Failed to create campaign. Attempts:', attempts);

    if (camp.errors && camp.errors.some(e => mbLooksLikeForeignKeyViolation(e.data))) {
      // eslint-disable-next-line no-console
      console.error('TIP: Check that --user-id and --phonebook-id exist in MagnusBilling.');
    }

    // eslint-disable-next-line no-console
    console.error('TIP: If you need a TTS message, pass --tts "your message" (or use --extra to set campaign fields).');
    process.exit(1);
  }

  const campaignId = camp.id;
  // eslint-disable-next-line no-console
  console.log('Campaign created:', { id: campaignId || null, httpStatus: camp.resp?.status, preview: safePreview(camp.resp?.data) });

  // 4) Start (optional)
  if (shouldStart) {
    const startRes = await tryStartCampaign({ module: campaignModule, campaignId });
    if (startRes.ok) {
      // eslint-disable-next-line no-console
      console.log('Campaign start attempt succeeded via action:', startRes.action);
    } else {
      // eslint-disable-next-line no-console
      console.warn('Could not confirm campaign start. Attempts:', startRes.attempts);
      // eslint-disable-next-line no-console
      console.warn('TIP: Some installs start automatically when status=1, others require a different action name.');
    }
  }

  // eslint-disable-next-line no-console
  console.log('Done.');
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error('Fatal error:', e?.message || e);
  process.exit(1);
});

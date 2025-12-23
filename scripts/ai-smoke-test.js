#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const axios = require('axios');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

// Load env like server.js: .env.local (if present), else .env
(function loadEnv() {
  const envLocalPath = path.join(__dirname, '..', '.env.local');
  if (fs.existsSync(envLocalPath)) {
    require('dotenv').config({ path: envLocalPath });
    return;
  }
  require('dotenv').config();
})();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getArgValue(name) {
  const prefix = `${name}=`;
  const hit = process.argv.slice(2).find((a) => a.startsWith(prefix));
  return hit ? hit.slice(prefix.length) : null;
}

function hasFlag(name) {
  return process.argv.slice(2).includes(name);
}

function safeJson(x) {
  try {
    return JSON.stringify(x);
  } catch {
    return String(x);
  }
}

function summarizeAxiosFailure(err) {
  // Avoid dumping headers (could include Authorization). Only show safe details.
  const status = err?.response?.status;
  const data = err?.response?.data;
  const msg = err?.message || String(err);
  const safeData = (data && typeof data === 'object') ? data : (data != null ? String(data).slice(0, 400) : null);
  return { message: msg, status: status ?? null, data: safeData };
}

function extractCookie(setCookieHeaders, cookieName) {
  if (!Array.isArray(setCookieHeaders)) return null;
  for (const c of setCookieHeaders) {
    const s = String(c || '');
    if (s.startsWith(`${cookieName}=`)) {
      return s.split(';')[0];
    }
  }
  return null;
}

function startServer({ port }) {
  const serverPath = path.join(__dirname, '..', 'server.js');

  const childEnv = {
    ...process.env,
    PORT: String(port),
    // Ensure cookies work over http://localhost
    COOKIE_SECURE: '0',
    // Disable background schedulers during smoke tests
    BILLING_MARKUP_INTERVAL_MINUTES: '0',
    MB_CDR_IMPORT_INTERVAL_SECONDS: '0',
    // Keep output quieter
    DEBUG: '0'
  };

  const child = spawn(process.execPath, [serverPath], {
    env: childEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });

  const stdout = [];
  const stderr = [];
  child.stdout.on('data', (d) => {
    stdout.push(d.toString());
    if (stdout.length > 200) stdout.shift();
  });
  child.stderr.on('data', (d) => {
    stderr.push(d.toString());
    if (stderr.length > 200) stderr.shift();
  });

  return {
    child,
    getLogs: () => ({ stdout: stdout.join(''), stderr: stderr.join('') })
  };
}

async function waitForHealth(baseUrl, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const resp = await axios.get(`${baseUrl}/health`, { timeout: 2000, validateStatus: () => true });
      if (resp.status === 200) return true;
    } catch {
      // ignore
    }
    await sleep(500);
  }
  return false;
}

function buildDbPoolFromDatabaseUrl(dsn) {
  const u = new URL(dsn);
  const dbName = u.pathname.replace(/^\//, '');

  const sslMode = (u.searchParams.get('ssl-mode') || u.searchParams.get('sslmode') || '').toUpperCase();
  const caPath = process.env.DATABASE_CA_CERT;

  let sslOptions;
  if (caPath && fs.existsSync(caPath)) {
    sslOptions = { ca: fs.readFileSync(caPath, 'utf8'), rejectUnauthorized: true };
  } else if (sslMode === 'REQUIRED') {
    sslOptions = { rejectUnauthorized: false };
  }

  return mysql.createPool({
    host: u.hostname,
    port: Number(u.port) || 3306,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: dbName,
    ssl: sslOptions,
    connectionLimit: 2,
    waitForConnections: true,
    queueLimit: 0
  });
}

async function createTempUser(db) {
  const rand = crypto.randomBytes(4).toString('hex');
  const username = `smoketest_${rand}`;
  const email = `smoketest+${rand}@example.com`;
  const password = crypto.randomBytes(18).toString('base64url');
  const passwordHash = await bcrypt.hash(password, 10);

  const [ins] = await db.execute(
    'INSERT INTO signup_users (username, email, firstname, lastname, phone, password_hash) VALUES (?,?,?,?,?,?)',
    [username, email, 'Smoke', 'Test', null, passwordHash]
  );

  return {
    userId: ins.insertId,
    username,
    email,
    password
  };
}

async function deleteTempUser(db, userId) {
  await db.execute('DELETE FROM signup_users WHERE id = ?', [userId]);
}

async function loginAndGetSessionCookie(baseUrl, { username, password }) {
  const body = new URLSearchParams({ username, password }).toString();
  const resp = await axios.post(`${baseUrl}/login`, body, {
    timeout: 15000,
    maxRedirects: 0,
    validateStatus: () => true,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });

  if (resp.status !== 302) {
    throw new Error(`Login failed: expected 302, got ${resp.status}`);
  }

  const cookie = extractCookie(resp.headers['set-cookie'], 'connect.sid');
  if (!cookie) {
    throw new Error('Login failed: connect.sid cookie not found');
  }

  return cookie;
}

async function apiJson(baseUrl, cookie, { method, path: p, body }) {
  const url = `${baseUrl}${p}`;
  const resp = await axios.request({
    method,
    url,
    data: body,
    timeout: 30000,
    maxRedirects: 0,
    validateStatus: () => true,
    headers: {
      'Cookie': cookie,
      'Accept': 'application/json'
    }
  });

  return resp;
}

async function main() {
  const withNumber = hasFlag('--with-number');
  const keepServer = hasFlag('--keep-server');
  const port = Number(getArgValue('--port') || '8099');
  const baseUrl = getArgValue('--base-url') || `http://localhost:${port}`;

  const present = (k) => {
    const v = process.env[k];
    if (!v) return false;
    const s = String(v).trim();
    if (!s) return false;
    if (s === 'REPLACE_ME') return false;
    if (/^your_/i.test(s)) return false;
    return true;
  };
  const hasPipecatKey = present('PIPECAT_PRIVATE_API_KEY') || present('PIPECAT_API_KEY');

  if (withNumber) {
    console.log('NOTE: --with-number will BUY a Daily number (billable) and cannot automatically release it.');
  }

  const dsn = process.env.DATABASE_URL || '';
  if (!dsn) {
    console.error('DATABASE_URL is not set. Cannot run end-to-end /login + /api/me tests.');
    process.exitCode = 2;
    return;
  }

  // Fail fast if required provider/telephony keys are missing.
  // (These are required for POST /api/me/ai/agents to provision a Pipecat Cloud agent.)
  const missing = [];
  if (!hasPipecatKey) missing.push('PIPECAT_PRIVATE_API_KEY (or PIPECAT_API_KEY)');
  if (!present('PIPECAT_ORG_ID')) missing.push('PIPECAT_ORG_ID');
  if (!present('PIPECAT_AGENT_IMAGE')) missing.push('PIPECAT_AGENT_IMAGE');
  if (!present('DEEPGRAM_API_KEY')) missing.push('DEEPGRAM_API_KEY');
  if (!present('CARTESIA_API_KEY')) missing.push('CARTESIA_API_KEY');
  if (!present('XAI_API_KEY')) missing.push('XAI_API_KEY');
  if (withNumber && !present('DAILY_API_KEY')) missing.push('DAILY_API_KEY');

  if (missing.length) {
    console.error('Missing required environment variables for the AI smoke test:');
    for (const k of missing) console.error(`- ${k}`);
    console.error('Set these in .env.local (preferred) or your environment, then re-run.');
    process.exitCode = 2;
    return;
  }

  const server = startServer({ port });
  let db;
  let tempUser;
  let cookie;
  let agentId;

  try {
    const ok = await waitForHealth(baseUrl, 20000);
    if (!ok) {
      const logs = server.getLogs();
      console.error('Server did not become healthy in time. Recent logs:');
      console.error(logs.stderr.slice(-2000) || logs.stdout.slice(-2000));
      process.exitCode = 3;
      return;
    }

    db = buildDbPoolFromDatabaseUrl(dsn);
    tempUser = await createTempUser(db);

    cookie = await loginAndGetSessionCookie(baseUrl, { username: tempUser.username, password: tempUser.password });

    // Create agent
    const createResp = await apiJson(baseUrl, cookie, {
      method: 'POST',
      path: '/api/me/ai/agents',
      body: {
        display_name: `Smoke Agent ${tempUser.username}`,
        greeting: 'Hello! This is a local smoke test.',
        prompt: 'You are a smoke test agent. Keep responses brief.'
      }
    });

    if (createResp.status !== 200 || createResp.data?.success !== true) {
      throw new Error(`Create agent failed: status=${createResp.status} body=${safeJson(createResp.data).slice(0, 800)}`);
    }

    agentId = createResp.data?.data?.id;
    if (!agentId) throw new Error('Create agent succeeded but response missing agent id');

    // Update agent
    const patchResp = await apiJson(baseUrl, cookie, {
      method: 'PATCH',
      path: `/api/me/ai/agents/${encodeURIComponent(String(agentId))}`,
      body: {
        greeting: 'Hello! (updated) Local smoke test.',
        prompt: 'You are an updated smoke test agent.'
      }
    });

    if (patchResp.status !== 200 || patchResp.data?.success !== true) {
      throw new Error(`Patch agent failed: status=${patchResp.status} body=${safeJson(patchResp.data).slice(0, 800)}`);
    }

    // List agents
    const listResp = await apiJson(baseUrl, cookie, {
      method: 'GET',
      path: '/api/me/ai/agents'
    });

    if (listResp.status !== 200 || listResp.data?.success !== true) {
      throw new Error(`List agents failed: status=${listResp.status} body=${safeJson(listResp.data).slice(0, 800)}`);
    }

    const agents = Array.isArray(listResp.data?.data) ? listResp.data.data : [];
    const found = agents.find((a) => String(a.id) === String(agentId));
    if (!found) throw new Error('List agents did not include the created agent');

    if (withNumber) {
      // WARNING: This buys a number on your Daily account and cannot be auto-released.
      const buyResp = await apiJson(baseUrl, cookie, {
        method: 'POST',
        path: '/api/me/ai/numbers/buy',
        body: {}
      });
      if (buyResp.status !== 200 || buyResp.data?.success !== true) {
        throw new Error(`Buy number failed: status=${buyResp.status} body=${safeJson(buyResp.data).slice(0, 800)}`);
      }

      const numberId = buyResp.data?.data?.id;
      if (!numberId) throw new Error('Buy number succeeded but response missing number id');

      const assignResp = await apiJson(baseUrl, cookie, {
        method: 'POST',
        path: `/api/me/ai/numbers/${encodeURIComponent(String(numberId))}/assign`,
        body: { agent_id: agentId }
      });
      if (assignResp.status !== 200 || assignResp.data?.success !== true) {
        throw new Error(`Assign number failed: status=${assignResp.status} body=${safeJson(assignResp.data).slice(0, 800)}`);
      }

      const unassignResp = await apiJson(baseUrl, cookie, {
        method: 'POST',
        path: `/api/me/ai/numbers/${encodeURIComponent(String(numberId))}/unassign`,
        body: {}
      });
      if (unassignResp.status !== 200 || unassignResp.data?.success !== true) {
        throw new Error(`Unassign number failed: status=${unassignResp.status} body=${safeJson(unassignResp.data).slice(0, 800)}`);
      }
    }

    // Delete agent (cleans up Pipecat resources)
    const delResp = await apiJson(baseUrl, cookie, {
      method: 'DELETE',
      path: `/api/me/ai/agents/${encodeURIComponent(String(agentId))}`
    });

    if (delResp.status !== 200 || delResp.data?.success !== true) {
      throw new Error(`Delete agent failed: status=${delResp.status} body=${safeJson(delResp.data).slice(0, 800)}`);
    }

    console.log('AI smoke test: OK');
    console.log(`- Server: ${baseUrl}`);
    console.log(`- Created temp user id=${tempUser.userId} username=${tempUser.username}`);
    console.log(`- Created + updated + listed + deleted agent id=${agentId}`);

    // Success
    process.exitCode = 0;
  } catch (e) {
    const info = summarizeAxiosFailure(e);
    console.error('AI smoke test: FAILED');
    console.error(info.message);
    if (info.status) console.error('HTTP status:', info.status);
    if (info.data != null) console.error('Response:', safeJson(info.data).slice(0, 1200));

    // If server failed, show tail logs (safe) to help debug.
    try {
      const logs = server.getLogs();
      const tail = (logs.stderr || logs.stdout || '').slice(-2000);
      if (tail) {
        console.error('--- server log tail ---');
        console.error(tail);
      }
    } catch {}

    process.exitCode = 1;
  } finally {
    // Cleanup DB user (cascades local rows). Agent cleanup is done via DELETE endpoint above.
    try {
      if (db && tempUser?.userId) {
        await deleteTempUser(db, tempUser.userId);
      }
    } catch (e) {
      console.error('Cleanup warning: failed to delete temp user:', e?.message || e);
    }

    try {
      if (db) await db.end();
    } catch {}

    if (!keepServer) {
      try {
        if (server?.child && !server.child.killed) {
          server.child.kill();
        }
      } catch {}
    } else {
      console.log('Keeping server running because --keep-server was provided.');
    }
  }
}

main().catch((e) => {
  console.error('Fatal error:', e?.message || e);
  process.exitCode = 1;
});

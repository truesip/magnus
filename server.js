// Load .env.local first (for local development), fallback to .env
const fs = require('fs');
const path = require('path');
const envLocalPath = path.join(__dirname, '.env.local');
if (fs.existsSync(envLocalPath)) {
  require('dotenv').config({ path: envLocalPath });
  console.log('Loaded environment from .env.local');
} else {
  require('dotenv').config();
}
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const https = require('https');
const zlib = require('zlib');
const mysql = require('mysql2/promise');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 8080;
const DEBUG = process.env.DEBUG === '1' || process.env.LOG_LEVEL === 'debug';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-change-this';
const MB_SIP_MODULE = process.env.MB_SIP_MODULE || 'sip';

const MB_CDR_MODULE = process.env.MB_CDR_MODULE || 'call';
const MB_PAGE_SIZE = parseInt(process.env.MB_PAGE_SIZE || '50', 10);
// Background MagnusBilling CDR import tuning
const MB_CDR_IMPORT_PAGE_SIZE = parseInt(process.env.MB_CDR_IMPORT_PAGE_SIZE || '500', 10);
const MB_CDR_IMPORT_MAX_PAGES = parseInt(process.env.MB_CDR_IMPORT_MAX_PAGES || '20', 10);
// When no prior import cursor exists, look back this many minutes for initial backfill
const MB_CDR_IMPORT_LOOKBACK_MINUTES = parseInt(process.env.MB_CDR_IMPORT_LOOKBACK_MINUTES || '1440', 10); // default 24h
// If a user has no new CDRs in the queried window, advance their cursor close to "now"
// to avoid repeatedly scanning the same foreign-user pages.
const MB_CDR_IMPORT_EMPTY_ADVANCE_SLACK_SECONDS = parseInt(process.env.MB_CDR_IMPORT_EMPTY_ADVANCE_SLACK_SECONDS || '300', 10);
const CHECKOUT_MIN_AMOUNT = parseFloat(process.env.CHECKOUT_MIN_AMOUNT || '100');
const CHECKOUT_MAX_AMOUNT = parseFloat(process.env.CHECKOUT_MAX_AMOUNT || '500');

// Inbound call billing (flat rates expressed per minute, billed per second)
// Defaults: Local $0.025/min equivalent, Toll-Free $0.03/min equivalent
const INBOUND_LOCAL_RATE_PER_MIN = parseFloat(process.env.INBOUND_LOCAL_RATE_PER_MIN || '0.025') || 0.025;
const INBOUND_TOLLFREE_RATE_PER_MIN = parseFloat(process.env.INBOUND_TOLLFREE_RATE_PER_MIN || '0.03') || 0.03;
app.set('trust proxy', 1);
app.set('etag', false);
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';

// Reusable HTTPS agent for MagnusBilling API calls (connection pooling)
const magnusBillingAgent = new https.Agent({
  rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1',
  ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}),
  keepAlive: true,
  keepAliveMsecs: 1000,
  maxSockets: 50,
  maxFreeSockets: 10
});

function joinUrl(base, p) {
  if (!base) return p || '';
  let b = String(base);
  let s = String(p || '');
  if (b.endsWith('/')) b = b.slice(0, -1);
  if (s && !s.startsWith('/')) s = '/' + s;
  return b + s;
}

function passwordIsAlnum(pwd) {
  return /^[A-Za-z0-9]+$/.test(String(pwd || ''));
}
function usernameIsDigitsMin10(u){
  return /^\d{10,}$/.test(String(u||''));
}
function usernameIsAlnumMax10(u){
  return /^[A-Za-z0-9]{1,10}$/.test(String(u||''));
}
function passwordIsAlnumMax10(pwd){
  return /^[A-Za-z0-9]{1,10}$/.test(String(pwd||''));
}
function buildNonce() {
  const nowSec = Math.floor(Date.now() / 1000);
  const micro = String(Number(process.hrtime.bigint() % 1000000n)).padStart(6, '0');
  return `${nowSec}${micro}`;
}
async function mbSignedCall({ relPath, params, httpsAgent, hostHeader, validateStatus }) {
  const apiKey = process.env.MAGNUSBILLING_API_KEY;
  const apiSecret = process.env.MAGNUSBILLING_API_SECRET;
  const magnusBillingUrl = process.env.MAGNUSBILLING_URL;
  if (!apiKey || !apiSecret || !magnusBillingUrl) throw new Error('MagnusBilling credentials missing');
  const p = params instanceof URLSearchParams ? params : new URLSearchParams(params || {});
  if (!p.get('nonce')) p.append('nonce', buildNonce());
  const postData = p.toString();
  const sign = crypto.createHmac('sha512', apiSecret).update(postData).digest('hex');
  const url = joinUrl(magnusBillingUrl, relPath);
  return axios.post(url, postData, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(hostHeader ? { 'Host': hostHeader } : {}), 'Key': apiKey, 'Sign': sign },
    httpsAgent,
    timeout: 30000,
    validateStatus: validateStatus || (()=>true)
  });
}
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (DEBUG) console.warn('[auth.fail]', { sid: req.sessionID, hasSession: !!req.session, userId: req.session?.userId });
  return res.redirect('/login');
}
const PREFETCH_DAYS = parseInt(process.env.CDR_PREFETCH_DAYS || '7', 10);
function ymd(d){ return new Date(d.getTime() - d.getTimezoneOffset()*60000).toISOString().slice(0,10); }
function defaultRange(){ const now=new Date(); const from=new Date(now.getTime()-(PREFETCH_DAYS-1)*86400000); return { from: ymd(from), to: ymd(now) }; }
async function fetchSipUsers({ idUser, httpsAgent, hostHeader }){
  const p = new URLSearchParams();
  p.append('module', MB_SIP_MODULE); p.append('action','read'); p.append('start','0'); p.append('limit', String(Math.max(50, MB_PAGE_SIZE)));
  if (idUser) { p.append('id_user', String(idUser)); p.append('idUser', String(idUser)); p.append('userid', String(idUser)); }
  const path = `/index.php/${MB_SIP_MODULE}/read`;
  const resp = await mbSignedCall({ relPath: path, params: p, httpsAgent, hostHeader });
  return resp.data;
}
async function fetchUser({ idUser, httpsAgent, hostHeader }){
  const p = new URLSearchParams();
  p.append('module', 'user'); p.append('action','read'); p.append('start','0'); p.append('limit','1');
  if (idUser) { p.append('id_user', String(idUser)); p.append('idUser', String(idUser)); p.append('userid', String(idUser)); }
  const resp = await mbSignedCall({ relPath: '/index.php/user/read', params: p, httpsAgent, hostHeader });
  return resp.data;
}
// Fetch user row with client-side filtering (MagnusBilling API doesn't filter properly with admin creds)
async function fetchUserRow({ idUser, username, email, httpsAgent, hostHeader }){
  try {
    // Fetch multiple users without filters, then filter client-side
    const params = new URLSearchParams();
    params.append('module','user'); 
    params.append('action','read'); 
    params.append('start','0'); 
    params.append('limit','100'); // Fetch more users to find the right one
    
    if (DEBUG) console.log('[fetchUserRow] Fetching users for client-side filter:', { idUser, username, email });
    const resp = await mbSignedCall({ relPath: '/index.php/user/read', params, httpsAgent, hostHeader });
    const allUsers = resp?.data?.rows || resp?.data?.data || [];
    
    if (DEBUG) {
      console.log('[fetchUserRow] Got users:', { total: allUsers.length, userIds: allUsers.map(u => u.id_user || u.id).slice(0, 10) });
      if (allUsers.length > 0) {
        console.log('[fetchUserRow] Sample user:', JSON.stringify(allUsers[0]).substring(0, 500));
      }
    }
    
    // Find the user that matches our criteria
    const row = allUsers.find(r => belongsToUser(r, idUser, username, email));
    
    if (row && DEBUG) {
      console.log('[fetchUserRow] Found matching user:', { id: row.id_user || row.id, username: row.username, id_group: row.id_group });
    } else if (DEBUG) {
      console.warn('[fetchUserRow] No matching user found:', { searchingFor: { idUser, username, email } });
    }
    
    return row;
  } catch (e) { 
    if (DEBUG) console.log('[fetchUserRow] Fetch failed:', e.message); 
    return undefined;
  }
}
async function fetchCdr({ idUser, username, from, to, httpsAgent, hostHeader, start = 0, limit }){
  const p = new URLSearchParams();
  const pageLimit = limit != null ? Number(limit) || MB_PAGE_SIZE : MB_PAGE_SIZE;
  p.append('module', MB_CDR_MODULE);
  p.append('action','read');
  p.append('start', String(start));
  p.append('limit', String(pageLimit));
  if (idUser) { p.append('id_user', String(idUser)); p.append('idUser', String(idUser)); p.append('userid', String(idUser)); }
  if (username) { p.append('username', String(username)); p.append('user', String(username)); }
  if (from) { p.append('startdate', from); p.append('starttime', from); p.append('date_from', from); }
  if (to) { p.append('stopdate', to); p.append('stoptime', to); p.append('date_to', to); }
  const path = `/index.php/${MB_CDR_MODULE}/read`;
  const resp = await mbSignedCall({ relPath: path, params: p, httpsAgent, hostHeader });
  return resp.data;
}
// Format JS Date to MagnusBilling-compatible "YYYY-MM-DD HH:MM:SS" in local time
function formatMagnusDateTime(d) {
  const pad = (n) => String(n).padStart(2, '0');
  const year = d.getFullYear();
  const month = pad(d.getMonth() + 1);
  const day = pad(d.getDate());
  const hours = pad(d.getHours());
  const mins = pad(d.getMinutes());
  const secs = pad(d.getSeconds());
  return `${year}-${month}-${day} ${hours}:${mins}:${secs}`;
}
function belongsToUser(row, idUser, username, email){
  const idStr = String(idUser || '');
  // Generic helper used mainly for /user endpoint lookups. For CDRs we use
  // cdrRowBelongsToUser instead so we don't accidentally treat row.id (CDR ID)
  // as a user identifier.
  const idMatches = idStr && [row?.id, row?.user_id, row?.uid, row?.id_user, row?.idUser, row?.userid].some(v => String(v||'') === idStr);
  const u = (username||'').toString().toLowerCase();
  const userMatches = u && [row?.username, row?.name, row?.sipuser, row?.user].some(v => String(v||'').toLowerCase() === u);
  const em = (email||'').toString().toLowerCase();
  const emailMatches = em && [row?.email, row?.mail, row?.user_email].some(v => String(v||'').toLowerCase() === em);
  return Boolean(idMatches || userMatches || emailMatches);
}
// CDR-specific ownership check. Magnus CDR rows often include per-call
// id_user plus helper fields like accountcode and idUserusername. We avoid
// looking at row.id here because that's the CDR primary key, not the user.
function cdrRowBelongsToUser(row, idUser, username, email){
  const idStr = String(idUser || '');
  const u = (username||'').toString().toLowerCase();
  const em = (email||'').toString().toLowerCase();

  const idMatches = idStr && [
    row?.id_user,
    row?.user_id,
    row?.uid,
    row?.idUser,
    row?.userid
  ].some(v => String(v || '') === idStr);

  const userMatches = u && [
    row?.username,
    row?.name,
    row?.sipuser,
    row?.user,
    row?.accountcode,
    row?.idUserusername
  ].some(v => String(v || '').toLowerCase() === u);

  const emailMatches = em && [row?.email, row?.mail, row?.user_email].some(v => String(v||'').toLowerCase() === em);

  return Boolean(idMatches || userMatches || emailMatches);
}

function extractMagnusUserIdFromCdrRow(row) {
  const v = row?.id_user ?? row?.user_id ?? row?.uid ?? row?.idUser ?? row?.userid;
  const s = String(v || '').trim();
  return s;
}
// Strict SIP ownership check: require row id_user to equal current id
function sipBelongsToUser(row, idUser){
  const idStr = String(idUser || '');
  return Boolean(idStr && [row?.id_user, row?.idUser, row?.userid, row?.user_id].some(v => String(v||'') === idStr));
}
// Redact sensitive SIP fields for logging
function redactSipRow(row){
  if (!row || typeof row !== 'object') return row;
  const clone = { ...row };
  for (const key of ['secret','sippasswd','password']) {
    if (key in clone) clone[key] = '***REDACTED***';
  }
  return clone;
}
// Resolve MagnusBilling user id when missing by querying upstream; cache in session and DB
async function ensureMagnusUserId(req, { httpsAgent, hostHeader }) {
  // First, try to get the Magnus user ID from local database
  let storedMagnusId = '';
  if (pool && req.session.userId) {
    try {
      const [rows] = await pool.execute('SELECT magnus_user_id FROM signup_users WHERE id=? LIMIT 1', [req.session.userId]);
      if (rows && rows[0] && rows[0].magnus_user_id) {
        storedMagnusId = String(rows[0].magnus_user_id);
        if (DEBUG) console.log('[ensureMagnusUserId] Found stored Magnus ID:', { localUserId: req.session.userId, magnusUserId: storedMagnusId });
      }
    } catch (e) { if (DEBUG) console.warn('[ensureMagnusUserId] DB lookup failed:', e.message); }
  }
  
  // If we have a stored Magnus ID, use it
  if (storedMagnusId) {
    if (req.session.magnusUserId !== storedMagnusId) {
      req.session.magnusUserId = storedMagnusId;
      try { await new Promise((res)=>req.session.save(()=>res())); } catch {}
    }
    return storedMagnusId;
  }
  
  // Fallback: fetch from MagnusBilling (this may not work if usernames don't match)
  try {
    const row = await fetchUserRow({ username: req.session.username, email: req.session.email, httpsAgent, hostHeader });
    const foundId = row?.id_user || row?.id || row?.user_id || row?.uid || '';
    if (foundId) {
      const idUser = String(foundId);
      if (DEBUG) console.log('[ensureMagnusUserId] Found from MagnusBilling:', { username: req.session.username, magnusUserId: idUser });
      req.session.magnusUserId = idUser;
      // Persist mapping locally
      try { await saveUserRow({ magnusUserId: idUser, username: req.session.username, email: req.session.email }); } catch {}
      try { await new Promise((res)=>req.session.save(()=>res())); } catch {}
      return idUser;
    }
  } catch (e) { if (DEBUG) console.warn('ensureMagnusUserId MagnusBilling lookup failed', e.message || e); }
  
  // Last resort: use cached session value
  return (req.session && req.session.magnusUserId) ? String(req.session.magnusUserId) : '';
}
async function prefetchUserData(req){
  try {
    const httpsAgent = magnusBillingAgent;
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
    const idUser = await ensureMagnusUserId(req, { httpsAgent, hostHeader });
    const username = req.session.username;
    const rng = defaultRange();

    // Only prefetch SIP users for this Magnus account. We no longer prefetch
    // CDRs from MagnusBilling at login; all CDR history is served from the
    // local mirrors (user_did_cdrs + user_mb_cdrs) populated by background
    // importers.
    const sipsData = await fetchSipUsers({ idUser, httpsAgent, hostHeader });
    const rawSipRows = (sipsData?.rows || sipsData?.data || []);
    const sipsRows = (idUser
      ? rawSipRows.filter(r => sipBelongsToUser(r, idUser))
      : rawSipRows.filter(r => belongsToUser(r, idUser, username, req.session.email))
    );
    const sips = { rows: sipsRows };

    req.session.prefetch = { range: rng, sips, fetchedAt: Date.now() };
    console.log('[me.prefetch]', { userId: idUser || null, username, sipRows: sipsRows.length });
  } catch (e) { console.warn('prefetch failed', e.message || e); }
}



// Views + Sessions + Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// Session configuration; store will be attached after initDb() creates sessionStore
const sessionConfig = {
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    // In dev over HTTP, set COOKIE_SECURE=0 (default). In prod behind HTTPS, set COOKIE_SECURE=1
    secure: COOKIE_SECURE,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
};
let sessionMiddleware;
app.use((req, res, next) => {
  // sessionMiddleware is created in startServer() after DB init.
  // As a safety net, if it is somehow missing, fall back to a
  // MemoryStore-backed session with a warning.
  if (!sessionMiddleware) {
    if (DEBUG) console.warn('[session] Session middleware used before DB init; falling back to MemoryStore');
    sessionMiddleware = session(sessionConfig);
  }
  return sessionMiddleware(req, res, next);
});
// Capture raw JSON body (for IPN signature verification, etc.)
// NOTE: We skip JSON parsing for the DIDWW CDR webhook so we can handle
// newline-delimited JSON (NDJSON) and optional gzip compression manually.
app.use((req, res, next) => {
  if (req.path === '/webhooks/didww/voice-in-cdr') return next();
  return bodyParser.json({
    verify: (req, res, buf) => {
      // Store raw body buffer for routes that need HMAC verification (e.g., NOWPayments IPN)
      req.rawBody = buf;
    }
  })(req, res, next);
});
app.use(bodyParser.urlencoded({ extended: true }));
// Lightweight request logging (always on). Logs when the response finishes.
app.use((req, res, next) => {
  const t0 = process.hrtime.bigint();
  const wantsLog = req.path.startsWith('/api/') || req.path === '/login' || req.path === '/dashboard';
  const redact = (obj)=>{
    try {
      const c = Object.assign({}, obj||{});
      if ('password' in c) c.password='***';
      if ('secret' in c) c.secret='***';
      if ('api_key' in c) c.api_key='***';
      if ('code' in c) c.code='***';
      if ('token' in c) c.token='***';
      return c;
    } catch {
      return {};
    }
  };
  res.on('finish', () => {
    if (!wantsLog) return;
    const ms = Number(process.hrtime.bigint() - t0)/1e6;
    const line = {
      at: new Date().toISOString(),
      status: res.statusCode,
      method: req.method,
      path: req.path,
      query: req.query || {},
      body: (req.method==='POST'||req.method==='PUT'||req.method==='PATCH') ? redact(req.body) : undefined,
      ms: Number(ms.toFixed(1))
    };
    try { console.log('[req]', JSON.stringify(line)); } catch {}
  });
  next();
});
// Prevent caching on user-scoped/admin API responses to avoid cross-user data
function noCache(res) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Vary', 'Cookie');
}
app.use('/api/me', (req, res, next) => { noCache(res); next(); });
app.use('/api/admin', (req, res, next) => { noCache(res); next(); });

// Email verification store (MySQL)
const OTP_TTL_MS = (parseInt(process.env.EMAIL_VERIFICATION_TTL_MINUTES) || 10) * 60 * 1000;
const OTP_MAX_ATTEMPTS = parseInt(process.env.OTP_MAX_ATTEMPTS || '5', 10);
function otp() { return String(Math.floor(100000 + Math.random() * 900000)); }
function sha256(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }
let pool;
let sessionStore;

// Basic rate limits (per IP)
// Login: allow moderate retries without being too strict (20 per 15 minutes)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many login attempts. Please try again later.' }
});

// OTP-related endpoints
// - Sending codes must be strict (prevents email flooding)
// - Verifying codes can be more lenient (attempts are also limited per token in DB)
const otpSendLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many verification code requests. Please try again later.' }
});
const otpVerifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many verification attempts. Please try again later.' }
});
async function initDb() {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) return; // DB optional; if missing, endpoints will throw when used
  const u = new URL(dsn);
  const dbName = u.pathname.replace(/^\//, '');
  // TLS options
  const sslMode = (u.searchParams.get('ssl-mode') || u.searchParams.get('sslmode') || '').toUpperCase();
  const caPath = process.env.DATABASE_CA_CERT;
  let sslOptions;
  if (caPath && fs.existsSync(caPath)) {
    sslOptions = { ca: fs.readFileSync(caPath, 'utf8'), rejectUnauthorized: true };
  } else if (sslMode === 'REQUIRED') {
    sslOptions = { rejectUnauthorized: false }; // encrypted, non-verified fallback
  }

  pool = mysql.createPool({
    host: u.hostname,
    port: Number(u.port) || 3306,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: dbName,
    ssl: sslOptions,
    connectionLimit: 50,
    waitForConnections: true,
    queueLimit: 0
  });
  
  // Initialize MySQL session store
  sessionStore = new MySQLStore({
    clearExpired: true,
    checkExpirationInterval: 900000, // 15 minutes
    expiration: 86400000 * 7, // 7 days
    createDatabaseTable: true,
    schema: {
      tableName: 'sessions',
      columnNames: {
        session_id: 'session_id',
        expires: 'expires',
        data: 'data'
      }
    }
  }, pool.pool);
  await pool.query(`CREATE TABLE IF NOT EXISTS email_verifications (
    token VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    code_hash CHAR(64) NOT NULL,
    expires_at BIGINT NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    attempts INT NOT NULL DEFAULT 0,
    username VARCHAR(80) NOT NULL,
    password VARCHAR(255) NOT NULL,
    firstname VARCHAR(80) NOT NULL,
    lastname VARCHAR(80) NOT NULL,
    phone VARCHAR(40) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  // Ensure email_verifications.password is large enough for bcrypt hashes and attempts column exists
  try {
    const [pwdCol] = await pool.query(
      "SELECT CHARACTER_MAXIMUM_LENGTH AS len FROM information_schema.columns WHERE table_schema=? AND table_name='email_verifications' AND column_name='password' LIMIT 1",
      [dbName]
    );
    const col = pwdCol && pwdCol[0];
    if (!col || (col.len != null && col.len < 60)) {
      try {
        await pool.query('ALTER TABLE email_verifications MODIFY COLUMN password VARCHAR(255) NOT NULL');
        if (DEBUG) console.log('[schema] Upgraded email_verifications.password to VARCHAR(255) for bcrypt hashes');
      } catch (e) {
        if (DEBUG) console.warn('[schema] Failed to alter email_verifications.password length:', e.message || e);
      }
    }
    // Ensure attempts column exists for per-token OTP attempt tracking
    try {
      const [attemptCol] = await pool.query(
        "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='email_verifications' AND column_name='attempts' LIMIT 1",
        [dbName]
      );
      if (!attemptCol || !attemptCol.length) {
        await pool.query('ALTER TABLE email_verifications ADD COLUMN attempts INT NOT NULL DEFAULT 0 AFTER used');
        if (DEBUG) console.log('[schema] Added email_verifications.attempts column');
      }
    } catch (e) {
      if (DEBUG) console.warn('[schema] email_verifications.attempts check failed', e.message || e);
    }
  } catch (e) {
    if (DEBUG) console.warn('[schema] email_verifications.password length check failed', e.message || e);
  }
  await pool.query(`CREATE TABLE IF NOT EXISTS signup_users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    magnus_user_id VARCHAR(64) NULL,
    username VARCHAR(80) NOT NULL,
    email VARCHAR(255) NOT NULL,
    firstname VARCHAR(80) NULL,
    lastname VARCHAR(80) NULL,
    phone VARCHAR(40) NULL,
    password_hash VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_username (username),
    UNIQUE KEY uniq_email (email)
  )`);
  // User trunks table - stores DIDWW trunk ownership per user
  await pool.query(`CREATE TABLE IF NOT EXISTS user_trunks (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    didww_trunk_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    dst VARCHAR(32) NULL,
    description TEXT NULL,
    capacity_limit INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_didww_trunk (didww_trunk_id),
    KEY idx_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // User DIDs table - stores purchased phone numbers per user
  await pool.query(`CREATE TABLE IF NOT EXISTS user_dids (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    didww_did_id VARCHAR(64) NOT NULL,
    did_number VARCHAR(32) NOT NULL,
    country VARCHAR(64) NULL,
    region VARCHAR(64) NULL,
    city VARCHAR(64) NULL,
    did_type VARCHAR(32) NULL,
    monthly_price DECIMAL(10,4) NULL,
    setup_price DECIMAL(10,4) NULL,
    trunk_id VARCHAR(64) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_didww_did (didww_did_id),
    KEY idx_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // DID markup tracking table - stores last billed cycle per DID per user (for reporting/debugging)
  await pool.query(`CREATE TABLE IF NOT EXISTS user_did_markups (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    didww_did_id VARCHAR(64) NOT NULL,
    last_billed_to DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_user_did (user_id, didww_did_id),
    KEY idx_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // DID markup cycles table - enforces at-most-once billing per (user, DID, billing period)
  await pool.query(`CREATE TABLE IF NOT EXISTS user_did_markup_cycles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    didww_did_id VARCHAR(64) NOT NULL,
    billed_to DATETIME NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_user_did_cycle (user_id, didww_did_id, billed_to),
    KEY idx_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // Per-DID CDR history table - stores inbound CDRs streamed from DIDWW per user/DID
  await pool.query(`CREATE TABLE IF NOT EXISTS user_did_cdrs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    cdr_id VARCHAR(64) NOT NULL,
    user_id BIGINT NULL,
    did_number VARCHAR(32) NOT NULL,
    direction VARCHAR(16) NOT NULL DEFAULT 'inbound',
    src_number VARCHAR(64) NULL,
    dst_number VARCHAR(64) NULL,
    time_start DATETIME NULL,
    time_connect DATETIME NULL,
    time_end DATETIME NULL,
    duration INT NULL,
    billsec INT NULL,
    price DECIMAL(18,8) NULL,
    raw_cdr JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_cdr_id (cdr_id),
    KEY idx_user_id (user_id),
    KEY idx_did_number (did_number),
    CONSTRAINT fk_user_did_cdrs_user FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE SET NULL
  )`);
  // Per-user outbound CDR history table - stores normalized MagnusBilling CDRs per user
  await pool.query(`CREATE TABLE IF NOT EXISTS user_mb_cdrs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    cdr_id VARCHAR(64) NOT NULL,
    user_id BIGINT NOT NULL,
    magnus_user_id VARCHAR(64) NOT NULL,
    direction VARCHAR(16) NOT NULL DEFAULT 'outbound',
    src_number VARCHAR(64) NULL,
    dst_number VARCHAR(64) NULL,
    did_number VARCHAR(32) NULL,
    time_start DATETIME NULL,
    duration INT NULL,
    billsec INT NULL,
    price DECIMAL(18,8) NULL,
    raw_cdr JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_mb_cdr (cdr_id),
    KEY idx_mb_user (user_id),
    KEY idx_mb_magnus_user (magnus_user_id),
    KEY idx_mb_time_start (time_start),
    CONSTRAINT fk_user_mb_cdrs_user FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // CDR import cursors - tracks last imported MagnusBilling CDR timestamp per magnus_user_id
  await pool.query(`CREATE TABLE IF NOT EXISTS cdr_import_cursors (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    magnus_user_id VARCHAR(64) NOT NULL,
    last_time_start_ms BIGINT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_magnus (magnus_user_id)
  )`);
  // Ensure uniq_user_did_cycle index exists even if table was created on an older schema
  try {
    const [cycleIdx] = await pool.query(
      "SELECT 1 FROM information_schema.statistics WHERE table_schema=? AND table_name='user_did_markup_cycles' AND index_name='uniq_user_did_cycle' LIMIT 1",
      [dbName]
    );
    if (!cycleIdx || !cycleIdx.length) {
      try {
        await pool.query('ALTER TABLE user_did_markup_cycles ADD UNIQUE KEY uniq_user_did_cycle (user_id, didww_did_id, billed_to)');
      } catch (e) {
        if (DEBUG) console.warn('[schema] Failed to add uniq_user_did_cycle index:', e.message || e);
      }
    }
  } catch (e) {
    if (DEBUG) console.warn('[schema] Failed to verify uniq_user_did_cycle index:', e.message || e);
  }
  // Billing history table - records user refills/credits
  await pool.query(`CREATE TABLE IF NOT EXISTS billing_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    amount DECIMAL(18,8) NOT NULL,
    description VARCHAR(255) NULL,
    status ENUM('pending', 'completed', 'failed') NOT NULL DEFAULT 'completed',
    magnus_response TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_billing_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // Pending orders table - tracks DIDWW orders that haven't completed yet
  await pool.query(`CREATE TABLE IF NOT EXISTS pending_orders (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    order_id VARCHAR(64) NOT NULL,
    reconciled TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_order (order_id),
    KEY idx_pending_user (user_id),
    FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // DID purchase receipts table - enforces at-most-once customer receipt per (user, order)
  await pool.query(`CREATE TABLE IF NOT EXISTS did_purchase_receipts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    order_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_user_order (user_id, order_id),
    KEY idx_receipt_user (user_id),
    FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // NOWPayments payments table - tracks crypto payments and credits
  await pool.query(`CREATE TABLE IF NOT EXISTS nowpayments_payments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    payment_id VARCHAR(128) NOT NULL,
    order_id VARCHAR(191) NOT NULL,
    price_amount DECIMAL(18,8) NOT NULL,
    price_currency VARCHAR(16) NOT NULL DEFAULT 'usd',
    pay_amount DECIMAL(36,18) NULL,
    pay_currency VARCHAR(32) NULL,
    payment_status VARCHAR(64) NOT NULL DEFAULT 'pending',
    credited TINYINT(1) NOT NULL DEFAULT 0,
    raw_payload JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_payment_id (payment_id),
    KEY idx_np_user (user_id),
    KEY idx_np_order (order_id),
    FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // Square payments table - tracks card payments (Square Payment Links) and credits
  await pool.query(`CREATE TABLE IF NOT EXISTS square_payments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    payment_link_id VARCHAR(128) NOT NULL,
    order_id VARCHAR(191) NOT NULL,
    square_order_id VARCHAR(128) NULL,
    square_payment_id VARCHAR(128) NULL,
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(16) NOT NULL DEFAULT 'USD',
    status VARCHAR(64) NOT NULL DEFAULT 'pending',
    credited TINYINT(1) NOT NULL DEFAULT 0,
    raw_payload JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_payment_link (payment_link_id),
    KEY idx_sq_user (user_id),
    KEY idx_sq_order (square_order_id),
    KEY idx_sq_local_order (order_id),
    FOREIGN KEY (user_id) REFERENCES signup_users(id) ON DELETE CASCADE
  )`);
  // One-time migration: drop legacy per-user API columns if present and add password_hash if missing
  try {
    const toDrop = ['api_key','api_secret'];
    for (const c of toDrop) {
      const [rows] = await pool.query(
        'SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name=\'signup_users\' AND column_name=? LIMIT 1',
        [dbName, c]
      );
      if (rows && rows.length) {
        try { await pool.query(`ALTER TABLE signup_users DROP COLUMN ${c}`); } catch (e) { if (DEBUG) console.warn('Schema drop failed', c, e.message || e); }
      }
    }
    const [hasPwd] = await pool.query(
      'SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name=\'signup_users\' AND column_name=\'password_hash\' LIMIT 1',
      [dbName]
    );
    if (!hasPwd || !hasPwd.length) {
      try { await pool.query('ALTER TABLE signup_users ADD COLUMN password_hash VARCHAR(255) NULL AFTER phone'); } catch (e) { if (DEBUG) console.warn('Add password_hash failed', e.message || e); }
    }
    // Add dst column to user_trunks if missing
    const [hasDst] = await pool.query(
      'SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name=\'user_trunks\' AND column_name=\'dst\' LIMIT 1',
      [dbName]
    );
    if (!hasDst || !hasDst.length) {
      try { await pool.query('ALTER TABLE user_trunks ADD COLUMN dst VARCHAR(32) NULL AFTER name'); } catch (e) { if (DEBUG) console.warn('Add dst column failed', e.message || e); }
    }

    // Drop legacy user_sms_trunks table now that SMS forwarding is removed
    try {
      const [hasSmsTable] = await pool.query(
        'SELECT 1 FROM information_schema.tables WHERE table_schema=? AND table_name=\'user_sms_trunks\' LIMIT 1',
        [dbName]
      );
      if (hasSmsTable && hasSmsTable.length) {
        if (DEBUG) console.log('[schema] Dropping legacy table user_sms_trunks');
        await pool.query('DROP TABLE IF EXISTS user_sms_trunks');
      }
    } catch (e) {
      if (DEBUG) console.warn('[schema] Failed to drop user_sms_trunks:', e.message || e);
    }

    // Ensure inbound CDR billing columns exist on user_did_cdrs
    try {
      const [hasCdrBilled] = await pool.query(
        'SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name=\'user_did_cdrs\' AND column_name=\'billed\' LIMIT 1',
        [dbName]
      );
      if (!hasCdrBilled || !hasCdrBilled.length) {
        try { await pool.query('ALTER TABLE user_did_cdrs ADD COLUMN billed TINYINT(1) NOT NULL DEFAULT 0 AFTER price'); } catch (e) { if (DEBUG) console.warn('Add billed column to user_did_cdrs failed', e.message || e); }
      }
      const [hasCdrBillingId] = await pool.query(
        'SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name=\'user_did_cdrs\' AND column_name=\'billing_history_id\' LIMIT 1',
        [dbName]
      );
      if (!hasCdrBillingId || !hasCdrBillingId.length) {
        try { await pool.query('ALTER TABLE user_did_cdrs ADD COLUMN billing_history_id BIGINT NULL AFTER billed'); } catch (e) { if (DEBUG) console.warn('Add billing_history_id column to user_did_cdrs failed', e.message || e); }
      }
    } catch (e) {
      if (DEBUG) console.warn('[schema] Inbound CDR billing column check failed', e.message || e);
    }

    // Ensure billing_history.amount has enough precision for small per-second charges
    try {
      const [amountCol] = await pool.query(
        "SELECT NUMERIC_SCALE AS scale, NUMERIC_PRECISION AS prec FROM information_schema.columns WHERE table_schema=? AND table_name='billing_history' AND column_name='amount' LIMIT 1",
        [dbName]
      );
      const col = amountCol && amountCol[0];
      // If scale < 4 or precision < 18, upgrade to DECIMAL(18,8)
      if (col && ((col.scale != null && col.scale < 4) || (col.prec != null && col.prec < 18))) {
        try {
          await pool.query('ALTER TABLE billing_history MODIFY COLUMN amount DECIMAL(18,8) NOT NULL');
          if (DEBUG) console.log('[schema] Upgraded billing_history.amount to DECIMAL(18,8)');
        } catch (e) {
          if (DEBUG) console.warn('[schema] Failed to alter billing_history.amount precision:', e.message || e);
        }
      }
    } catch (e) {
      if (DEBUG) console.warn('[schema] Billing_history.amount precision check failed:', e.message || e);
    }
  } catch (e) { if (DEBUG) console.warn('Schema check failed', e.message || e); }
}
async function storeVerification({ token, codeHash, email, expiresAt, fields }) {
  if (!pool) throw new Error('Database not configured');
  // Store plaintext password (legacy behavior). NOTE: less secure; consider encrypting in future.
  const plainPassword = String(fields.password || '');
  const sql = `INSERT INTO email_verifications (token,email,code_hash,expires_at,used,username,password,firstname,lastname,phone) VALUES (?,?,?,?,0,?,?,?,?,?)`;
  await pool.execute(sql, [token, email, codeHash, expiresAt, fields.username, plainPassword, fields.firstname, fields.lastname, fields.phone || null]);
}
async function fetchVerification(token) {
  if (!pool) throw new Error('Database not configured');
  const [rows] = await pool.execute('SELECT * FROM email_verifications WHERE token=?', [token]);
  return rows[0];
}
async function fetchVerificationLatestByEmail(email) {
  if (!pool) throw new Error('Database not configured');
  const [rows] = await pool.execute('SELECT * FROM email_verifications WHERE email=? AND used=0 AND expires_at>=? ORDER BY expires_at DESC LIMIT 1', [email, Date.now()]);
  return rows[0];
}
async function markVerificationUsed(token) {
  if (!pool) throw new Error('Database not configured');
  await pool.execute('UPDATE email_verifications SET used=1 WHERE token=?', [token]);
}
async function purgeExpired() {
  if (!pool) return; try { await pool.execute('DELETE FROM email_verifications WHERE expires_at < ? OR used=1', [Date.now()]); } catch {}
}
async function saveUserRow({ magnusUserId, username, email, firstname, lastname, phone, passwordHash = null }) {
  if (!pool) return;
  const sql = `INSERT INTO signup_users (magnus_user_id, username, email, firstname, lastname, phone, password_hash)
               VALUES (?,?,?,?,?,?,?)
               ON DUPLICATE KEY UPDATE magnus_user_id=VALUES(magnus_user_id), firstname=VALUES(firstname), lastname=VALUES(lastname), phone=VALUES(phone), password_hash=COALESCE(VALUES(password_hash), password_hash)`;
  await pool.execute(sql, [String(magnusUserId || ''), username, email, firstname || null, lastname || null, phone || null, passwordHash]);
}
async function checkAvailability({ username, email }) {
  if (!pool) return { usernameAvailable: true, emailAvailable: true };
  let usernameAvailable = true, emailAvailable = true;
  if (username) {
    const [r] = await pool.execute('SELECT 1 FROM signup_users WHERE username=? LIMIT 1', [username]);
    usernameAvailable = r.length === 0;
  }
  if (email) {
    const [r2] = await pool.execute('SELECT 1 FROM signup_users WHERE email=? LIMIT 1', [email]);
    emailAvailable = r2.length === 0;
  }
  return { usernameAvailable, emailAvailable };
}
async function sendVerificationEmail(toEmail, code) {
  const apiKey = process.env.SMTP2GO_API_KEY;
  const sender = process.env.SMTP2GO_SENDER || `no-reply@${(process.env.SENDER_DOMAIN || 'talkusa.net')}`;
  if (!apiKey) throw new Error('SMTP2GO_API_KEY missing');
  const subject = 'Your TalkUSA verification code';
  const minutes = Math.round(OTP_TTL_MS / 60000);
  const text = `Your verification code is ${code}. It expires in ${minutes} minutes.`;
  const html = `<p>Your verification code is <b>${code}</b>.</p><p>This code expires in ${minutes} minutes.</p>`;
  const payload = { api_key: apiKey, to: [toEmail], sender, subject, text_body: text, html_body: html };
  await axios.post('https://api.smtp2go.com/v3/email/send', payload, { timeout: 15000 });
}

async function sendWelcomeEmail(toEmail, username, sipDomain, portalUrl, password = '') {
  const apiKey = process.env.SMTP2GO_API_KEY;
  const sender = process.env.SMTP2GO_SENDER || `no-reply@${(process.env.SENDER_DOMAIN || 'talkusa.net')}`;
  if (!apiKey) throw new Error('SMTP2GO_API_KEY missing');
  const subject = 'Welcome to TalkUSA';
  const safePortal = portalUrl || (sipDomain ? `https://${sipDomain}/mbilling` : '');
  const text = `Welcome to TalkUSA!\n\nSIP Username: ${username}\nSIP Password: ${password}\nSIP Domain: ${sipDomain}\nPortal: ${safePortal}\n\nYou can now log in to manage your account.`;
  const html = `
  <div style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;\">\r
    <h2>Welcome to TalkUSA!</h2>\r
    <p>Your SIP account has been created.</p>\r
    <div style=\"background:#f7f7fb;border:1px solid #e5e7ef;border-radius:10px;padding:12px;max-width:460px;\">\r
      <p><b>SIP Username:</b> ${username}</p>\r
      <p><b>SIP Password:</b> ${password}</p>\r
      <p><b>SIP Domain:</b> ${sipDomain}</p>\r
    </div>\r
    ${safePortal ? `<p style=\"margin-top:14px;\"><a href=\"${safePortal}\" style=\"background:#4f46e5;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none;\">Log in to your portal</a></p>` : ''}\r
    <p style=\"color:#555;margin-top:18px;\">Keep your SIP password safe.</p>\r
  </div>`;
  const adminEmail = process.env.ADMIN_NOTIFY_EMAIL;
  const to = [toEmail].filter(Boolean);
  const payload = {
    api_key: apiKey,
    to,
    ...(adminEmail ? { bcc: [adminEmail] } : {}),
    sender,
    subject,
    text_body: text,
    html_body: html
  };
  await axios.post('https://api.smtp2go.com/v3/email/send', payload, { timeout: 15000 });
}

// Send a refill receipt email when funds are added
async function sendRefillReceiptEmail({ toEmail, username, amount, description }) {
  const apiKey = process.env.SMTP2GO_API_KEY;
  const sender = process.env.SMTP2GO_SENDER || `no-reply@${(process.env.SENDER_DOMAIN || 'talkusa.net')}`;
  if (!apiKey) throw new Error('SMTP2GO_API_KEY missing');
  const amt = Number(amount || 0);
  const safeUser = username || 'Customer';
  const subject = `Payment receipt - $${amt.toFixed(2)} added to your TalkUSA balance`;
  const text = `Hello ${safeUser},\n\nWe have received your payment of $${amt.toFixed(2)}.\nDescription: ${description}\n\nYou can view your updated balance in your TalkUSA portal.\n\nThank you for your business,\nTalkUSA`;
  const html = `
  <div style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;\">\r
    <h2>Payment receipt</h2>\r
    <p>Hello ${safeUser},</p>\r
    <p>We have received your payment of <strong>$${amt.toFixed(2)}</strong>.</p>\r
    <p><b>Description:</b> ${description}</p>\r
    <p style=\"margin-top:16px;\">You can log in to your TalkUSA portal to see your updated balance and billing history.</p>\r
    <p style=\"color:#555;margin-top:18px;\">Thank you for your business.</p>\r
  </div>`;
  const adminEmail = process.env.ADMIN_NOTIFY_EMAIL;
  const to = [toEmail].filter(Boolean);
  const payload = {
    api_key: apiKey,
    to,
    ...(adminEmail ? { bcc: [adminEmail] } : {}),
    sender,
    subject,
    text_body: text,
    html_body: html
  };
  await axios.post('https://api.smtp2go.com/v3/email/send', payload, { timeout: 15000 });
}

// Send a DID purchase receipt email when new numbers are purchased
// NOTE: This email only shows TalkUSA markup monthly pricing, not DIDWW wholesale amounts.
async function sendDidPurchaseReceiptEmail({ toEmail, displayName, items, totalAmount, orderReference }) {
  const apiKey = process.env.SMTP2GO_API_KEY;
  const sender = process.env.SMTP2GO_SENDER || `no-reply@${(process.env.SENDER_DOMAIN || 'talkusa.net')}`;
  if (!apiKey) throw new Error('SMTP2GO_API_KEY missing');

  const safeUser = displayName || 'Customer';
  const safeItems = Array.isArray(items) ? items : [];

  const primaryNumber = safeItems[0]?.number || '';
  const extraCount = Math.max(0, safeItems.length - 1);
  const subjectSuffix = primaryNumber
    ? extraCount > 0
      ? `${primaryNumber} + ${extraCount} more`
      : primaryNumber
    : `${safeItems.length} number(s)`;
  const subject = `Number purchase receipt - ${subjectSuffix}`;

  const numbersList = safeItems.length
    ? safeItems.map(item => {
        const num = item.number || '';
        const loc = item.location || 'Unknown location';
        const m = Number(item.monthlyPrice || 0);
        const s = Number(item.setupPrice || 0);
        const mFmt = `$${m.toFixed(2)}`;
        const sFmt = `$${s.toFixed(2)}`;
        return ` - ${num} — ${loc} — Monthly: ${mFmt}, Setup: ${sFmt}`;
      }).join('\n')
    : ' - (no numbers listed)';

  const orderLine = orderReference ? `Order: ${orderReference}\n` : '';

  const text = `Hello ${safeUser},\n\n` +
    `Thank you for your purchase. We have added the following number(s) to your TalkUSA account:\n\n` +
    `${numbersList}\n\n` +
    `These numbers will be billed at the TalkUSA monthly rates shown above.\n` +
    orderLine +
    `\nYou can now configure call routing for these numbers in your TalkUSA portal.\n\n` +
    `Thank you for your business,\nTalkUSA`;

  const htmlList = safeItems.length
    ? safeItems.map(item => {
        const num = item.number || '';
        const loc = item.location || 'Unknown location';
        const m = Number(item.monthlyPrice || 0);
        const s = Number(item.setupPrice || 0);
        const mFmt = `$${m.toFixed(2)}`;
        const sFmt = `$${s.toFixed(2)}`;
        return `<li><strong>${num}</strong>${loc ? ` — ${loc}` : ''} — Monthly: ${mFmt}, Setup: ${sFmt}</li>`;
      }).join('')
    : '<li>(no numbers listed)</li>';

  const html = `
  <div style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;\">\r
    <h2>Number purchase receipt</h2>\r
    <p>Hello ${safeUser},</p>\r
    <p>Thank you for your purchase. We have added the following number(s) to your TalkUSA account:</p>\r
    <ul>${htmlList}</ul>\r
    ${orderReference ? `<p><strong>Order:</strong> ${orderReference}</p>` : ''}\r
    <p style=\"margin-top:16px;\">These numbers will be billed at the TalkUSA monthly rates shown above.</p>\r
    <p style=\"margin-top:8px;\">You can now configure call routing for these numbers in your TalkUSA portal.</p>\r
    <p style=\"color:#555;margin-top:18px;\">Thank you for your business.</p>\r
  </div>`;

  // DID purchase receipts go only to the customer, not the admin.
  const to = [toEmail].filter(Boolean);
  const payload = {
    api_key: apiKey,
    to,
    sender,
    subject,
    text_body: text,
    html_body: html
  };
  await axios.post('https://api.smtp2go.com/v3/email/send', payload, { timeout: 15000 });
}

// Build location and pricing information for DID purchase receipt items
// NOTE: this uses TalkUSA markup prices (from env) rather than raw DIDWW prices.
function buildDidPurchaseLineItems(dids, included) {
  const citiesMap = {};
  const regionsMap = {};
  const countriesMap = {};
  const didGroupsMap = {};

  if (Array.isArray(included)) {
    for (const item of included) {
      if (!item || !item.id || !item.type) continue;
      if (item.type === 'cities') citiesMap[item.id] = item.attributes?.name || '';
      if (item.type === 'regions') regionsMap[item.id] = item.attributes?.name || '';
      if (item.type === 'countries') countriesMap[item.id] = item.attributes?.name || '';
      if (item.type === 'did_groups') didGroupsMap[item.id] = item;
    }
  }

  const result = [];
  if (!Array.isArray(dids)) return result;

  const localMarkup = parseFloat(process.env.DID_LOCAL_MONTHLY_MARKUP || '10.20') || 0;
  const tollfreeMarkup = parseFloat(process.env.DID_TOLLFREE_MONTHLY_MARKUP || '25.20') || 0;

  for (const did of dids) {
    if (!did) continue;
    const attrs = did.attributes || {};
    let location = '';
    const didGroupRel = did.relationships?.did_group?.data;

    if (didGroupRel && didGroupsMap[didGroupRel.id]) {
      const dg = didGroupsMap[didGroupRel.id];
      const parts = [];
      const cityRel = dg.relationships?.city?.data;
      const regionRel = dg.relationships?.region?.data;
      const countryRel = dg.relationships?.country?.data;
      if (cityRel && citiesMap[cityRel.id]) parts.push(citiesMap[cityRel.id]);
      if (regionRel && regionsMap[regionRel.id]) parts.push(regionsMap[regionRel.id]);
      if (countryRel && countriesMap[countryRel.id]) parts.push(countriesMap[countryRel.id]);
      location = parts.join(', ');
    }

    if (!location) {
      location = [attrs.city_name, attrs.region_name, attrs.country_name].filter(Boolean).join(', ');
    }

    // Determine if this DID is toll-free for pricing
    const didType = String(attrs.did_type || '').toLowerCase();
    let isTollfreeDid = didType.includes('toll');
    if (!isTollfreeDid && didGroupRel && didGroupsMap[didGroupRel.id]) {
      const dg = didGroupsMap[didGroupRel.id];
      const name = String(dg.attributes?.name || '').toLowerCase();
      if (name.includes('toll')) isTollfreeDid = true;
    }

    const monthlyNum = isTollfreeDid ? tollfreeMarkup : localMarkup;
    const setupNum = 0; // We don't expose DIDWW setup price in customer receipts

    result.push({
      number: attrs.number || '',
      location: location || '',
      monthlyPrice: monthlyNum,
      setupPrice: setupNum
    });
  }

  return result;
}

// Health check endpoint for DigitalOcean
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Optional debug endpoint (disabled in production)
if (DEBUG) {
  app.get('/debug/env', (req, res) => {
    const rawPath = process.env.MAGNUSBILLING_USER_PATH;
    const effectivePath = (rawPath === undefined) ? '/user' : rawPath;
    res.json({
      NODE_ENV: process.env.NODE_ENV,
      PORT: process.env.PORT,
      MAGNUSBILLING_URL: process.env.MAGNUSBILLING_URL,
      MAGNUSBILLING_USER_PATH_RAW: rawPath ?? null,
      MAGNUSBILLING_USER_PATH_EFFECTIVE: effectivePath,
      MAGNUSBILLING_TLS_SERVERNAME: process.env.MAGNUSBILLING_TLS_SERVERNAME || null,
      MAGNUSBILLING_TLS_INSECURE: process.env.MAGNUSBILLING_TLS_INSECURE || '0',
      MAGNUSBILLING_HOST_HEADER: process.env.MAGNUSBILLING_HOST_HEADER || null,
      DEFAULT_GROUP_ID: process.env.DEFAULT_GROUP_ID,
      DEFAULT_PLAN_ID: process.env.DEFAULT_PLAN_ID
    });
  });
}

// Serve the home page at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Serve the signup page at /signup
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve static files from public directory (after route handlers to prevent index.html from being served at root)
app.use(express.static('public'));

// Login + Dashboard
app.get('/login', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/dashboard');
  res.render('login', { error: null });
});
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, username, password } = req.body || {};
    const ident = (email || username || '').trim();
    const pwd = String(password || '');
    if (!ident || !pwd) return res.status(400).render('login', { error: 'Missing email/username or password' });
    if (!pool) return res.status(500).render('login', { error: 'Database not configured' });
    const [rows] = await pool.execute('SELECT id, magnus_user_id, username, email, password_hash FROM signup_users WHERE email=? OR username=? LIMIT 1', [ident, ident]);
    const row = rows && rows[0];
    if (!row || !row.password_hash) return res.status(401).render('login', { error: 'Invalid credentials' });
    const ok = await bcrypt.compare(pwd, row.password_hash);
    if (!ok) return res.status(401).render('login', { error: 'Invalid credentials' });
    if (DEBUG) console.log('[login] User from DB:', { id: row.id, magnus_user_id: row.magnus_user_id, username: row.username, email: row.email });
    // Regenerate session to avoid session fixation / stale data reuse
    req.session.regenerate((err) => {
      if (err) { return res.status(500).render('login', { error: 'Session error' }); }
      req.session.userId = String(row.id);
      req.session.magnusUserId = String(row.magnus_user_id || '');
      req.session.username = row.username;
      req.session.email = row.email;
      setImmediate(() => { prefetchUserData(req); });
      req.session.save((saveErr) => {
        if (saveErr) { return res.status(500).render('login', { error: 'Session save error' }); }
        if (DEBUG) console.log('[login.ok]', { sid: req.sessionID, userId: req.session.userId, magnusUserId: req.session.magnusUserId, username: req.session.username });
        return res.redirect('/dashboard');
      });
    });
  } catch (e) {
    if (DEBUG) console.warn('login error', e.message || e);
    return res.status(500).render('login', { error: 'Login failed' });
  }
});
app.post('/logout', (req, res) => { try { req.session.destroy(()=>{}); } catch {} res.redirect('/login'); });
app.get('/dashboard', requireAuth, (req, res) => {
  const localMarkup = parseFloat(process.env.DID_LOCAL_MONTHLY_MARKUP || '10.20') || 0;
  const tollfreeMarkup = parseFloat(process.env.DID_TOLLFREE_MONTHLY_MARKUP || '25.20') || 0;
  const checkoutMin = Number.isFinite(CHECKOUT_MIN_AMOUNT) ? CHECKOUT_MIN_AMOUNT : 100;
  const checkoutMax = Number.isFinite(CHECKOUT_MAX_AMOUNT) ? CHECKOUT_MAX_AMOUNT : 500;
  const sipDomain = process.env.SIP_DOMAIN || process.env.MAGNUSBILLING_TLS_SERVERNAME || process.env.MAGNUSBILLING_HOST_HEADER || '';
  res.render('dashboard', {
    username: req.session.username || '',
    localDidMarkup: localMarkup,
    tollfreeDidMarkup: tollfreeMarkup,
    checkoutMinAmount: checkoutMin,
    checkoutMaxAmount: checkoutMax,
    sipDomain
  });
});
// Guard: deleting the primary signup user is disabled via API as well
app.delete('/api/me', requireAuth, (req, res)=>{
  return res.status(403).json({ success:false, message:'Deleting the primary signup user is disabled.' });
});

// Admin: list users and balances via MagnusBilling HTTP API (guarded by ADMIN_TOKEN)
app.get('/api/admin/users-balances', async (req, res) => {
  try {
    const token = req.headers['x-admin-token'] || req.headers['authorization']?.replace(/^Bearer\s+/i,'');
    if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit || '100', 10)));
    const page = Math.max(0, parseInt(req.query.page || '0', 10));
    const start = page * limit;
    const q = (req.query.q || '').toString().trim();
    const httpsAgent = new https.Agent({ rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1', ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}) });
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
    const params = new URLSearchParams();
    params.append('module', 'user');
    params.append('action', 'read');
    params.append('start', String(start));
    params.append('limit', String(limit));
    if (q) {
      // Try multiple common filters; API will ignore unknown ones
      params.append('username', q);
      params.append('user', q);
      params.append('like', q);
      params.append('filter', q);
    }
    const resp = await mbSignedCall({ relPath: '/index.php/user/read', params, httpsAgent, hostHeader });
    const raw = resp?.data?.rows || resp?.data?.data || [];
    const rows = raw.map(r => ({ id: r.id_user || r.id || r.user_id, username: r.username || r.user || '', credit: Number(r.credit ?? 0) }));
    return res.json({ success: true, rows, page, limit });
  } catch (e) {
    console.error('users-balances api error', e.message || e);
    return res.status(500).json({ success: false, message: 'Query failed' });
  }
});

// Protected API proxies
// Profile from local MySQL (name/email/phone) + balance from MagnusBilling
app.get('/api/me/profile', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    const [rows] = await pool.execute('SELECT username, firstname, lastname, email, phone FROM signup_users WHERE id=? LIMIT 1', [userId]);
    const row = rows && rows[0] ? rows[0] : {};
    const name = [row.firstname, row.lastname].filter(Boolean).join(' ').trim();
    const sipDomain = process.env.SIP_DOMAIN || process.env.MAGNUSBILLING_TLS_SERVERNAME || process.env.MAGNUSBILLING_HOST_HEADER || '';
    
    // Fetch balance from MagnusBilling
    let balance = null;
    try {
      const httpsAgent = new https.Agent({ rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1', ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}) });
      const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
      const idUser = await ensureMagnusUserId(req, { httpsAgent, hostHeader });
      if (idUser) {
        // Fetch multiple users and filter client-side (MagnusBilling API doesn't filter properly with admin creds)
        const params = new URLSearchParams();
        params.append('module', 'user');
        params.append('action', 'read');
        params.append('start', '0');
        params.append('limit', '100'); // Fetch more users to find the right one
        const resp = await mbSignedCall({ relPath: '/index.php/user/read', params, httpsAgent, hostHeader });
        const allUsers = resp?.data?.rows || resp?.data?.data || [];
        
        if (DEBUG && allUsers.length > 0) {
          console.log('[profile] Sample user data:', JSON.stringify(allUsers[0]).substring(0, 500));
          console.log('[profile] All user IDs:', allUsers.map(u => ({ id: u.id, id_user: u.id_user, username: u.username })));
        }
        
        // Find the user that matches our idUser (check id FIRST, not id_user)
        const userRow = allUsers.find(u => {
          const uId = String(u.id || u.user_id || u.uid || u.id_user || '');
          const matches = uId === String(idUser);
          if (DEBUG && matches) console.log('[profile] Matched user by ID:', { id: u.id, id_user: u.id_user, username: u.username });
          return matches;
        });
        if (userRow && userRow.credit !== undefined) {
          balance = Number(userRow.credit || 0);
          const callLimit = userRow.calllimit || userRow.credit_limit || userRow.creditlimit || 0;
          const cpsLimit = userRow.cpslimit || userRow.cps_limit || 0;
          if (DEBUG) console.log('[profile] Balance fetched:', { userId: idUser, username: userRow.username, balance, callLimit, cpsLimit, totalUsersChecked: allUsers.length });
          // Store call limit and CPS limit for response
          req.session.callLimit = callLimit;
          req.session.cpsLimit = cpsLimit;
        } else if (DEBUG) {
          console.warn('[profile] User not found in response:', { searchingFor: idUser, availableUserIds: allUsers.map(u => u.id_user || u.id).slice(0, 10) });
        }
      }
    } catch (e) {
      if (DEBUG) console.warn('[profile] Balance fetch failed:', e.message);
    }
    
    const callLimit = req.session.callLimit || 0;
    const cpsLimit = req.session.cpsLimit || 0;
    return res.json({ success: true, data: { name, email: row.email || '', phone: row.phone || '', username: row.username || '', sipDomain, balance, callLimit, cpsLimit } });
  } catch (e) { return res.status(500).json({ success: false, message: 'Profile fetch failed' }); }
});

// ========== Billing History ==========
// Get billing history for current user
// NOTE: We intentionally hide raw DIDWW purchase rows ("DID Purchase (Order: ...)")
// from the customer-facing history so users only see TalkUSA-level charges
// such as refills and DID markup fees.
app.get('/api/me/billing-history', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    const page = Math.max(0, parseInt(req.query.page || '0', 10));
    const pageSize = Math.max(1, Math.min(100, parseInt(req.query.pageSize || '20', 10)));
    const offset = page * pageSize;

    // Get total count of *visible* billing rows (exclude internal DIDWW purchase lines)
    const [[countRow]] = await pool.execute(
      "SELECT COUNT(*) as total FROM billing_history WHERE user_id = ? AND (description IS NULL OR description NOT LIKE 'DID Purchase (Order:%')",
      [userId]
    );
    const total = countRow?.total || 0;

    // Get visible billing records (exclude internal DIDWW purchases)
    // Use query instead of execute for LIMIT/OFFSET as MySQL prepared statements require string conversion
    const [rows] = await pool.query(
      `SELECT id, amount, description, status, created_at
       FROM billing_history
       WHERE user_id = ? AND (description IS NULL OR description NOT LIKE 'DID Purchase (Order:%')
       ORDER BY created_at DESC
       LIMIT ${parseInt(pageSize, 10)} OFFSET ${parseInt(offset, 10)}`,
      [userId]
    );

    if (DEBUG) console.log('[billing.history.rows]', { userId, count: rows.length, sample: rows[0] || null });

    // Also fetch current balance from MagnusBilling
    let balance = null;
    try {
      const httpsAgent = new https.Agent({ rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1', ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}) });
      const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
      const idUser = await ensureMagnusUserId(req, { httpsAgent, hostHeader });
      if (idUser) {
        const params = new URLSearchParams();
        params.append('module', 'user'); params.append('action', 'read'); params.append('start', '0'); params.append('limit', '100');
        const resp = await mbSignedCall({ relPath: '/index.php/user/read', params, httpsAgent, hostHeader });
        const allUsers = resp?.data?.rows || resp?.data?.data || [];
        const userRow = allUsers.find(u => String(u.id || u.user_id || u.uid || u.id_user || '') === String(idUser));
        if (userRow) balance = Number(userRow.credit || 0);
      }
    } catch (e) { if (DEBUG) console.warn('[billing.balance] fetch failed:', e.message); }

    return res.json({ success: true, data: rows, total, page, pageSize, balance });
  } catch (e) {
    if (DEBUG) console.error('[billing.history] error:', e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch billing history' });
  }
});

// ========== Per-user CDR history (from streamed DIDWW Voice IN CDRs) ==========
// Returns CDRs for the logged-in user based on user_did_cdrs table.
// Supports pagination (?page, ?pageSize) and optional filters: ?from, ?to, ?did.

// Shared helper to build a unified CDR timeline (inbound from user_did_cdrs + outbound
// from user_mb_cdrs) with sorting and pagination. Used by both /api/me/cdrs and
// /api/me/cdrs/local so they stay in sync.
async function loadUserCdrTimeline({ userId, page, pageSize, fromRaw, toRaw, didFilter }) {
  if (!pool) throw new Error('Database not configured');
  if (!userId) throw new Error('Missing userId');

  const filters = ['user_id = ?'];
  const params = [userId];

  if (fromRaw) {
    filters.push('DATE(time_start) >= ?');
    params.push(fromRaw);
  }
  if (toRaw) {
    filters.push('DATE(time_start) <= ?');
    params.push(toRaw);
  }
  if (didFilter) {
    filters.push('did_number = ?');
    params.push(didFilter);
  }
  const whereSql = filters.length ? 'WHERE ' + filters.join(' AND ') : '';

  // Inbound from user_did_cdrs (local DIDWW mirror)
  const [inboundRows] = await pool.query(
    `SELECT id, cdr_id, user_id, did_number, direction, src_number, dst_number,
            time_start, time_connect, time_end, duration, billsec, price, created_at
     FROM user_did_cdrs
     ${whereSql}
     ORDER BY time_start DESC, id DESC`,
    params
  );

  const inbound = inboundRows.map(r => ({
    id: r.id,
    cdrId: r.cdr_id,
    didNumber: r.did_number,
    direction: r.direction,
    srcNumber: r.src_number,
    dstNumber: r.dst_number,
    timeStart: r.time_start ? r.time_start.toISOString() : null,
    timeConnect: r.time_connect ? r.time_connect.toISOString() : null,
    timeEnd: r.time_end ? r.time_end.toISOString() : null,
    duration: r.duration != null ? Number(r.duration) : null,
    billsec: r.billsec != null ? Number(r.billsec) : null,
    price: r.price != null ? Number(r.price) : null,
    createdAt: r.created_at ? r.created_at.toISOString() : null
  }));

  // Outbound from user_mb_cdrs (local MagnusBilling mirror)
  let outbound = [];
  try {
    outbound = await loadLocalOutboundCdrs({ userId, fromRaw, toRaw, didFilter });
  } catch (e) {
    if (DEBUG) console.warn('[cdr.timeline] Failed to load outbound from user_mb_cdrs:', e.message || e);
    outbound = [];
  }

  let all = inbound.concat(outbound);

  // Sort newest first by timeStart (fallback to createdAt)
  all.sort((a, b) => {
    const aTs = a.timeStart ? Date.parse(a.timeStart) : (a.createdAt ? Date.parse(a.createdAt) : 0);
    const bTs = b.timeStart ? Date.parse(b.timeStart) : (b.createdAt ? Date.parse(b.createdAt) : 0);
    if (bTs !== aTs) return bTs - aTs;
    const aId = String(a.id || '');
    const bId = String(b.id || '');
    return bId.localeCompare(aId);
  });

  const total = all.length;
  const startIndex = page * pageSize;
  const endIndex = startIndex + pageSize;
  const pageRows = all.slice(startIndex, endIndex);

  if (DEBUG) console.log('[cdr.timeline]', { userId, count: pageRows.length, total });

  return { rows: pageRows, total };
}
app.get('/api/me/cdrs', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    if (!userId) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const page = Math.max(0, parseInt(req.query.page || '0', 10));
    const pageSize = Math.max(1, Math.min(200, parseInt(req.query.pageSize || '50', 10)));

    const fromRaw = (req.query.from || '').toString().trim();
    const toRaw = (req.query.to || '').toString().trim();
    const didFilter = (req.query.did || '').toString().trim();

    const { rows, total } = await loadUserCdrTimeline({
      userId,
      page,
      pageSize,
      fromRaw,
      toRaw,
      didFilter
    });

    return res.json({ success: true, data: rows, total, page, pageSize });
  } catch (e) {
    if (DEBUG) console.error('[me.cdrs] error:', e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch CDRs' });
  }
});

// Persist normalized MagnusBilling CDRs into local DB for history
async function saveMagnusCdrsToDb({ localUserId, magnusUserId, rows, rawRows }) {
  if (!pool || !localUserId || !magnusUserId || !Array.isArray(rows) || !rows.length) return;
  try {
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      const raw = Array.isArray(rawRows) && rawRows[i] ? rawRows[i] : null;
      if (!r || !r.cdrId) continue;
      const ts = r.timeStart ? new Date(r.timeStart) : null;
      await pool.execute(
        'INSERT IGNORE INTO user_mb_cdrs (cdr_id, user_id, magnus_user_id, direction, src_number, dst_number, did_number, time_start, duration, billsec, price, raw_cdr) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          String(r.cdrId),
          localUserId,
          String(magnusUserId),
          r.direction || 'outbound',
          r.srcNumber || null,
          r.dstNumber || null,
          r.didNumber || null,
          ts,
          r.duration != null ? Number(r.duration) : null,
          r.billsec != null ? Number(r.billsec) : null,
          r.price != null ? Number(r.price) : null,
          raw ? JSON.stringify(raw) : null
        ]
      );
    }
  } catch (e) {
    if (DEBUG) console.warn('[me.cdrs.magnus.store] Error while inserting outbound CDRs:', e.message || e);
  }
}

// Load outbound CDRs for a user from the local MagnusBilling mirror (user_mb_cdrs)
// using the same date/DID filters as /api/me/cdrs and /api/me/cdrs/local.
async function loadLocalOutboundCdrs({ userId, fromRaw, toRaw, didFilter }) {
  if (!pool || !userId) return [];

  const outFilters = ['user_id = ?'];
  const outParams = [userId];
  if (fromRaw) {
    outFilters.push('DATE(time_start) >= ?');
    outParams.push(fromRaw);
  }
  if (toRaw) {
    outFilters.push('DATE(time_start) <= ?');
    outParams.push(toRaw);
  }
  if (didFilter) {
    outFilters.push('(did_number = ? OR dst_number = ? OR src_number = ?)');
    outParams.push(didFilter, didFilter, didFilter);
  }
  const whereOutSql = outFilters.length ? 'WHERE ' + outFilters.join(' AND ') : '';

  const [outRows] = await pool.query(
    `SELECT id, cdr_id, magnus_user_id, direction, src_number, dst_number, did_number,
            time_start, duration, billsec, price, created_at
     FROM user_mb_cdrs
     ${whereOutSql}
     ORDER BY time_start DESC, id DESC`,
    outParams
  );

  if (DEBUG) {
    console.log('[me.cdrs.local.query]', {
      userId,
      from: fromRaw || null,
      to: toRaw || null,
      did: didFilter || null,
      count: outRows.length
    });
  }

  return outRows.map(r => ({
    id: r.cdr_id ? `mb-${r.cdr_id}` : `mb-db-${r.id}`,
    cdrId: r.cdr_id ? String(r.cdr_id) : null,
    didNumber: r.did_number,
    direction: r.direction || 'outbound',
    srcNumber: r.src_number || '',
    dstNumber: r.dst_number || '',
    timeStart: r.time_start ? r.time_start.toISOString() : null,
    timeConnect: null,
    timeEnd: null,
    duration: r.duration != null ? Number(r.duration) : (r.billsec != null ? Number(r.billsec) : null),
    billsec: r.billsec != null ? Number(r.billsec) : (r.duration != null ? Number(r.duration) : null),
    price: r.price != null ? Number(r.price) : null,
    createdAt: r.created_at ? r.created_at.toISOString() : null
  }));
}

// Normalize a raw MagnusBilling CDR row into the local CDR shape used by user_mb_cdrs
function normalizeMagnusCdrRow(r) {
  if (!r) return null;

  const dirRaw = String(
    r.direction || r.calltype || r.call_type || r.call_direction || ''
  ).toLowerCase();
  let direction = 'outbound';
  if (dirRaw.includes('in') && !dirRaw.includes('out')) direction = 'inbound';
  if (dirRaw.includes('out')) direction = 'outbound';

  const startStr =
    r.starttime ||
    r.start_time ||
    r.calldate ||
    r.callstart ||
    r.start_date ||
    r.date ||
    null;
  const startDate = startStr ? new Date(startStr) : null;

  let callerRaw =
    r.callerid ||
    r.cid ||
    r.clid ||
    r.cli ||
    r.callingnumber ||
    r.src_number ||
    r.src ||
    '';
  callerRaw = String(callerRaw || '').trim();
  const angleMatch = /<([^>]+)>/.exec(callerRaw);
  if (angleMatch) callerRaw = angleMatch[1];
  callerRaw = callerRaw.replace(/\"/g, '').trim();

  const extRaw =
    r.src ||
    r.accountcode ||
    r.sipiax ||
    '';

  const src = callerRaw || extRaw || '';

  const dst =
    r.dst ||
    r.calledstation ||
    r.destination ||
    r.dest ||
    r.dst_number ||
    '';

  let billsec = null;
  if (r.billsec != null) billsec = Number(r.billsec) || 0;
  else if (r.sessiontime != null) billsec = Number(r.sessiontime) || 0;
  else if (r.duration != null) billsec = Number(r.duration) || 0;
  if (billsec != null && billsec < 0) billsec = 0;

  let price = null;
  if (r.sessionbill != null) price = Number(r.sessionbill);
  else if (r.debit != null) price = Number(r.debit);
  else if (r.cost != null) price = Number(r.cost);

  const idVal = r.id || r.id_call || r.uniqueid || r.unique_id || null;
  const didNumber = r.did || r.did_number || r.didnumber || null;
  const timeIso = startDate ? startDate.toISOString() : null;

  return {
    id: idVal != null ? `mb-${idVal}` : `mb-${Math.random().toString(36).slice(2)}`,
    cdrId: idVal != null ? String(idVal) : null,
    didNumber,
    direction,
    srcNumber: src || '',
    dstNumber: dst || '',
    timeStart: timeIso,
    timeConnect: null,
    timeEnd: null,
    duration: billsec,
    billsec,
    price: price != null && Number.isFinite(price) ? price : null,
    createdAt: timeIso
  };
}

// Incrementally import MagnusBilling CDRs for a single user into user_mb_cdrs
async function importMagnusCdrsForUser({ localUserId, magnusUserId, username, email, httpsAgent, hostHeader }) {
  if (!pool || !localUserId || !magnusUserId) return;
  const magnusIdStr = String(magnusUserId);

  const now = new Date();
  const nowMs = now.getTime();
  const defaultSinceMs = nowMs - MB_CDR_IMPORT_LOOKBACK_MINUTES * 60 * 1000;
  let sinceMs = defaultSinceMs;

  // Load previous cursor, if any
  try {
    const [rows] = await pool.execute(
      'SELECT last_time_start_ms FROM cdr_import_cursors WHERE magnus_user_id = ? LIMIT 1',
      [magnusIdStr]
    );
    if (rows && rows[0] && rows[0].last_time_start_ms != null) {
      const lastMs = Number(rows[0].last_time_start_ms) || 0;
      if (lastMs > 0) {
        // Small overlap (60s) to be resilient to clock skew / late CDRs
        const overlapMs = 60 * 1000;
        sinceMs = Math.max(lastMs - overlapMs, defaultSinceMs);
      }
    }
  } catch (e) {
    if (DEBUG) console.warn('[cdr.import.cursor.load] failed:', e.message || e);
  }

  const fromStr = formatMagnusDateTime(new Date(sinceMs));
  const toStr = formatMagnusDateTime(now);

  let start = 0;
  const pageLimit = MB_CDR_IMPORT_PAGE_SIZE;
  const maxPages = MB_CDR_IMPORT_MAX_PAGES;
  let imported = 0;
  let maxSeenMs = sinceMs;

  for (let page = 0; page < maxPages; page++, start += pageLimit) {
    let dataRaw;
    try {
      dataRaw = await fetchCdr({
        idUser: magnusIdStr,
        username,
        from: fromStr,
        to: toStr,
        httpsAgent,
        hostHeader,
        start,
        limit: pageLimit
      });
    } catch (e) {
      if (DEBUG) console.warn('[cdr.import.fetch] failed:', e.message || e);
      break;
    }

    const rawRows = (dataRaw && (dataRaw.rows || dataRaw.data)) || [];
    if (!rawRows.length) break;

    // For debugging: log a small sample of raw CDR rows for magnusUserId where
    // we are currently seeing ownedCount=0 so we can tune the filter safely.
    if (DEBUG && magnusIdStr === '2' && page === 0 && rawRows.length) {
      const s = rawRows[0] || {};
      console.log('[cdr.import.sample]', {
        magnusUserId: magnusIdStr,
        id_user: s.id_user,
        user_id: s.user_id,
        uid: s.uid,
        idUser: s.idUser,
        userid: s.userid,
        username: s.username,
        name: s.name,
        user: s.user,
        accountcode: s.accountcode,
        idUserusername: s.idUserusername
      });
    }

    // IMPORTANT: MagnusBilling "call" module often ignores id_user filters when
    // queried with admin credentials, returning CDRs for many users. We must
    // therefore apply a strict per-row ownership check, otherwise this importer
    // would mirror *everyone's* calls into the current user's history.
    const ownedRows = rawRows.filter(r => cdrRowBelongsToUser(r, magnusIdStr, username, email));
    if (!ownedRows.length) {
      if (DEBUG) {
        console.log('[cdr.import.user.skipPage]', {
          localUserId,
          magnusUserId: magnusIdStr,
          rawCount: rawRows.length,
          ownedCount: 0,
          page,
          start
        });
      }
      // Do not advance cursor based on foreign users' CDRs.
      continue;
    }

    const normalized = [];
    const rawForSave = [];
    for (const r of ownedRows) {
      const n = normalizeMagnusCdrRow(r);
      if (!n || !n.cdrId) continue;
      normalized.push(n);
      rawForSave.push(r);
      const ts = Date.parse(n.timeStart || n.createdAt || toStr);
      if (!Number.isNaN(ts) && ts > maxSeenMs) maxSeenMs = ts;
    }

    if (normalized.length) {
      await saveMagnusCdrsToDb({
        localUserId,
        magnusUserId: magnusIdStr,
        rows: normalized,
        rawRows: rawForSave
      });
      imported += normalized.length;
    }

    if (rawRows.length < pageLimit) break;
  }

  if (imported && maxSeenMs > sinceMs) {
    try {
      await pool.execute(
        'INSERT INTO cdr_import_cursors (magnus_user_id, last_time_start_ms) VALUES (?, ?) ON DUPLICATE KEY UPDATE last_time_start_ms = VALUES(last_time_start_ms), updated_at = CURRENT_TIMESTAMP',
        [magnusIdStr, maxSeenMs]
      );
    } catch (e) {
      if (DEBUG) console.warn('[cdr.import.cursor.save] failed:', e.message || e);
    }
  }

  if (DEBUG && imported) {
    console.log('[cdr.import.user]', {
      localUserId,
      magnusUserId: magnusIdStr,
      imported,
      from: fromStr,
      to: toStr
    });
  }
}

// Batch import MagnusBilling CDRs once per tick and distribute to local users.
// This avoids N_users * N_pages scans when the upstream endpoint ignores id_user filters.
async function importMagnusCdrsForUsersBatch({ users, httpsAgent, hostHeader }) {
  if (!pool || !Array.isArray(users) || !users.length) return;

  const now = new Date();
  const nowMs = now.getTime();
  const defaultSinceMs = nowMs - MB_CDR_IMPORT_LOOKBACK_MINUTES * 60 * 1000;
  const overlapMs = 60 * 1000;
  const slackMs = (Number.isFinite(MB_CDR_IMPORT_EMPTY_ADVANCE_SLACK_SECONDS) ? MB_CDR_IMPORT_EMPTY_ADVANCE_SLACK_SECONDS : 300) * 1000;

  // Load all cursors once (table is small) and build a per-user sinceMs map.
  const cursorByMagnus = new Map();
  try {
    const [rows] = await pool.query('SELECT magnus_user_id, last_time_start_ms FROM cdr_import_cursors');
    for (const r of rows || []) {
      const mid = String(r.magnus_user_id || '').trim();
      if (!mid) continue;
      const lastMs = Number(r.last_time_start_ms) || 0;
      cursorByMagnus.set(mid, lastMs);
    }
  } catch (e) {
    if (DEBUG) console.warn('[cdr.import.cursor.loadAll] failed:', e.message || e);
  }

  const userByMagnus = new Map();
  let globalSinceMs = nowMs;

  for (const u of users) {
    const magnusUserId = String(u.magnus_user_id || '').trim();
    if (!magnusUserId) continue;
    const localUserId = String(u.id);

    const lastMs = cursorByMagnus.get(magnusUserId) || 0;
    const sinceMs = lastMs > 0
      ? Math.max(lastMs - overlapMs, defaultSinceMs)
      : defaultSinceMs;

    if (sinceMs < globalSinceMs) globalSinceMs = sinceMs;

    userByMagnus.set(magnusUserId, {
      localUserId,
      magnusUserId,
      username: u.username || '',
      email: u.email || '',
      sinceMs
    });
  }

  if (!userByMagnus.size) return;

  const fromStr = formatMagnusDateTime(new Date(globalSinceMs));
  const toStr = formatMagnusDateTime(now);

  const pageLimit = MB_CDR_IMPORT_PAGE_SIZE;
  const maxPages = MB_CDR_IMPORT_MAX_PAGES;

  const importedByMagnus = new Map();
  const maxSeenByMagnus = new Map();
  const sawNewByMagnus = new Map();
  for (const [mid, info] of userByMagnus.entries()) {
    importedByMagnus.set(mid, 0);
    maxSeenByMagnus.set(mid, info.sinceMs);
    sawNewByMagnus.set(mid, false);
  }

  let completedWindow = false;
  let pagesFetched = 0;
  let start = 0;

  for (let page = 0; page < maxPages; page++, start += pageLimit) {
    pagesFetched++;

    let dataRaw;
    try {
      dataRaw = await fetchCdr({
        from: fromStr,
        to: toStr,
        httpsAgent,
        hostHeader,
        start,
        limit: pageLimit
      });
    } catch (e) {
      if (DEBUG) console.warn('[cdr.import.batch.fetch] failed:', e.message || e);
      break;
    }

    const rawRows = (dataRaw && (dataRaw.rows || dataRaw.data)) || [];
    if (!rawRows.length) {
      completedWindow = true;
      break;
    }

    // Group by magnus_user_id to reduce DB roundtrips.
    const buckets = new Map(); // magnusUserId -> { localUserId, magnusUserId, rows, rawRows }

    for (const r of rawRows) {
      const mid = extractMagnusUserIdFromCdrRow(r);
      if (!mid) continue;

      const user = userByMagnus.get(mid);
      if (!user) continue;

      let n;
      try {
        n = normalizeMagnusCdrRow(r);
      } catch (e) {
        if (DEBUG) console.warn('[cdr.import.batch.normalize] failed:', e.message || e);
        continue;
      }
      if (!n || !n.cdrId) continue;

      const ts = Date.parse(n.timeStart || n.createdAt || '');
      if (!Number.isNaN(ts) && ts < user.sinceMs) {
        // Outside this user's effective window (likely already imported on prior ticks).
        continue;
      }

      if (!Number.isNaN(ts)) {
        sawNewByMagnus.set(mid, true);
        if (ts > (maxSeenByMagnus.get(mid) || user.sinceMs)) maxSeenByMagnus.set(mid, ts);
      } else {
        // If timestamp is missing/unparseable, treat as "new" so we don't advance the cursor incorrectly.
        sawNewByMagnus.set(mid, true);
      }

      let b = buckets.get(mid);
      if (!b) {
        b = { localUserId: user.localUserId, magnusUserId: mid, rows: [], rawRows: [] };
        buckets.set(mid, b);
      }
      b.rows.push(n);
      b.rawRows.push(r);
    }

    for (const [mid, b] of buckets.entries()) {
      if (!b.rows.length) continue;
      await saveMagnusCdrsToDb({
        localUserId: b.localUserId,
        magnusUserId: b.magnusUserId,
        rows: b.rows,
        rawRows: b.rawRows
      });
      importedByMagnus.set(mid, (importedByMagnus.get(mid) || 0) + b.rows.length);
    }

    if (rawRows.length < pageLimit) {
      completedWindow = true;
      break;
    }
  }

  // Cursor updates: update per-user on success; if window completed and user had no new rows,
  // advance close to now to prevent repeated scans of foreign-user pages.
  for (const [mid, info] of userByMagnus.entries()) {
    const imported = importedByMagnus.get(mid) || 0;
    const maxSeenMs = maxSeenByMagnus.get(mid) || info.sinceMs;

    if (imported > 0 && maxSeenMs > info.sinceMs) {
      try {
        await pool.execute(
          'INSERT INTO cdr_import_cursors (magnus_user_id, last_time_start_ms) VALUES (?, ?) ON DUPLICATE KEY UPDATE last_time_start_ms = VALUES(last_time_start_ms), updated_at = CURRENT_TIMESTAMP',
          [mid, maxSeenMs]
        );
      } catch (e) {
        if (DEBUG) console.warn('[cdr.import.cursor.save] failed:', e.message || e);
      }
      continue;
    }

    if (completedWindow && !sawNewByMagnus.get(mid)) {
      // No calls for this user in the completed window: move the cursor near now.
      const advanceTo = Math.max(nowMs - slackMs, defaultSinceMs);
      try {
        await pool.execute(
          'INSERT INTO cdr_import_cursors (magnus_user_id, last_time_start_ms) VALUES (?, ?) ON DUPLICATE KEY UPDATE last_time_start_ms = VALUES(last_time_start_ms), updated_at = CURRENT_TIMESTAMP',
          [mid, advanceTo]
        );
      } catch (e) {
        if (DEBUG) console.warn('[cdr.import.cursor.advanceEmpty] failed:', e.message || e);
      }
    }
  }

  if (DEBUG) {
    const totalImported = [...importedByMagnus.values()].reduce((a, b) => a + (Number(b) || 0), 0);
    console.log('[cdr.import.batch]', {
      users: userByMagnus.size,
      pagesFetched,
      completedWindow,
      from: fromStr,
      to: toStr,
      imported: totalImported
    });
  }
}

let cdrImportRunning = false;
async function runCdrImportTick() {
  if (!pool) return;
  if (cdrImportRunning) {
    if (DEBUG) console.log('[cdr.import] tick skipped (already running)');
    return;
  }
  cdrImportRunning = true;
  try {
    const [users] = await pool.execute(
      'SELECT id, magnus_user_id, username, email FROM signup_users WHERE magnus_user_id IS NOT NULL'
    );
    if (!users || users.length === 0) {
      if (DEBUG) console.log('[cdr.import] No users with magnus_user_id; skipping tick');
      return;
    }

    const httpsAgent = magnusBillingAgent;
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;

    try {
      await importMagnusCdrsForUsersBatch({ users, httpsAgent, hostHeader });
    } catch (e) {
      if (DEBUG) console.warn('[cdr.import.batch.error]', e.message || e);
    }
  } catch (e) {
    if (DEBUG) console.warn('[cdr.import.tick] error:', e.message || e);
  } finally {
    cdrImportRunning = false;
  }
}

function startCdrImportScheduler() {
  const intervalMs = (parseInt(process.env.MB_CDR_IMPORT_INTERVAL_SECONDS || '0', 10) || 0) * 1000;
  if (!intervalMs) {
    if (DEBUG) console.log('[cdr.import.scheduler] Disabled (no interval set)');
    return;
  }
  if (DEBUG) console.log('[cdr.import.scheduler] Enabled with interval (ms):', intervalMs);
  setInterval(() => {
    runCdrImportTick();
  }, intervalMs);
}

// Simple list of the logged-in user's DIDs from local DB (used for Call History DID filter)
app.get('/api/me/dids', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    if (!userId) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const [rows] = await pool.execute(
      'SELECT did_number FROM user_dids WHERE user_id = ? ORDER BY did_number',
      [userId]
    );

    return res.json({ success: true, data: rows });
  } catch (e) {
    if (DEBUG) console.error('[me.dids] error:', e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch DIDs' });
  }
});

// Lightweight per-user stats endpoint for dashboard (totals + daily counts)
// Query params: optional from, to (YYYY-MM-DD). Defaults to PREFETCH_DAYS window.
app.get('/api/me/stats', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    if (!userId) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const fromRaw = (req.query.from || '').toString().trim();
    const toRaw = (req.query.to || '').toString().trim();
    let from = fromRaw;
    let to = toRaw;
    if (!from || !to) {
      const rng = defaultRange();
      if (!from) from = rng.from;
      if (!to) to = rng.to;
    }

    // Total DIDs for this user
    let totalDids = 0;
    try {
      const [[row]] = await pool.execute(
        'SELECT COUNT(*) AS total FROM user_dids WHERE user_id = ?',
        [userId]
      );
      totalDids = Number(row?.total || 0);
    } catch (e) {
      if (DEBUG) console.warn('[me.stats.dids] failed:', e.message || e);
    }

    // Inbound calls grouped by day from user_did_cdrs
    let inboundCount = 0;
    const inboundByDayMap = new Map();
    try {
      const [rows] = await pool.query(
        `SELECT DATE(time_start) AS d, COUNT(*) AS calls
         FROM user_did_cdrs
         WHERE user_id = ? AND DATE(time_start) BETWEEN ? AND ?
         GROUP BY DATE(time_start)
         ORDER BY DATE(time_start)`,
        [userId, from, to]
      );
      for (const r of rows) {
        const dObj = r.d instanceof Date ? r.d : null;
        const day = dObj ? dObj.toISOString().slice(0, 10) : String(r.d || '');
        const c = Number(r.calls || 0);
        inboundCount += c;
        inboundByDayMap.set(day, (inboundByDayMap.get(day) || 0) + c);
      }
    } catch (e) {
      if (DEBUG) console.warn('[me.stats.inbound] failed:', e.message || e);
    }

    // Outbound calls grouped by day from user_mb_cdrs
    let outboundCount = 0;
    const outboundByDayMap = new Map();
    try {
      const [rows] = await pool.query(
        `SELECT DATE(time_start) AS d, COUNT(*) AS calls
         FROM user_mb_cdrs
         WHERE user_id = ? AND DATE(time_start) BETWEEN ? AND ?
         GROUP BY DATE(time_start)
         ORDER BY DATE(time_start)`,
        [userId, from, to]
      );
      for (const r of rows) {
        const dObj = r.d instanceof Date ? r.d : null;
        const day = dObj ? dObj.toISOString().slice(0, 10) : String(r.d || '');
        const c = Number(r.calls || 0);
        outboundCount += c;
        outboundByDayMap.set(day, (outboundByDayMap.get(day) || 0) + c);
      }
    } catch (e) {
      if (DEBUG) console.warn('[me.stats.outbound] failed:', e.message || e);
    }

    // SIP users: count total + online (lineStatus starts with OK)
    let totalSip = null;
    let onlineSip = null;
    try {
      const httpsAgent = new https.Agent({
        rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1',
        ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {})
      });
      const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
      const idUser = await ensureMagnusUserId(req, { httpsAgent, hostHeader });
      if (idUser) {
        const sipData = await fetchSipUsers({ idUser, httpsAgent, hostHeader });
        const rawRows = sipData?.rows || sipData?.data || [];
        const sipRows = rawRows.filter(r => sipBelongsToUser(r, idUser));
        totalSip = sipRows.length;
        onlineSip = sipRows.filter(r => {
          const status = String(r.lineStatus || r.linestatus || r.status || '').toUpperCase();
          return status.startsWith('OK');
        }).length;
      }
    } catch (e) {
      if (DEBUG) console.warn('[me.stats.sip] failed:', e.message || e);
    }

    // Merge daily inbound/outbound into a single series
    const allDays = new Set([...inboundByDayMap.keys(), ...outboundByDayMap.keys()]);
    const callsByDay = Array.from(allDays)
      .sort()
      .map(d => ({
        date: d,
        inbound: inboundByDayMap.get(d) || 0,
        outbound: outboundByDayMap.get(d) || 0
      }));

    // "Today" is interpreted as the end of the selected range ("to" date)
    const todayKey = to;
    const inboundToday = inboundByDayMap.get(todayKey) || 0;
    const outboundToday = outboundByDayMap.get(todayKey) || 0;

    return res.json({
      success: true,
      range: { from, to },
      kpis: {
        totalDids,
        inboundCount,
        outboundCount,
        inboundToday,
        outboundToday,
        totalSip,
        onlineSip
      },
      series: {
        callsByDay
      }
    });
  } catch (e) {
    if (DEBUG) console.error('[me.stats] error:', e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch stats' });
  }
});

// Local CDR history endpoint: reads outbound from user_mb_cdrs instead of MagnusBilling
// and inbound from user_did_cdrs. Same query params as /api/me/cdrs: page, pageSize,
// optional from, to, did. Useful for long history and when MagnusBilling is offline.
app.get('/api/me/cdrs/local', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    if (!userId) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const page = Math.max(0, parseInt(req.query.page || '0', 10));
    const pageSize = Math.max(1, Math.min(200, parseInt(req.query.pageSize || '50', 10)));

    const fromRaw = (req.query.from || '').toString().trim();
    const toRaw = (req.query.to || '').toString().trim();
    const didFilter = (req.query.did || '').toString().trim();

    const { rows, total } = await loadUserCdrTimeline({
      userId,
      page,
      pageSize,
      fromRaw,
      toRaw,
      didFilter
    });

    return res.json({ success: true, data: rows, total, page, pageSize });
  } catch (e) {
    if (DEBUG) console.error('[me.cdrs.local] error:', e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch local CDRs' });
  }
});

// Shared helper to apply a refill in MagnusBilling, update billing_history and send receipt
async function applyMagnusRefill({ userId, magnusUserId, amountNum, desc, displayName, userEmail, httpsAgent, hostHeader, billingId }) {
  if (!pool) throw new Error('Database not configured');
  if (!magnusUserId) throw new Error('Missing MagnusBilling user id');

  try {
    if (DEBUG) console.log('[refill] Attempting to add credit:', { magnusUserId, amount: amountNum, billingId });

    let success = false;
    let magnusResponse = null;

    // Method 1: Use the 'refill' module (the proper way to add credit in MagnusBilling)
    try {
      const refillParams = new URLSearchParams();
      refillParams.append('module', 'refill');
      refillParams.append('action', 'save');
      refillParams.append('id_user', String(magnusUserId));
      refillParams.append('credit', String(amountNum));
      refillParams.append('description', desc);
      refillParams.append('payment', '1'); // 1 = Yes (payment confirmed)
      refillParams.append('refill_type', '0'); // 0 = Bank transfer/manual (releases credit immediately)

      const refillResp = await mbSignedCall({ relPath: '/index.php/refill/save', params: refillParams, httpsAgent, hostHeader });
      magnusResponse = JSON.stringify(refillResp?.data || refillResp);

      if (DEBUG) console.log('[refill] Refill module response:', magnusResponse);

      // Check for success - MagnusBilling returns success:true or the new record
      if (refillResp?.data?.success === true || refillResp?.data?.rows?.length > 0 || (refillResp?.status >= 200 && refillResp?.status < 300)) {
        success = true;
        if (DEBUG) console.log('[refill] Refill successful via refill module');

        // Also verify/force the user credit update (some MagnusBilling versions need this)
        try {
          const readParams = new URLSearchParams();
          readParams.append('module', 'user');
          readParams.append('action', 'read');
          readParams.append('start', '0');
          readParams.append('limit', '100');
          const readResp = await mbSignedCall({ relPath: '/index.php/user/read', params: readParams, httpsAgent, hostHeader });
          const allUsers = readResp?.data?.rows || readResp?.data?.data || [];
          const userRow = allUsers.find(u => String(u.id || u.user_id || '') === String(magnusUserId));

          if (userRow) {
            const currentCredit = Number(userRow.credit || 0);
            const newCredit = currentCredit + amountNum;
            if (DEBUG) console.log('[refill] Credit after refill API call:', { currentCredit, newCredit, amountAdded: amountNum });

            // Force update the user's credit field directly
            // Some MagnusBilling versions don't auto-update user.credit from refill records
            if (DEBUG) console.log('[refill] Forcing direct credit update...');
            const updateParams = new URLSearchParams();
            updateParams.append('module', 'user');
            updateParams.append('action', 'save');
            updateParams.append('id', String(magnusUserId));
            updateParams.append('credit', String(newCredit));
            const updateResp = await mbSignedCall({ relPath: '/index.php/user/save', params: updateParams, httpsAgent, hostHeader });
            if (DEBUG) console.log('[refill] Direct credit update response:', JSON.stringify(updateResp?.data || updateResp?.status));
          }
        } catch (creditErr) {
          if (DEBUG) console.warn('[refill] Credit verification/update failed:', creditErr.message);
        }
      }
    } catch (e) {
      if (DEBUG) console.warn('[refill] refill module failed:', e.message, e.response?.data);
      magnusResponse = JSON.stringify(e.response?.data || e.message);
    }

    // Method 2: Try refillcredit module as fallback
    if (!success) {
      try {
        const refillParams = new URLSearchParams();
        refillParams.append('module', 'refillcredit');
        refillParams.append('action', 'save');
        refillParams.append('id_user', String(magnusUserId));
        refillParams.append('credit', String(amountNum));
        refillParams.append('description', desc);

        const refillResp = await mbSignedCall({ relPath: '/index.php/refillcredit/save', params: refillParams, httpsAgent, hostHeader });
        magnusResponse = JSON.stringify(refillResp?.data || refillResp);

        if (DEBUG) console.log('[refill] Refillcredit module response:', magnusResponse);

        if (refillResp?.data?.success === true || refillResp?.data?.rows?.length > 0) {
          success = true;
          if (DEBUG) console.log('[refill] Refill successful via refillcredit module');
        }
      } catch (e) {
        if (DEBUG) console.warn('[refill] refillcredit module failed:', e.message);
      }
    }

    if (success) {
      await pool.execute(
        'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
        ['completed', magnusResponse, billingId]
      );

      // Send refill receipt email (best-effort, do not fail the caller if this fails)
      try {
        if (userEmail) {
          await sendRefillReceiptEmail({ toEmail: userEmail, username: displayName, amount: amountNum, description: desc });
        }
      } catch (emailErr) {
        if (DEBUG) console.warn('[refill] Failed to send refill receipt email:', emailErr.message || emailErr);
      }

      return { success: true, magnusResponse };
    } else {
      await pool.execute(
        'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
        ['failed', magnusResponse || 'No response', billingId]
      );
      return { success: false, error: 'Failed to add credit to MagnusBilling', magnusResponse };
    }
  } catch (e) {
    if (DEBUG) console.error('[refill] MagnusBilling error:', e.message || e);
    try {
      await pool.execute(
        'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
        ['failed', String(e.message || e), billingId]
      );
    } catch {}
    return { success: false, error: e.message || 'Unknown error' };
  }
}

// Add funds to user account (manual/direct refill)
app.post('/api/me/add-funds', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    const { amount } = req.body || {};

    // Validate amount
    const amountNum = parseFloat(amount);
    if (!amountNum || amountNum <= 0) {
      return res.status(400).json({ success: false, message: 'Amount must be greater than 0' });
    }
    if (amountNum > 10000) {
      return res.status(400).json({ success: false, message: 'Amount cannot exceed $10,000' });
    }

    // Build a standard refill description: username + amount + fixed note
    let username = '';
    let firstName = '';
    let lastName = '';
    let userEmail = '';
    try {
      if (pool) {
        const [rows] = await pool.execute('SELECT username, firstname, lastname, email FROM signup_users WHERE id=? LIMIT 1', [userId]);
        if (rows && rows[0]) {
          if (rows[0].username) username = String(rows[0].username);
          if (rows[0].firstname) firstName = String(rows[0].firstname);
          if (rows[0].lastname) lastName = String(rows[0].lastname);
          if (rows[0].email) userEmail = String(rows[0].email);
        }
      }
    } catch (e) {
      if (DEBUG) console.warn('[add-funds] Failed to fetch user info for description:', e.message || e);
    }
    const baseUser = username || (req.session.username || 'unknown');
    const fullName = `${firstName || ''} ${lastName || ''}`.trim();
    const displayName = fullName || baseUser;
    const descRaw = `${baseUser} - $${amountNum.toFixed(2)} - TalkUSA refill`;
    const desc = descRaw.substring(0, 255);

    // Get Magnus user ID
    const httpsAgent = new https.Agent({
      rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1',
      ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {})
    });
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
    const magnusUserId = await ensureMagnusUserId(req, { httpsAgent, hostHeader });

    if (!magnusUserId) {
      return res.status(400).json({ success: false, message: 'Could not find MagnusBilling user ID' });
    }

    // Insert pending billing record
    const [insertResult] = await pool.execute(
      'INSERT INTO billing_history (user_id, amount, description, status) VALUES (?, ?, ?, ?)',
      [userId, amountNum, desc, 'pending']
    );
    const billingId = insertResult.insertId;

    const result = await applyMagnusRefill({
      userId,
      magnusUserId,
      amountNum,
      desc,
      displayName,
      userEmail,
      httpsAgent,
      hostHeader,
      billingId
    });

    if (result.success) {
      return res.json({ success: true, message: 'Funds added successfully' });
    }
    return res.status(500).json({ success: false, message: 'Failed to add credit: ' + (result.error || 'Unknown error') });
  } catch (e) {
    if (DEBUG) console.error('[add-funds] error:', e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to add funds' });
  }
});

// Create a NOWPayments checkout (Standard e-commerce flow)
// Returns a hosted payment URL where the user can complete a crypto payment.
app.post('/api/me/nowpayments/checkout', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    if (!NOWPAYMENTS_API_KEY) {
      return res.status(500).json({ success: false, message: 'Crypto payments are not configured' });
    }
    const userId = req.session.userId;
    const { amount } = req.body || {};

    const amountNum = parseFloat(amount);
    if (!Number.isFinite(amountNum)) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }
    if (amountNum < CHECKOUT_MIN_AMOUNT || amountNum > CHECKOUT_MAX_AMOUNT) {
      return res.status(400).json({ success: false, message: `Amount must be between $${CHECKOUT_MIN_AMOUNT} and $${CHECKOUT_MAX_AMOUNT}` });
    }

    // Fetch user info for description + email
    let username = '';
    let firstName = '';
    let lastName = '';
    let userEmail = '';
    try {
      const [rows] = await pool.execute('SELECT username, firstname, lastname, email FROM signup_users WHERE id=? LIMIT 1', [userId]);
      if (rows && rows[0]) {
        if (rows[0].username) username = String(rows[0].username);
        if (rows[0].firstname) firstName = String(rows[0].firstname);
        if (rows[0].lastname) lastName = String(rows[0].lastname);
        if (rows[0].email) userEmail = String(rows[0].email);
      }
    } catch (e) {
      if (DEBUG) console.warn('[nowpayments.checkout] Failed to fetch user info:', e.message || e);
    }
    const baseUser = username || (req.session.username || 'unknown');
    const fullName = `${firstName || ''} ${lastName || ''}`.trim();
    const displayName = fullName || baseUser;
    const descRaw = `${baseUser} - $${amountNum.toFixed(2)} - TalkUSA crypto refill`;
    const desc = descRaw.substring(0, 255);

    // Insert pending billing record (we will mark completed after successful IPN)
    const [insertResult] = await pool.execute(
      'INSERT INTO billing_history (user_id, amount, description, status) VALUES (?, ?, ?, ?)',
      [userId, amountNum, desc, 'pending']
    );
    const billingId = insertResult.insertId;

    // Build deterministic order_id encoding userId + billingId for later lookup from IPN
    const orderId = `np-${userId}-${billingId}`;

    // Build IPN & redirect URLs
    const baseUrl = PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;
    const ipnUrl = joinUrl(baseUrl, '/nowpayments/ipn');
    const successUrl = joinUrl(baseUrl, '/dashboard?payment=success&method=crypto');
    const cancelUrl = joinUrl(baseUrl, '/dashboard?payment=cancel&method=crypto');

    const client = nowpaymentsAxios();
    const payload = {
      price_amount: amountNum,
      price_currency: 'usd',
      order_id: orderId,
      order_description: desc,
      ipn_callback_url: ipnUrl,
      success_url: successUrl,
      cancel_url: cancelUrl
    };

    if (DEBUG) console.log('[nowpayments.checkout] Creating invoice:', payload);
    const resp = await client.post('/invoice', payload);
    const data = resp?.data || {};
    const paymentUrl = data.invoice_url || data.payment_url || data.checkout_url || null;
    if (!paymentUrl) {
      if (DEBUG) console.error('[nowpayments.checkout] Missing invoice/payment URL in response:', data);
      await pool.execute(
        'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
        ['failed', JSON.stringify(data), billingId]
      );
      return res.status(502).json({ success: false, message: 'Payment provider did not return a checkout URL' });
    }

    // Record NOWPayments invoice/payment row for tracking/idempotency
    try {
      const remoteId = data.id || data.payment_id || orderId;
      const paymentStatus = data.payment_status || data.invoice_status || 'waiting';
      await pool.execute(
        'INSERT INTO nowpayments_payments (user_id, payment_id, order_id, price_amount, price_currency, payment_status, credited, raw_payload) VALUES (?, ?, ?, ?, ?, ?, 0, ?)',
        [userId, String(remoteId), String(orderId), amountNum, 'usd', String(paymentStatus), JSON.stringify(data)]
      );
    } catch (e) {
      if (DEBUG) console.warn('[nowpayments.checkout] Failed to insert nowpayments_payments row:', e.message || e);
      // Do not fail the checkout creation if this insert fails; IPN can still be processed via order_id encoding
    }

    return res.json({ success: true, payment_url: paymentUrl });
  } catch (e) {
    if (DEBUG) console.error('[nowpayments.checkout] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to create crypto payment' });
  }
});

// Create a Square Payment Link checkout for card payments
// Returns a hosted Square URL where the user can pay with card.
app.post('/api/me/square/checkout', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    if (!SQUARE_ACCESS_TOKEN || !SQUARE_APPLICATION_ID) {
      return res.status(500).json({ success: false, message: 'Card payments are not configured' });
    }
    const userId = req.session.userId;
    const { amount } = req.body || {};

    const amountNum = parseFloat(amount);
    if (!Number.isFinite(amountNum)) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }
    if (amountNum < CHECKOUT_MIN_AMOUNT || amountNum > CHECKOUT_MAX_AMOUNT) {
      return res.status(400).json({ success: false, message: `Amount must be between $${CHECKOUT_MIN_AMOUNT} and $${CHECKOUT_MAX_AMOUNT}` });
    }

    // Fetch user info for description + email
    let username = '';
    let firstName = '';
    let lastName = '';
    let userEmail = '';
    try {
      const [rows] = await pool.execute('SELECT username, firstname, lastname, email FROM signup_users WHERE id=? LIMIT 1', [userId]);
      if (rows && rows[0]) {
        if (rows[0].username) username = String(rows[0].username);
        if (rows[0].firstname) firstName = String(rows[0].firstname);
        if (rows[0].lastname) lastName = String(rows[0].lastname);
        if (rows[0].email) userEmail = String(rows[0].email);
      }
    } catch (e) {
      if (DEBUG) console.warn('[square.checkout] Failed to fetch user info:', e.message || e);
    }
    const baseUser = username || (req.session.username || 'unknown');
    const fullName = `${firstName || ''} ${lastName || ''}`.trim();
    const displayName = fullName || baseUser;
    const descRaw = `${baseUser} - $${amountNum.toFixed(2)} - TalkUSA card refill`;
    const desc = descRaw.substring(0, 255);

    // Insert pending billing record (we will mark completed after successful webhook)
    const [insertResult] = await pool.execute(
      'INSERT INTO billing_history (user_id, amount, description, status) VALUES (?, ?, ?, ?)',
      [userId, amountNum, desc, 'pending']
    );
    const billingId = insertResult.insertId;

    // Build deterministic local order_id encoding userId + billingId for correlation with Square
    const orderId = `sq-${userId}-${billingId}`;

    const baseUrl = PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;
    const redirectUrl = joinUrl(baseUrl, '/dashboard?payment=success&method=card');

    const locationId = await getSquareLocationId();
    if (!locationId) {
      if (DEBUG) console.error('[square.checkout] Could not resolve Square location id');
      await pool.execute(
        'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
        ['failed', 'Square location_id not configured', billingId]
      );
      return res.status(500).json({ success: false, message: 'Card payments are temporarily unavailable' });
    }

    const idempotencyKey = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
    const body = {
      idempotency_key: idempotencyKey,
      quick_pay: {
        name: desc.substring(0, 60),
        price_money: {
          amount: Math.round(amountNum * 100),
          currency: 'USD'
        },
        location_id: locationId
      },
      payment_note: orderId,
      checkout_options: {
        redirect_url: redirectUrl
      }
    };

    if (userEmail) {
      body.pre_populated_data = { buyer_email: userEmail };
    }

    const squareBase = squareApiBaseUrl();
    if (DEBUG) console.log('[square.checkout] Creating payment link:', { orderId, amountNum, locationId });
    const resp = await axios.post(`${squareBase}/v2/online-checkout/payment-links`, body, {
      timeout: 30000,
      headers: {
        'Authorization': `Bearer ${SQUARE_ACCESS_TOKEN}`,
        'Square-Version': '2025-10-16',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });

    const data = resp?.data || {};
    const paymentLink = data.payment_link || {};
    const paymentUrl = paymentLink.url || paymentLink.long_url || null;
    const squareOrderId = paymentLink.order_id || (data.related_resources && data.related_resources.orders && data.related_resources.orders[0] && data.related_resources.orders[0].id) || null;

    if (!paymentUrl) {
      if (DEBUG) console.error('[square.checkout] Missing payment link URL in response:', data);
      await pool.execute(
        'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
        ['failed', JSON.stringify(data), billingId]
      );
      return res.status(502).json({ success: false, message: 'Card payment provider did not return a checkout URL' });
    }

    // Record Square payment link for tracking/idempotency
    try {
      await pool.execute(
        'INSERT INTO square_payments (user_id, payment_link_id, order_id, square_order_id, amount, currency, status, credited, raw_payload) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)',
        [userId, String(paymentLink.id || orderId), String(orderId), squareOrderId, amountNum, 'USD', 'pending', JSON.stringify(data)]
      );
    } catch (e) {
      if (DEBUG) console.warn('[square.checkout] Failed to insert square_payments row:', e.message || e);
      // Do not fail the checkout creation if this insert fails; webhook can still be correlated via payment_note/order_id
    }

    return res.json({ success: true, payment_url: paymentUrl });
  } catch (e) {
    if (DEBUG) console.error('[square.checkout] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to create card payment' });
  }
});

// NOWPayments IPN webhook (server-to-server callback)
app.post('/nowpayments/ipn', async (req, res) => {
  try {
    if (!pool) {
      return res.status(500).json({ success: false, message: 'Database not configured' });
    }

    // Verify HMAC signature
    const sigOk = verifyNowpaymentsSignature(req);
    if (!sigOk) {
      if (DEBUG) console.warn('[nowpayments.ipn] Invalid signature');
      return res.status(400).json({ success: false, message: 'Invalid signature' });
    }

    const p = req.body || {};
    if (DEBUG) console.log('[nowpayments.ipn] Payload:', JSON.stringify(p));

    const orderId = String(p.order_id || '').trim();
    const paymentStatus = String(p.payment_status || '').toLowerCase();
    const priceAmount = parseFloat(p.price_amount || '0');
    const payAmount = p.pay_amount != null ? parseFloat(p.pay_amount) : null;
    const payCurrency = p.pay_currency || null;
    const remotePaymentId = p.payment_id || p.id || null;

    if (!orderId) {
      if (DEBUG) console.warn('[nowpayments.ipn] Missing order_id in IPN payload');
      return res.status(200).json({ success: true, ignored: true });
    }

    // Order id format: np-<userId>-<billingId>
    const m = /^np-(\d+)-(\d+)$/.exec(orderId);
    if (!m) {
      if (DEBUG) console.warn('[nowpayments.ipn] order_id does not match expected pattern:', orderId);
      return res.status(200).json({ success: true, ignored: true });
    }
    const userId = Number(m[1]);
    const billingId = Number(m[2]);

    // Fetch billing_history row
    const [billingRows] = await pool.execute(
      'SELECT id, user_id, amount, description, status FROM billing_history WHERE id = ? LIMIT 1',
      [billingId]
    );
    const billing = billingRows && billingRows[0];
    if (!billing || String(billing.user_id) !== String(userId)) {
      if (DEBUG) console.warn('[nowpayments.ipn] Billing row not found or user mismatch for order:', { orderId, userId, billingId });
      return res.status(200).json({ success: true, ignored: true });
    }

    // Upsert nowpayments_payments row for tracking
    let existing = null;
    try {
      const [npRows] = await pool.execute(
        'SELECT * FROM nowpayments_payments WHERE order_id = ? LIMIT 1',
        [orderId]
      );
      existing = npRows && npRows[0] ? npRows[0] : null;
    } catch (e) {
      if (DEBUG) console.warn('[nowpayments.ipn] Failed to select nowpayments_payments row:', e.message || e);
    }

    const paymentStatusLabel = paymentStatus || 'unknown';
    const payloadJson = JSON.stringify(p);
    if (existing) {
      try {
        await pool.execute(
          'UPDATE nowpayments_payments SET payment_id = ?, price_amount = ?, price_currency = ?, pay_amount = ?, pay_currency = ?, payment_status = ?, raw_payload = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
          [remotePaymentId || existing.payment_id || orderId, priceAmount || billing.amount, p.price_currency || 'usd', payAmount, payCurrency, paymentStatusLabel, payloadJson, existing.id]
        );
      } catch (e) {
        if (DEBUG) console.warn('[nowpayments.ipn] Failed to update nowpayments_payments row:', e.message || e);
      }
    } else {
      try {
        await pool.execute(
          'INSERT INTO nowpayments_payments (user_id, payment_id, order_id, price_amount, price_currency, pay_amount, pay_currency, payment_status, credited, raw_payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)',
          [userId, String(remotePaymentId || orderId), String(orderId), priceAmount || billing.amount, p.price_currency || 'usd', payAmount, payCurrency, paymentStatusLabel, payloadJson]
        );
      } catch (e) {
        if (DEBUG) console.warn('[nowpayments.ipn] Failed to insert nowpayments_payments row:', e.message || e);
      }
    }

    // Handle non-finished statuses: distinguish pending vs terminal failure
    if (paymentStatus !== 'finished') {
      const normalized = paymentStatusLabel.toLowerCase();
      const pendingStatuses = ['waiting', 'confirming', 'confirmed', 'sending'];
      const isPending = pendingStatuses.includes(normalized);

      if (!isPending) {
        // Terminal state: mark billing row as failed
        try {
          await pool.execute(
            'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
            ['failed', payloadJson, billingId]
          );
        } catch (e) {
          if (DEBUG) console.warn('[nowpayments.ipn] Failed to mark billing as failed for order:', orderId, e.message || e);
        }
        if (DEBUG) console.log('[nowpayments.ipn] Terminal status, marking failed:', { orderId, status: paymentStatusLabel });
        return res.status(200).json({ success: true, failed: true });
      }

      if (DEBUG) console.log('[nowpayments.ipn] Payment not finished yet, status=', paymentStatusLabel);
      return res.status(200).json({ success: true, pending: true });
    }

    // Acquire a per-order lock to prevent double-crediting the same NOWPayments order.
    let lockAcquired = false;
    try {
      const [lockResult] = await pool.execute(
        'UPDATE nowpayments_payments SET credited = 2 WHERE order_id = ? AND credited = 0',
        [orderId]
      );
      lockAcquired = !!(lockResult && lockResult.affectedRows > 0);
    } catch (e) {
      if (DEBUG) console.warn('[nowpayments.ipn] Failed to acquire processing lock:', e.message || e);
    }

    if (!lockAcquired) {
      // Someone else has already processed or is processing this order.
      try {
        const [npRows2] = await pool.execute(
          'SELECT credited FROM nowpayments_payments WHERE order_id = ? LIMIT 1',
          [orderId]
        );
        const creditedVal = npRows2 && npRows2[0] ? Number(npRows2[0].credited || 0) : 0;
        if (creditedVal === 1) {
          if (DEBUG) console.log('[nowpayments.ipn] Order already credited, skipping duplicate:', { orderId, billingId });
          return res.status(200).json({ success: true, alreadyCredited: true });
        }
        if (DEBUG) console.log('[nowpayments.ipn] Order is being processed by another handler, skipping duplicate:', { orderId, billingId, credited: creditedVal });
        return res.status(200).json({ success: true, pending: true, duplicate: true });
      } catch (e) {
        if (DEBUG) console.warn('[nowpayments.ipn] Failed to re-read nowpayments_payments for lock check:', e.message || e);
        // Do not risk double-charging if we are unsure.
        return res.status(200).json({ success: true, pending: true });
      }
    }

    // If billing row is already completed, treat this as already credited and
    // simply sync the credited flag.
    if (billing.status === 'completed') {
      if (DEBUG) console.log('[nowpayments.ipn] Billing already completed, skipping refill:', { billingId, orderId });
      try {
        await pool.execute(
          'UPDATE nowpayments_payments SET credited = 1 WHERE order_id = ? AND credited <> 1',
          [orderId]
        );
      } catch (e) {
        if (DEBUG) console.warn('[nowpayments.ipn] Failed to sync credited flag for already-completed billing:', e.message || e);
      }
      return res.status(200).json({ success: true, alreadyCredited: true });
    }

    // Fetch user + MagnusBilling id
    const [userRows] = await pool.execute(
      'SELECT id, magnus_user_id, username, firstname, lastname, email FROM signup_users WHERE id = ? LIMIT 1',
      [userId]
    );
    const user = userRows && userRows[0];
    if (!user) {
      if (DEBUG) console.warn('[nowpayments.ipn] User not found for order:', { orderId, userId });
      return res.status(200).json({ success: true, ignored: true });
    }
    const magnusUserId = String(user.magnus_user_id || '').trim();
    if (!magnusUserId) {
      if (DEBUG) console.warn('[nowpayments.ipn] Missing magnus_user_id for user:', { userId });
      return res.status(200).json({ success: true, ignored: true });
    }

    const nameBase = user.username || '';
    const fullName2 = `${user.firstname || ''} ${user.lastname || ''}`.trim();
    const displayName = fullName2 || nameBase || 'Customer';
    const userEmail = user.email || '';

    // Use the amount from billing_history as source of truth (what we asked customer to pay)
    const amountNum = Number(billing.amount || priceAmount || 0);
    const desc = billing.description || p.order_description || `TalkUSA crypto refill (${orderId})`;

    const httpsAgent = magnusBillingAgent;
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;

    const result = await applyMagnusRefill({
      userId,
      magnusUserId,
      amountNum,
      desc,
      displayName,
      userEmail,
      httpsAgent,
      hostHeader,
      billingId
    });

    if (!result.success) {
      if (DEBUG) console.error('[nowpayments.ipn] Failed to credit MagnusBilling for order:', { orderId, error: result.error });
      // Release the processing lock so a future IPN can retry.
      try {
        await pool.execute(
          'UPDATE nowpayments_payments SET credited = 0 WHERE order_id = ? AND credited = 2',
          [orderId]
        );
      } catch (e) {
        if (DEBUG) console.warn('[nowpayments.ipn] Failed to revert credited flag after error:', e.message || e);
      }
      return res.status(500).json({ success: false, message: 'Failed to credit MagnusBilling' });
    }

    // Mark as credited
    try {
      await pool.execute(
        'UPDATE nowpayments_payments SET credited = 1 WHERE order_id = ?',
        [orderId]
      );
    } catch (e) {
      if (DEBUG) console.warn('[nowpayments.ipn] Failed to mark payment as credited:', e.message || e);
    }

    if (DEBUG) console.log('[nowpayments.ipn] Successfully credited order:', { orderId, billingId, userId });
    return res.status(200).json({ success: true });
  } catch (e) {
    if (DEBUG) console.error('[nowpayments.ipn] Unhandled error:', e.message || e);
    return res.status(500).json({ success: false, message: 'IPN handling failed' });
  }
});

// Square webhook for card payments (payment.updated -> COMPLETED)
app.post('/webhooks/square', async (req, res) => {
  try {
    if (!pool) {
      return res.status(500).json({ success: false, message: 'Database not configured' });
    }

    const sigOk = verifySquareSignature(req);
    if (!sigOk) {
      if (DEBUG) console.warn('[square.webhook] Invalid signature');
      return res.status(400).json({ success: false, message: 'Invalid signature' });
    }

    const evt = req.body || {};
    const type = String(evt.type || '').toLowerCase();
    if (type !== 'payment.updated' && type !== 'payment.created') {
      return res.status(200).json({ success: true, ignored: true });
    }

    const dataObj = evt.data || {};
    const payment = dataObj.object && dataObj.object.payment ? dataObj.object.payment : null;
    if (!payment) {
      if (DEBUG) console.warn('[square.webhook] Missing payment object in event');
      return res.status(200).json({ success: true, ignored: true });
    }

    const status = String(payment.status || '').toUpperCase();

    const squareOrderId = payment.order_id || null;
    if (!squareOrderId) {
      if (DEBUG) console.warn('[square.webhook] Missing order_id on payment');
      return res.status(200).json({ success: true, ignored: true });
    }

    // Look up our local square_payments record
    const [sqRows] = await pool.execute(
      'SELECT * FROM square_payments WHERE square_order_id = ? LIMIT 1',
      [squareOrderId]
    );
    const sq = sqRows && sqRows[0] ? sqRows[0] : null;
    if (!sq) {
      if (DEBUG) console.warn('[square.webhook] No local square_payments row for order:', squareOrderId);
      return res.status(200).json({ success: true, ignored: true });
    }

    // Handle non-completed statuses: mark terminal failures
    if (status !== 'COMPLETED') {
      const terminal = ['FAILED', 'CANCELED'];
      const isTerminal = terminal.includes(status);

      if (isTerminal) {
        const localOrderIdFail = String(sq.order_id || '');
        const mFail = /^sq-(\d+)-(\d+)$/.exec(localOrderIdFail);
        if (mFail) {
          const userIdFail = Number(mFail[1]);
          const billingIdFail = Number(mFail[2]);
          try {
            const [bRows] = await pool.execute(
              'SELECT id, user_id, status FROM billing_history WHERE id = ? LIMIT 1',
              [billingIdFail]
            );
            const bRow = bRows && bRows[0] ? bRows[0] : null;
            if (bRow && String(bRow.user_id) === String(userIdFail) && bRow.status !== 'completed') {
              await pool.execute(
                'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
                ['failed', `Square status: ${status}`, billingIdFail]
              );
            }
          } catch (e) {
            if (DEBUG) console.warn('[square.webhook] Failed to mark billing as failed for order:', localOrderIdFail, e.message || e);
          }

          try {
            await pool.execute(
              'UPDATE square_payments SET status = ?, credited = 0 WHERE id = ?',
              [status, sq.id]
            );
          } catch (e) {
            if (DEBUG) console.warn('[square.webhook] Failed to update square_payments for failed status:', e.message || e);
          }

          if (DEBUG) console.log('[square.webhook] Terminal status, marking failed:', { orderId: squareOrderId, status });
          return res.status(200).json({ success: true, failed: true });
        }
      }

      if (DEBUG) console.log('[square.webhook] Payment not completed yet, status=', status);
      return res.status(200).json({ success: true, pending: true });
    }

    // Acquire a per-payment lock to prevent double-crediting the same order.
    let lockAcquired = false;
    try {
      const [lockResult] = await pool.execute(
        'UPDATE square_payments SET status = ?, credited = 2 WHERE id = ? AND credited = 0',
        ['PROCESSING', sq.id]
      );
      lockAcquired = !!(lockResult && lockResult.affectedRows > 0);
    } catch (e) {
      if (DEBUG) console.warn('[square.webhook] Failed to acquire processing lock:', e.message || e);
    }

    if (!lockAcquired) {
      // Someone else has already processed or is processing this payment.
      try {
        const [freshRows] = await pool.execute(
          'SELECT credited FROM square_payments WHERE id = ? LIMIT 1',
          [sq.id]
        );
        const fresh = freshRows && freshRows[0] ? freshRows[0] : null;
        const creditedVal = fresh ? Number(fresh.credited || 0) : Number(sq.credited || 0);
        if (creditedVal === 1) {
          if (DEBUG) console.log('[square.webhook] Payment already credited, skipping duplicate:', { id: sq.id, order_id: sq.order_id });
          return res.status(200).json({ success: true, alreadyCredited: true });
        }
        if (DEBUG) console.log('[square.webhook] Payment is being processed by another handler, skipping duplicate:', { id: sq.id, order_id: sq.order_id, credited: creditedVal });
        return res.status(200).json({ success: true, pending: true, duplicate: true });
      } catch (e) {
        if (DEBUG) console.warn('[square.webhook] Failed to re-read square_payments for lock check:', e.message || e);
        // Do not risk double-charging if we are unsure.
        return res.status(200).json({ success: true, pending: true });
      }
    }

    const localOrderId = String(sq.order_id || '');
    const m = /^sq-(\d+)-(\d+)$/.exec(localOrderId);
    if (!m) {
      if (DEBUG) console.warn('[square.webhook] order_id does not match expected pattern:', localOrderId);
      return res.status(200).json({ success: true, ignored: true });
    }
    const userId = Number(m[1]);
    const billingId = Number(m[2]);

    // Fetch billing_history row
    const [billingRows] = await pool.execute(
      'SELECT id, user_id, amount, description, status FROM billing_history WHERE id = ? LIMIT 1',
      [billingId]
    );
    const billing = billingRows && billingRows[0] ? billingRows[0] : null;
    if (!billing || String(billing.user_id) !== String(userId)) {
      if (DEBUG) console.warn('[square.webhook] Billing row not found or user mismatch for order:', { localOrderId, userId, billingId });
      return res.status(200).json({ success: true, ignored: true });
    }

    // If billing row is already completed, treat this as already credited
    if (billing.status === 'completed') {
      if (DEBUG) console.log('[square.webhook] Billing already completed, skipping refill:', { billingId, localOrderId });
      try {
        await pool.execute(
          'UPDATE square_payments SET status = ?, credited = 1 WHERE id = ? AND credited <> 1',
          ['COMPLETED', sq.id]
        );
      } catch (e) {
        if (DEBUG) console.warn('[square.webhook] Failed to sync credited flag for already-completed billing:', e.message || e);
      }
      return res.status(200).json({ success: true, alreadyCredited: true });
    }

    // Fetch user row for MagnusBilling id and email
    const [userRows] = await pool.execute(
      'SELECT id, magnus_user_id, username, firstname, lastname, email FROM signup_users WHERE id = ? LIMIT 1',
      [userId]
    );
    const user = userRows && userRows[0] ? userRows[0] : null;
    if (!user) {
      if (DEBUG) console.warn('[square.webhook] User not found for order:', { localOrderId, userId });
      return res.status(200).json({ success: true, ignored: true });
    }

    const magnusUserId = String(user.magnus_user_id || '').trim();
    if (!magnusUserId) {
      if (DEBUG) console.warn('[square.webhook] Missing magnus_user_id for user:', { userId });
      return res.status(200).json({ success: true, ignored: true });
    }

    const nameBase = user.username || '';
    const fullName = `${user.firstname || ''} ${user.lastname || ''}`.trim();
    const displayName = fullName || nameBase || 'Customer';
    const userEmail = user.email || '';

    // Use the amount from billing_history as source of truth (what we asked customer to pay)
    const amountNum = Number(billing.amount || 0);
    const desc = billing.description || `TalkUSA card refill (${localOrderId})`;

    const httpsAgent = magnusBillingAgent;
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;

    const result = await applyMagnusRefill({
      userId,
      magnusUserId,
      amountNum,
      desc,
      displayName,
      userEmail,
      httpsAgent,
      hostHeader,
      billingId
    });

    if (!result.success) {
      if (DEBUG) console.error('[square.webhook] Failed to credit MagnusBilling for order:', { localOrderId, error: result.error });
      // Release the processing lock so a future retry can attempt again.
      try {
        await pool.execute(
          'UPDATE square_payments SET status = ?, credited = 0 WHERE id = ? AND credited = 2',
          ['FAILED', sq.id]
        );
      } catch (e) {
        if (DEBUG) console.warn('[square.webhook] Failed to revert credited flag after error:', e.message || e);
      }
      return res.status(500).json({ success: false, message: 'Failed to credit MagnusBilling' });
    }

    // Mark as credited and save latest payload
    try {
      await pool.execute(
        'UPDATE square_payments SET status = ?, square_payment_id = ?, credited = 1, raw_payload = ? WHERE id = ?',
        ['COMPLETED', String(payment.id || sq.square_payment_id || ''), JSON.stringify(evt), sq.id]
      );
    } catch (e) {
      if (DEBUG) console.warn('[square.webhook] Failed to mark payment as credited:', e.message || e);
    }

    if (DEBUG) console.log('[square.webhook] Successfully credited order:', { localOrderId, billingId, userId });
    return res.status(200).json({ success: true });
  } catch (e) {
    if (DEBUG) console.error('[square.webhook] Unhandled error:', e.message || e);
    return res.status(500).json({ success: false, message: 'Webhook handling failed' });
  }
});

// DIDWW Voice IN CDR Streaming webhook (Call Events API)
app.post(
  '/webhooks/didww/voice-in-cdr',
  express.raw({ type: '*/*', limit: '5mb' }),
  async (req, res) => {
    try {
      if (!pool) {
        if (DEBUG) console.warn('[didww.cdr] Database not configured');
        // Acknowledge to avoid endless retries if the app is misconfigured.
        return res.status(200).end();
      }

      // HTTP Basic Auth (configured in DIDWW portal)
      const authHeader = req.headers.authorization || '';
      const m = /^Basic\s+(.+)$/.exec(authHeader);
      if (!m) {
        if (DEBUG) console.warn('[didww.cdr] Missing Authorization header');
        return res.status(401).end();
      }
      let basicUser = '';
      let basicPass = '';
      try {
        const decoded = Buffer.from(m[1], 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        basicUser = idx >= 0 ? decoded.slice(0, idx) : decoded;
        basicPass = idx >= 0 ? decoded.slice(idx + 1) : '';
      } catch {
        if (DEBUG) console.warn('[didww.cdr] Failed to decode Basic auth header');
        return res.status(401).end();
      }

      if (
        basicUser !== (process.env.DIDWW_CDR_BASIC_USER || '') ||
        basicPass !== (process.env.DIDWW_CDR_BASIC_PASS || '')
      ) {
        if (DEBUG) console.warn('[didww.cdr] Invalid Basic auth credentials');
        return res.status(401).end();
      }

      // Optional X-Auth-Token header (not enforced). If you want an extra
      // shared secret in the future, you can re-enable this check.
      // const token = req.get('X-Auth-Token') || '';
      // if (!token || token !== (process.env.DIDWW_CDR_X_AUTH_TOKEN || '')) {
      //   if (DEBUG) console.warn('[didww.cdr] Invalid X-Auth-Token header');
      //   return res.status(403).end();
      // }

      // Handle optional gzip compression
      const encoding = String(req.headers['content-encoding'] || '').toLowerCase();
      let bodyBuffer = req.body;
      if (!Buffer.isBuffer(bodyBuffer)) {
        bodyBuffer = Buffer.from(bodyBuffer || '');
      }

      // Some deployments or proxies may send plain JSON while still setting
      // Content-Encoding: gzip. Only gunzip when it is *actually* gzip.
      const looksGzip =
        bodyBuffer.length >= 2 &&
        bodyBuffer[0] === 0x1f &&
        bodyBuffer[1] === 0x8b;
      const headerSaysGzip = encoding.includes('gzip');

      if (headerSaysGzip && looksGzip) {
        try {
          bodyBuffer = zlib.gunzipSync(bodyBuffer);
        } catch (e) {
          // If it really looks like gzip but we can't decode it, return 5xx so DIDWW can retry.
          if (DEBUG) console.warn('[didww.cdr] Failed to gunzip gzipped body:', e.message || e);
          return res.status(500).end();
        }
      }

      // If the header claims gzip but body isn't gzipped, treat as plain text.
      // (No warning; still parse as JSON/NDJSON.)

      const text = bodyBuffer.toString('utf8');
      if (!text.trim()) {
        if (DEBUG) console.warn('[didww.cdr] Received empty body after decoding; nothing to process');
        return res.status(200).end();
      }

      if (DEBUG) {
        const preview = text.length > 400 ? text.slice(0, 400) + '…' : text;
        console.log('[didww.cdr] Raw body preview:', preview.replace(/\s+/g, ' ').slice(0, 400));
      }

      const didUserCache = new Map(); // did_number -> user_id | null

      // DIDWW may send either a single JSON object or newline-delimited JSON.
      // Try to parse the whole body first; if that fails, fall back to per-line.
      const records = [];
      try {
        const obj = JSON.parse(text);
        records.push(obj);
      } catch {
        const lines = text.split('\n');
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            records.push(JSON.parse(line));
          } catch (e) {
            if (DEBUG) console.warn('[didww.cdr] JSON parse failed for line:', e.message || e, 'line=', line.slice(0, 200));
          }
        }
      }

      for (const cdr of records) {
        if (!cdr || typeof cdr !== 'object') continue;

        const attrs = cdr.attributes || {};
        const didNumber = attrs.did_number || attrs.dst_number || null;
        const srcNumber = attrs.src_number || attrs.cli || null;
        const dstNumber = attrs.dst_number || attrs.did_number || null;
        const timeStart = attrs.time_start ? new Date(attrs.time_start) : null;
        const timeConnect = attrs.time_connect ? new Date(attrs.time_connect) : null;
        const timeEnd = attrs.time_end ? new Date(attrs.time_end) : null;
        const duration = attrs.duration != null ? Number(attrs.duration) || 0 : null;

        // billsec is the number of seconds we bill the customer for.
        // DIDWW does not always send a dedicated billsec field for inbound CDRs,
        // so derive it from the most reliable attributes we have:
        //   1) attrs.billsec (if present)
        //   2) attrs.duration (actual call duration in seconds)
        //   3) attrs.metered_channels_duration (wholesale billed seconds)
        //   4) Difference between time_end and time_connect
        let billsec = null;
        if (attrs.billsec != null) {
          billsec = Number(attrs.billsec) || 0;
        }
        if (!billsec && duration != null) {
          billsec = duration;
        }
        if (!billsec && attrs.metered_channels_duration != null) {
          billsec = Number(attrs.metered_channels_duration) || 0;
        }
        if (!billsec && timeConnect && timeEnd) {
          const diffSec = Math.round((timeEnd.getTime() - timeConnect.getTime()) / 1000);
          if (Number.isFinite(diffSec) && diffSec > 0) billsec = diffSec;
        }

        // DIDWW-provided price (may be 0); kept only for debugging/auditing in raw_cdr
        const carrierPrice = attrs.price != null ? Number(attrs.price) || 0 : null;
        const cdrId = cdr.id ? String(cdr.id) : null;
        const direction = String(cdr.type || 'inbound-cdr').includes('outbound') ? 'outbound' : 'inbound';

        if (!didNumber) {
          if (DEBUG) console.warn('[didww.cdr] Missing did_number/dst_number in CDR; skipping');
          continue;
        }

        let userId = null;
        if (didUserCache.has(didNumber)) {
          userId = didUserCache.get(didNumber);
        } else {
          try {
            const [rows] = await pool.execute(
              'SELECT user_id FROM user_dids WHERE did_number = ? LIMIT 1',
              [didNumber]
            );
            userId = rows && rows[0] ? rows[0].user_id : null;
          } catch (e) {
            if (DEBUG) console.warn('[didww.cdr] Failed to lookup DID owner:', e.message || e);
          }
          didUserCache.set(didNumber, userId);
        }

        // Rate this CDR using flat per-second retail pricing derived from per-minute rates
        let retailPrice = 0;
        try {
          const tollfreeNpas = ['800','833','844','855','866','877','888'];
          let isTollfreeDid = false;
          if (didNumber) {
            const rawNum = String(didNumber).replace(/\D/g, '');
            if (rawNum) {
              const digits = rawNum.length > 11 ? rawNum.slice(-11) : rawNum;
              const npa = digits.startsWith('1') ? digits.slice(1,4) : digits.slice(0,3);
              if (tollfreeNpas.includes(npa)) isTollfreeDid = true;
            }
          }
          const ratePerMin = isTollfreeDid ? INBOUND_TOLLFREE_RATE_PER_MIN : INBOUND_LOCAL_RATE_PER_MIN;
          if (billsec != null && billsec > 0 && ratePerMin > 0) {
            const ratePerSec = ratePerMin / 60;
            retailPrice = Number((billsec * ratePerSec).toFixed(6));
          } else {
            retailPrice = 0;
          }
          if (DEBUG) console.log('[didww.cdr.rate]', {
            didNumber,
            duration,
            billsec,
            isTollfreeDid,
            ratePerMin,
            retailPrice
          });
        } catch (e) {
          if (DEBUG) console.warn('[didww.cdr] Rating failed, falling back to carrier price:', e.message || e);
          retailPrice = carrierPrice != null ? carrierPrice : 0;
        }

        try {
          await pool.execute(
            'INSERT IGNORE INTO user_did_cdrs (cdr_id, user_id, did_number, direction, src_number, dst_number, time_start, time_connect, time_end, duration, billsec, price, raw_cdr) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
              cdrId,
              userId,
              didNumber,
              direction,
              srcNumber,
              dstNumber,
              timeStart,
              timeConnect,
              timeEnd,
              duration,
              billsec,
              retailPrice,
              JSON.stringify(cdr)
            ]
          );
        } catch (e) {
          if (DEBUG) console.warn('[didww.cdr] Failed to insert CDR row:', e.message || e);
        }
      }

      return res.status(200).end();
    } catch (e) {
      if (DEBUG) console.error('[didww.cdr] Unhandled error:', e.message || e);
      return res.status(500).end();
    }
  }
);

app.get('/api/me/sip-users', requireAuth, async (req, res) => {
  try {
    const httpsAgent = new https.Agent({ rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1', ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}) });
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
    let idUser = await ensureMagnusUserId(req, { httpsAgent, hostHeader });
    const username = req.session.username;
    
    if (!idUser) {
      console.warn('[me.sip] No Magnus user ID found for session user', { username, sessionUserId: req.session.userId });
      return res.json({ success: true, data: { rows: [], page: 0, pageSize: 0 }, message: 'User ID not found' });
    }
    
    const page = Math.max(0, parseInt(req.query.page || '0', 10));
    const pageSize = Math.max(1, parseInt(req.query.pageSize || String(MB_PAGE_SIZE), 10));
    const start = page * pageSize;
    const params = new URLSearchParams();
    params.append('module', MB_SIP_MODULE);
    params.append('action', 'read');
    params.append('start', '0'); // Fetch all, then filter client-side
    params.append('limit', '200'); // Increased limit to catch all potential accounts
    params.append('id_user', String(idUser));
    params.append('idUser', String(idUser));
    params.append('userid', String(idUser));
    const path = `/index.php/${MB_SIP_MODULE}/read`;
    const resp = await mbSignedCall({ relPath: path, params, httpsAgent, hostHeader });
    const rawRows = resp?.data?.rows || resp?.data?.data || [];
    if (DEBUG) console.log('[me.sip.raw]', { queryUserId: idUser, totalRows: rawRows.length, userIds: rawRows.map(r => r.id_user || r.idUser || r.userid).filter((v,i,a) => a.indexOf(v) === i) });
    // Strict filtering: only show SIP accounts that belong to this Magnus user ID
    const allFilteredRows = rawRows.filter(r => sipBelongsToUser(r, idUser));
    // Apply client-side pagination
    const paginatedRows = allFilteredRows.slice(start, start + pageSize);
    console.log('[me.sip]', { userId: idUser, username, in: rawRows.length, filtered: allFilteredRows.length, out: paginatedRows.length, page, pageSize });
    if (DEBUG && paginatedRows.length > 0) console.log('[me.sip.sample]', JSON.stringify(redactSipRow(paginatedRows[0])));
    if (DEBUG && rawRows.length > 0 && allFilteredRows.length === 0) console.warn('[me.sip] All rows filtered out. Sample raw row:', JSON.stringify(redactSipRow(rawRows[0])));
    return res.json({ success: true, data: { rows: paginatedRows, page, pageSize, total: allFilteredRows.length } });
  } catch (e) { 
    console.error('[me.sip.error]', e.message || e, e.stack);
    return res.status(500).json({ success: false, message: 'SIP users fetch failed' }); 
  }
});

// Check SIP username availability (case-insensitive) across instance
app.get('/api/me/sip-users/availability', requireAuth, async (req, res) => {
  try {
    const sipUser = String((req.query.sipUser||'')).trim();
    if (!sipUser) return res.status(400).json({ success: false, message: 'Missing sipUser' });
    const httpsAgent = new https.Agent({ rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1', ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}) });
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
    const params = new URLSearchParams();
    params.append('module', MB_SIP_MODULE);
    params.append('action','read');
    params.append('start','0');
    params.append('limit','1000');
    const path = `/index.php/${MB_SIP_MODULE}/read`;
    const resp = await mbSignedCall({ relPath: path, params, httpsAgent, hostHeader });
    const rawRows = resp?.data?.rows || resp?.data?.data || [];
    const target = sipUser.toLowerCase();
    const exists = rawRows.some(r => [r?.username, r?.name, r?.accountcode, r?.defaultuser]
      .some(v => String(v||'').toLowerCase() === target));
    return res.json({ success: true, available: !exists });
  } catch (e) {
    if (DEBUG) console.warn('[sip.available] error', e.message||e);
    return res.status(500).json({ success: false, message: 'Availability check failed' });
  }
});

// Create SIP user for the logged-in Magnus user
app.post('/api/me/sip-users', requireAuth, async (req, res) => {
  try {
    const httpsAgent = new https.Agent({ rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1', ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}) });
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
    const idUser = await ensureMagnusUserId(req, { httpsAgent, hostHeader });
    if (!idUser) return res.status(400).json({ success: false, message: 'User ID not found' });
    
    // Fetch user details to check user type/group
    if (DEBUG) {
      try {
        const userRow = await fetchUserRow({ idUser, httpsAgent, hostHeader });
        console.log('[sip.create] User details:', { id: userRow?.id || userRow?.id_user, username: userRow?.username, id_group: userRow?.id_group, user_type: userRow?.user_type });
      } catch (e) { console.warn('[sip.create] Could not fetch user details:', e.message); }
    }
    
    const { sipUser, password, callerid } = req.body || {};
    if (!sipUser || !password) return res.status(400).json({ success: false, message: 'sipUser and password are required' });
    if (!callerid || !/^\d{11}$/.test(String(callerid))) return res.status(400).json({ success: false, message: 'CallerID must be numbers only, exactly 11 digits.' });
    
    // Server-side availability check to prevent duplicates
    try {
      const params = new URLSearchParams();
      params.append('module', MB_SIP_MODULE); params.append('action','read'); params.append('start','0'); params.append('limit','1000');
      const path = `/index.php/${MB_SIP_MODULE}/read`;
      const resp = await mbSignedCall({ relPath: path, params, httpsAgent, hostHeader });
      const rawRows = resp?.data?.rows || resp?.data?.data || [];
      const target = String(sipUser).toLowerCase();
      const exists = rawRows.some(r => [r?.username, r?.name, r?.accountcode, r?.defaultuser]
        .some(v => String(v||'').toLowerCase() === target));
      if (exists) return res.status(409).json({ success: false, message: 'SIP username already exists. Choose another.' });
    } catch (e) { if (DEBUG) console.warn('[sip.create] availability check failed', e.message||e); }
    
    // Codec list used for SIP accounts
    const codecs = 'g729,gsm,alaw,ulaw,g722';
    
    // Fetch user details to check user type/group
    // Try multiple alias combinations to accommodate instance differences
    // MagnusBilling requires accountcode to match the SIP username
    const attempts = [
      (p)=>{ 
        p.append('name', sipUser); 
        p.append('accountcode', sipUser); 
        p.append('defaultuser', sipUser);
        p.append('secret', password); 
        p.append('id_user', String(idUser)); 
        p.append('host', 'dynamic');
        p.append('allow', codecs);
        if (callerid) p.append('callerid', callerid); 
      },
      (p)=>{ 
        p.append('username', sipUser); 
        p.append('accountcode', sipUser); 
        p.append('defaultuser', sipUser);
        p.append('secret', password); 
        p.append('id_user', String(idUser)); 
        p.append('host', 'dynamic');
        p.append('allow', codecs);
        if (callerid) p.append('callerid', callerid); 
      },
      (p)=>{ 
        p.append('name', sipUser); 
        p.append('accountcode', sipUser); 
        p.append('defaultuser', sipUser);
        p.append('secret', password); 
        p.append('idUser', String(idUser)); 
        p.append('host', 'dynamic');
        p.append('allow', codecs);
        if (callerid) p.append('cid', callerid); 
      }
    ];
    const errors = [];
    for (const build of attempts) {
      try {
        const params = new URLSearchParams();
        params.append('module', MB_SIP_MODULE);
        params.append('action', 'save');
        params.append('id', '0');
        params.append('status', '1');
        build(params);
        const path = `/index.php/${MB_SIP_MODULE}/save`;
        if (DEBUG) {
          const safeParams = Object.fromEntries(params.entries());
          for (const key of ['secret','password']) {
            if (key in safeParams) safeParams[key] = '***REDACTED***';
          }
          console.log('[sip.create] Attempting with params:', safeParams);
        }
        const resp = await mbSignedCall({ relPath: path, params, httpsAgent, hostHeader });
        if (DEBUG) console.log('[sip.create] Response:', { status: resp.status, data: resp.data });
        const ok = (resp.status>=200 && resp.status<300) && (resp.data?.success===true || /success/i.test(String(resp.data)));
        if (ok) return res.json({ success: true, data: resp.data });
        errors.push(resp.data || resp.statusText || 'unknown error');
      } catch (e) { 
        if (DEBUG) console.log('[sip.create] Attempt failed:', e?.response?.data || e.message || e);
        errors.push(e?.response?.data || e.message || e); 
      }
    }
    if (DEBUG) console.error('[sip.create] All attempts failed:', errors);
    // Check if the error is a permission issue
    const hasPermissionError = errors.some(e => typeof e === 'object' && e.errors && /only can create SipAccount to clients/i.test(e.errors));
    if (hasPermissionError) {
      return res.status(403).json({ 
        success: false, 
        message: 'Your account does not have permission to create SIP users. Please contact support.',
        details: 'User must be in the correct group (typically group 3 - Client) to create SIP accounts.'
      });
    }
    return res.status(400).json({ success: false, message: 'Failed to create SIP user', errors });
  } catch (e) { return res.status(500).json({ success: false, message: 'SIP user create failed' }); }
});

// Delete SIP user (must belong to current user)
app.delete('/api/me/sip-users/:id', requireAuth, async (req, res) => {
  try {
    const httpsAgent = new https.Agent({ rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1', ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}) });
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
    const idUser = await ensureMagnusUserId(req, { httpsAgent, hostHeader });
    if (!idUser) return res.status(400).json({ success: false, message: 'User ID not found' });
    const sipId = String(req.params.id || '');
    if (!sipId) return res.status(400).json({ success: false, message: 'Missing SIP user id' });
    const attempts = [
      { action: 'destroy', idKey: 'id' },
      { action: 'delete', idKey: 'id' }
    ];
    for (const a of attempts) {
      try {
        const params = new URLSearchParams();
        params.append('module', MB_SIP_MODULE); params.append('action', a.action);
        params.append(a.idKey, sipId);
        params.append('id_user', String(idUser));
        const path = `/index.php/${MB_SIP_MODULE}/${a.action}`;
        const resp = await mbSignedCall({ relPath: path, params, httpsAgent, hostHeader, validateStatus: (s)=>true });
        if (resp.status >= 200 && resp.status < 300) return res.json({ success: true, data: resp.data });
      } catch (e) { /* try next */ }
    }
    return res.status(400).json({ success: false, message: 'Failed to delete SIP user' });
  } catch (e) { return res.status(500).json({ success: false, message: 'SIP user delete failed' }); }
});

// Edit SIP user (e.g., callerID). Path param :id is MagnusBilling sip record id
app.put('/api/me/sip-users/:id', requireAuth, async (req, res) => {
  try {
    const sipId = String(req.params.id || '');
    if (!sipId) return res.status(400).json({ success: false, message: 'Missing SIP user id' });
    const { callerid, password } = req.body || {};
    if (callerid !== undefined && !/^\d{1,11}$/.test(String(callerid))) {
      return res.status(400).json({ success: false, message: 'CallerID must be numbers only, maximum 11 digits.' });
    }
    const httpsAgent = new https.Agent({ rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1', ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}) });
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
    const attempts = [
      (p)=>{ p.append('id', sipId); if (callerid) p.append('callerid', callerid); if (password) p.append('secret', password); },
      (p)=>{ p.append('id', sipId); if (callerid) p.append('cid', callerid); if (password) p.append('password', password); },
      (p)=>{ p.append('id', sipId); if (callerid) p.append('calleridname', callerid); }
    ];
    for (const build of attempts) {
      try {
        const params = new URLSearchParams();
        params.append('module', MB_SIP_MODULE);
        params.append('action', 'save');
        build(params);
        const path = `/index.php/${MB_SIP_MODULE}/save`;
        const resp = await mbSignedCall({ relPath: path, params, httpsAgent, hostHeader });
        const ok = (resp.status>=200 && resp.status<300) && (resp.data?.success===true || /success/i.test(String(resp.data)));
        if (ok) return res.json({ success: true, data: resp.data });
      } catch (e) { if (DEBUG) console.warn('sip edit attempt failed', e.message || e); }
    }
    return res.status(400).json({ success: false, message: 'Failed to update SIP user' });
  } catch (e) { return res.status(500).json({ success: false, message: 'SIP user update failed' }); }
});
// DIDWW API helpers
const DIDWW_API_KEY = process.env.DIDWW_API_KEY;
const DIDWW_API_URL = process.env.DIDWW_API_URL || 'https://api.didww.com/v3';

// NOWPayments configuration
const NOWPAYMENTS_API_KEY = process.env.NOWPAYMENTS_API_KEY || '';
const NOWPAYMENTS_IPN_SECRET = process.env.NOWPAYMENTS_IPN_SECRET || '';
const NOWPAYMENTS_API_URL = process.env.NOWPAYMENTS_API_URL || 'https://api.nowpayments.io/v1';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || '';

function nowpaymentsAxios() {
  if (!NOWPAYMENTS_API_KEY) {
    throw new Error('NOWPayments API key not configured');
  }
  return axios.create({
    baseURL: NOWPAYMENTS_API_URL,
    timeout: 15000,
    headers: {
      'x-api-key': NOWPAYMENTS_API_KEY,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  });
}

// Square configuration (card payments via Square Payment Links)
const SQUARE_ENVIRONMENT = process.env.SQUARE_ENVIRONMENT || 'sandbox'; // 'sandbox' or 'production'
const SQUARE_APPLICATION_ID = process.env.SQUARE_APPLICATION_ID || '';
const SQUARE_ACCESS_TOKEN = process.env.SQUARE_ACCESS_TOKEN || '';
const SQUARE_LOCATION_ID = process.env.SQUARE_LOCATION_ID || '';
const SQUARE_WEBHOOK_SIGNATURE_KEY = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY || '';
const SQUARE_WEBHOOK_NOTIFICATION_URL = process.env.SQUARE_WEBHOOK_NOTIFICATION_URL || '';

function squareApiBaseUrl() {
  return SQUARE_ENVIRONMENT === 'production'
    ? 'https://connect.squareup.com'
    : 'https://connect.squareupsandbox.com';
}

let cachedSquareLocationId = SQUARE_LOCATION_ID || null;
async function getSquareLocationId() {
  if (cachedSquareLocationId) return cachedSquareLocationId;
  if (!SQUARE_ACCESS_TOKEN) {
    throw new Error('Square access token not configured');
  }
  try {
    const baseUrl = squareApiBaseUrl();
    const resp = await axios.get(`${baseUrl}/v2/locations`, {
      timeout: 15000,
      headers: {
        'Authorization': `Bearer ${SQUARE_ACCESS_TOKEN}`,
        'Square-Version': '2025-10-16',
        'Accept': 'application/json'
      }
    });
    const locations = resp?.data?.locations || [];
    const active = locations.find(l => l.status === 'ACTIVE') || locations[0];
    if (active && active.id) {
      cachedSquareLocationId = active.id;
      if (DEBUG) console.log('[square.locations] Using location id:', cachedSquareLocationId);
      return cachedSquareLocationId;
    }
    if (DEBUG) console.warn('[square.locations] No locations returned from Square');
    return null;
  } catch (e) {
    if (DEBUG) console.error('[square.locations] Failed to fetch locations:', e.response?.data || e.message || e);
    return null;
  }
}

// Verify NOWPayments IPN HMAC signature (x-nowpayments-sig)
function verifyNowpaymentsSignature(req) {
  try {
    if (!NOWPAYMENTS_IPN_SECRET) {
      if (DEBUG) console.warn('[nowpayments.ipn] NOWPAYMENTS_IPN_SECRET not set; skipping signature verification');
      return true; // Do not block if secret not configured yet, but log
    }
    const signature = req.headers['x-nowpayments-sig'] || req.headers['x-nowpayments-signature'];
    if (!signature) return false;
    const raw = req.rawBody;
    if (!raw || !Buffer.isBuffer(raw)) return false;
    const hmac = crypto.createHmac('sha512', NOWPAYMENTS_IPN_SECRET);
    hmac.update(raw);
    const expected = hmac.digest('hex');
    // Use timing-safe compare
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(String(signature), 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (e) {
    if (DEBUG) console.warn('[nowpayments.ipn] Signature verification error:', e.message || e);
    return false;
  }
}

// Verify Square webhook signature (x-square-hmacsha256-signature)
// Square signs the body as: HMAC_SHA256( notification_url + raw_body ) using the
// subscription's "Signature key". We try both the configured notification URL
// and the actual request URL in case there is a mismatch (e.g. proxy changes).
function verifySquareSignature(req) {
  try {
    if (!SQUARE_WEBHOOK_SIGNATURE_KEY) {
      if (DEBUG) console.warn('[square.webhook] Signature key not set; skipping verification');
      return true; // do not block if key not configured yet
    }

    const signature = req.headers['x-square-hmacsha256-signature'];
    if (!signature) {
      if (DEBUG) console.warn('[square.webhook] Missing x-square-hmacsha256-signature header');
      return false;
    }

    const raw = req.rawBody;
    if (!raw || !Buffer.isBuffer(raw)) {
      if (DEBUG) console.warn('[square.webhook] Missing rawBody for signature verification');
      return false;
    }

    const urlsToTry = [];
    if (SQUARE_WEBHOOK_NOTIFICATION_URL) urlsToTry.push(SQUARE_WEBHOOK_NOTIFICATION_URL);
    const actualUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
    if (!urlsToTry.includes(actualUrl)) urlsToTry.push(actualUrl);

    const headerSig = String(signature);

    for (const url of urlsToTry) {
      const payload = String(url || '') + raw.toString('utf8');
      const expected = crypto
        .createHmac('sha256', SQUARE_WEBHOOK_SIGNATURE_KEY)
        .update(payload)
        .digest('base64');
      const a = Buffer.from(expected, 'utf8');
      const b = Buffer.from(headerSig, 'utf8');
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        if (DEBUG) console.log('[square.webhook] Signature verified', { urlUsed: url });
        return true;
      }
    }

    if (DEBUG) {
      console.warn('[square.webhook] Signature mismatch', {
        header: headerSig,
        triedUrls: urlsToTry
      });
    }
    return false;
  } catch (e) {
    if (DEBUG) console.warn('[square.webhook] Signature verification error:', e.message || e);
    return false;
  }
}

async function didwwApiCall({ method, path, body }) {
  if (!DIDWW_API_KEY) throw new Error('DIDWW_API_KEY not configured');
  const url = `${DIDWW_API_URL}${path}`;
  const headers = {
    'Api-Key': DIDWW_API_KEY,
    'Content-Type': 'application/vnd.api+json',
    'Accept': 'application/vnd.api+json'
  };
  const options = { method, headers, timeout: 30000 };
  if (body) options.data = body;
  try {
    const resp = await axios(url, options);
    return resp.data;
  } catch (e) {
    // Enhance error with more details for debugging
    const errDetails = {
      url,
      method,
      status: e.response?.status,
      statusText: e.response?.statusText,
      code: e.code,
      message: e.message,
      data: e.response?.data
    };
    if (DEBUG) console.error('[didwwApiCall] Request failed:', errDetails);
    throw e;
  }
}

// Helper to get capacity pool ID (supports ID or name lookup)
let cachedCapacityPoolId = null;
async function getCapacityPoolId() {
  // If already cached, return it
  if (cachedCapacityPoolId) return cachedCapacityPoolId;
  
  // Check if ID is directly configured
  const configuredId = process.env.DIDWW_CAPACITY_POOL_ID;
  const configuredName = process.env.DIDWW_CAPACITY_POOL_NAME;
  
  if (DEBUG) console.log('[didww.capacityPool] Looking up capacity pool:', { configuredId, configuredName });
  
  if (configuredId) {
    cachedCapacityPoolId = configuredId;
    return cachedCapacityPoolId;
  }
  
  // If name is configured, look up the ID
  if (configuredName) {
    try {
      const data = await didwwApiCall({ method: 'GET', path: '/capacity_pools' });
      const pools = data.data || [];
      if (DEBUG) console.log('[didww.capacityPool] Available pools:', pools.map(p => ({ id: p.id, name: p.attributes?.name })));
      const match = pools.find(p => p.attributes?.name?.toLowerCase() === configuredName.toLowerCase());
      if (match) {
        cachedCapacityPoolId = match.id;
        if (DEBUG) console.log('[didww.capacityPool] Found by name:', { name: configuredName, id: cachedCapacityPoolId });
        return cachedCapacityPoolId;
      } else {
        if (DEBUG) console.warn('[didww.capacityPool] No match found for name:', configuredName);
      }
    } catch (e) {
      if (DEBUG) console.error('[didww.capacityPool] Failed to lookup by name:', e.message);
    }
  } else {
    if (DEBUG) console.warn('[didww.capacityPool] No DIDWW_CAPACITY_POOL_ID or DIDWW_CAPACITY_POOL_NAME configured');
  }
  
  return null;
}

// Helper to get shared capacity group ID for the configured capacity pool
let cachedSharedCapacityGroupId = null;
async function getSharedCapacityGroupId() {
  if (cachedSharedCapacityGroupId) return cachedSharedCapacityGroupId;

  const poolId = await getCapacityPoolId();
  if (!poolId) {
    if (DEBUG) console.warn('[didww.sharedCapacityGroup] No capacity pool configured, cannot resolve shared capacity group');
    return null;
  }

  const configuredId = process.env.DIDWW_SHARED_CAPACITY_GROUP_ID;
  const configuredName = process.env.DIDWW_SHARED_CAPACITY_GROUP_NAME;

  if (DEBUG) console.log('[didww.sharedCapacityGroup] Looking up shared capacity group:', { configuredId, configuredName, poolId });

  if (configuredId) {
    cachedSharedCapacityGroupId = configuredId;
    return cachedSharedCapacityGroupId;
  }

  try {
    const data = await didwwApiCall({ method: 'GET', path: `/shared_capacity_groups?filter[capacity_pool.id]=${poolId}` });
    const groups = data.data || [];
    if (DEBUG) console.log('[didww.sharedCapacityGroup] Available groups for pool:', groups.map(g => ({
      id: g.id,
      name: g.attributes?.name,
      shared: g.attributes?.shared_channels_count,
      metered: g.attributes?.metered_channels_count
    })));

    let match = null;
    if (configuredName) {
      match = groups.find(g => g.attributes?.name?.toLowerCase() === configuredName.toLowerCase());
    } else {
      // Prefer a group that actually has capacity assigned; otherwise use the first one
      match = groups.find(g => (g.attributes?.metered_channels_count || 0) > 0) ||
              groups.find(g => (g.attributes?.shared_channels_count || 0) > 0) ||
              groups[0];
    }

    if (match) {
      cachedSharedCapacityGroupId = match.id;
      if (DEBUG) console.log('[didww.sharedCapacityGroup] Selected group:', { id: match.id, name: match.attributes?.name });
      return cachedSharedCapacityGroupId;
    }

    if (DEBUG) console.warn('[didww.sharedCapacityGroup] No shared capacity groups found for pool:', poolId);
  } catch (e) {
    if (DEBUG) console.error('[didww.sharedCapacityGroup] Failed to lookup groups:', e.message);
  }

  return null;
}

// List capacity pools
app.get('/api/me/didww/capacity-pools', requireAuth, async (req, res) => {
  try {
    const data = await didwwApiCall({ method: 'GET', path: '/capacity_pools' });
    return res.json({ success: true, data: data.data || [] });
  } catch (e) {
    if (DEBUG) console.error('[didww.capacity-pools] error:', e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch capacity pools' });
  }
});

// Get available POPs for trunk configuration
app.get('/api/me/didww/pops', requireAuth, async (req, res) => {
  try {
    const data = await didwwApiCall({ method: 'GET', path: '/pops' });
    return res.json({ success: true, data: data.data || [] });
  } catch (e) {
    if (DEBUG) console.error('[didww.pops] error:', e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch POPs' });
  }
});

// List voice in trunks (only those owned by the current user)
app.get('/api/me/didww/trunks', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    
    // Get trunk IDs owned by this user from local DB
    const [userTrunks] = await pool.execute('SELECT didww_trunk_id FROM user_trunks WHERE user_id = ?', [userId]);
    const ownedTrunkIds = userTrunks.map(t => t.didww_trunk_id);
    
    if (ownedTrunkIds.length === 0) {
      return res.json({ success: true, data: [], included: [] });
    }
    
    // Fetch full trunk details from DIDWW API
    const data = await didwwApiCall({ method: 'GET', path: '/voice_in_trunks?include=pop' });
    const allTrunks = data.data || [];
    
    // Filter to only include trunks owned by this user
    const userOwnedTrunks = allTrunks.filter(t => ownedTrunkIds.includes(t.id));
    
    return res.json({ success: true, data: userOwnedTrunks, included: data.included || [] });
  } catch (e) {
    if (DEBUG) console.error('[didww.trunks.list] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch trunks' });
  }
});

// Create voice in trunk
app.post('/api/me/didww/trunks', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    
    const { name, description, capacity_limit, pop_id, dst } = req.body || {};
    if (!name) {
      return res.status(400).json({ success: false, message: 'Trunk name is required' });
    }
    if (!dst) {
      return res.status(400).json({ success: false, message: 'PSTN destination number is required' });
    }
    if (!/^\d{11}$/.test(String(dst))) {
      return res.status(400).json({ success: false, message: 'PSTN destination number must be 11 digits (numbers only).' });
    }
    
    // Build attributes with required PSTN configuration
    const attributes = {
      name,
      configuration: {
        type: 'pstn_configurations',
        attributes: {
          dst: dst
        }
      }
    };
    
    // Add optional attributes
    if (description) attributes.description = description;
    if (capacity_limit) attributes.capacity_limit = parseInt(capacity_limit, 10);
    
    const body = {
      data: {
        type: 'voice_in_trunks',
        attributes
      }
    };
    
    // Add POP relationship if provided
    if (pop_id) {
      body.data.relationships = {
        pop: {
          data: { type: 'pops', id: pop_id }
        }
      };
    }
    
    const data = await didwwApiCall({ method: 'POST', path: '/voice_in_trunks', body });
    const createdTrunk = data.data || {};
    
    // Save trunk ownership to local DB
    if (createdTrunk.id) {
      try {
        const attrs = createdTrunk.attributes || {};
        await pool.execute(
          'INSERT INTO user_trunks (user_id, didww_trunk_id, name, dst, description, capacity_limit) VALUES (?, ?, ?, ?, ?, ?)',
          [userId, createdTrunk.id, attrs.name || name, dst, attrs.description || description || null, capacity_limit || null]
        );
        if (DEBUG) console.log('[didww.trunk.create] Saved trunk ownership:', { userId, trunkId: createdTrunk.id });
      } catch (dbErr) {
        console.error('[didww.trunk.create] Failed to save trunk ownership:', dbErr.message);
        // Trunk was created in DIDWW but failed to save locally - try to delete it
        try { await didwwApiCall({ method: 'DELETE', path: `/voice_in_trunks/${createdTrunk.id}` }); } catch {}
        return res.status(500).json({ success: false, message: 'Failed to save trunk ownership' });
      }
    }
    
    return res.json({ success: true, data: createdTrunk });
  } catch (e) {
    if (DEBUG) console.error('[didww.trunk.create] error:', e.response?.data || e.message || e);
    const errMsg = e.response?.data?.errors?.[0]?.detail || 'Failed to create trunk';
    return res.status(500).json({ success: false, message: errMsg });
  }
});

// Update voice in trunk (only if owned by current user)
app.patch('/api/me/didww/trunks/:id', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    const trunkId = req.params.id;
    
    // Verify ownership
    const [owned] = await pool.execute('SELECT id FROM user_trunks WHERE user_id = ? AND didww_trunk_id = ?', [userId, trunkId]);
    if (!owned || owned.length === 0) {
      return res.status(403).json({ success: false, message: 'You do not have permission to update this trunk' });
    }
    
    const { name, description, capacity_limit, dst } = req.body || {};
    
    const attributes = {};
    if (dst && !/^\d{11}$/.test(String(dst))) {
      return res.status(400).json({ success: false, message: 'PSTN destination number must be 11 digits (numbers only).' });
    }
    if (name) attributes.name = name;
    if (description !== undefined) attributes.description = description;
    if (capacity_limit !== undefined) attributes.capacity_limit = capacity_limit;
    
    // Include PSTN configuration if dst is provided
    if (dst) {
      attributes.configuration = {
        type: 'pstn_configurations',
        attributes: {
          dst: dst
        }
      };
    }
    
    const body = {
      data: {
        type: 'voice_in_trunks',
        id: trunkId,
        attributes
      }
    };
    
    const data = await didwwApiCall({ method: 'PATCH', path: `/voice_in_trunks/${trunkId}`, body });
    
    // Update local DB
    try {
      const updates = [];
      const values = [];
      if (name) { updates.push('name = ?'); values.push(name); }
      if (dst) { updates.push('dst = ?'); values.push(dst); }
      if (description !== undefined) { updates.push('description = ?'); values.push(description); }
      if (capacity_limit !== undefined) { updates.push('capacity_limit = ?'); values.push(capacity_limit); }
      if (updates.length > 0) {
        values.push(trunkId);
        await pool.execute(`UPDATE user_trunks SET ${updates.join(', ')} WHERE didww_trunk_id = ?`, values);
      }
    } catch (dbErr) {
      if (DEBUG) console.warn('[didww.trunk.update] Failed to update local DB:', dbErr.message);
    }
    
    return res.json({ success: true, data: data.data || {} });
  } catch (e) {
    if (DEBUG) console.error('[didww.trunk.update] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to update trunk' });
  }
});

// Delete voice in trunk (only if owned by current user)
app.delete('/api/me/didww/trunks/:id', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ success: false, message: 'Database not configured' });
    const userId = req.session.userId;
    const trunkId = req.params.id;
    
    // Verify ownership
    const [owned] = await pool.execute('SELECT id FROM user_trunks WHERE user_id = ? AND didww_trunk_id = ?', [userId, trunkId]);
    if (!owned || owned.length === 0) {
      return res.status(403).json({ success: false, message: 'You do not have permission to delete this trunk' });
    }
    
    // First, unassign this trunk from any DIDs that are using it
    try {
      const didsData = await didwwApiCall({ method: 'GET', path: '/dids?include=voice_in_trunk' });
      const allDids = didsData.data || [];
      const didsUsingTrunk = allDids.filter(d => d.relationships?.voice_in_trunk?.data?.id === trunkId);
      
      if (didsUsingTrunk.length > 0) {
        if (DEBUG) console.log('[didww.trunk.delete] Unassigning trunk from DIDs:', { trunkId, didCount: didsUsingTrunk.length });
        
        // Unassign trunk from each DID
        for (const did of didsUsingTrunk) {
          try {
            const unassignBody = {
              data: {
                type: 'dids',
                id: did.id,
                relationships: {
                  voice_in_trunk: { data: null }
                }
              }
            };
            await didwwApiCall({ method: 'PATCH', path: `/dids/${did.id}`, body: unassignBody });
            if (DEBUG) console.log('[didww.trunk.delete] Unassigned trunk from DID:', { trunkId, didId: did.id });
          } catch (unassignErr) {
            console.warn('[didww.trunk.delete] Failed to unassign trunk from DID:', did.id, unassignErr.message);
          }
        }
      }
    } catch (fetchErr) {
      // Continue with delete attempt even if we couldn't fetch DIDs
      if (DEBUG) console.warn('[didww.trunk.delete] Could not fetch DIDs to unassign:', fetchErr.message);
    }
    
    // Now delete the trunk
    await didwwApiCall({ method: 'DELETE', path: `/voice_in_trunks/${trunkId}` });
    
    // Remove from local DB
    try {
      await pool.execute('DELETE FROM user_trunks WHERE didww_trunk_id = ?', [trunkId]);
      if (DEBUG) console.log('[didww.trunk.delete] Removed trunk ownership:', { userId, trunkId });
    } catch (dbErr) {
      if (DEBUG) console.warn('[didww.trunk.delete] Failed to remove from local DB:', dbErr.message);
    }
    
    return res.json({ success: true });
  } catch (e) {
    if (DEBUG) console.error('[didww.trunk.delete] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to delete trunk' });
  }
});


// Charge monthly markup for a single DID (deducts from MagnusBilling and records billing history)
async function chargeDidMarkup({ userId, magnusUserId, didId, didNumber, markupAmount, isTollfree, billedTo, httpsAgent, hostHeader }) {
  if (!pool) return false;
  const amt = Number(markupAmount || 0);
  if (!amt || amt <= 0) return false;

  const periodLabel = billedTo ? `period ending ${new Date(billedTo).toISOString().slice(0, 10)}` : 'monthly period';
  const descRaw = `Number monthly service fee - ${isTollfree ? 'Toll-Free' : 'Local'} ${didNumber || didId} (${periodLabel})`;
  const description = descRaw.substring(0, 255);

  // Extra safety: check for an existing non-failed billing row with the same
  // user, amount, and description to avoid duplicate charges even if the
  // markup_cycles table is missing its unique index.
  try {
    const [existingRows] = await pool.execute(
      'SELECT id FROM billing_history WHERE user_id = ? AND amount = ? AND description = ? AND status != ? LIMIT 1',
      [userId, -amt, description, 'failed']
    );
    if (existingRows && existingRows.length) {
      if (DEBUG) console.warn('[didww.markup] Duplicate billing detected; skipping new charge', {
        userId,
        didId,
        didNumber,
        markupAmount: amt,
        billedTo
      });
      return true;
    }
  } catch (dupErr) {
    if (DEBUG) console.warn('[didww.markup] Duplicate-check query failed; continuing with charge:', dupErr.message || dupErr);
  }

  // Insert pending billing record
  const [insertResult] = await pool.execute(
    'INSERT INTO billing_history (user_id, amount, description, status) VALUES (?, ?, ?, ?)',
    [userId, -amt, description, 'pending']
  );
  const billingId = insertResult.insertId;

  try {
    // Read current credit
    const readParams = new URLSearchParams();
    readParams.append('module', 'user');
    readParams.append('action', 'read');
    readParams.append('start', '0');
    readParams.append('limit', '100');
    const readResp = await mbSignedCall({ relPath: '/index.php/user/read', params: readParams, httpsAgent, hostHeader });
    const allUsers = readResp?.data?.rows || readResp?.data?.data || [];
    const userRow = allUsers.find(u => String(u.id || u.user_id || u.uid || u.id_user || '') === String(magnusUserId));
    let magnusResponse = JSON.stringify(readResp?.data || readResp || {});

    if (userRow) {
      const currentCredit = Number(userRow.credit || 0);
      const newCredit = currentCredit - amt; // allow negative balance
      const updateParams = new URLSearchParams();
      updateParams.append('module', 'user');
      updateParams.append('action', 'save');
      updateParams.append('id', String(magnusUserId));
      updateParams.append('credit', String(newCredit));
      const updateResp = await mbSignedCall({ relPath: '/index.php/user/save', params: updateParams, httpsAgent, hostHeader });
      magnusResponse = JSON.stringify(updateResp?.data || updateResp || {});
      if (DEBUG) console.log('[didww.markup] Deducted markup from MagnusBilling credit:', {
        magnusUserId,
        didId,
        didNumber,
        amount: amt,
        currentCredit,
        newCredit
      });
    } else if (DEBUG) {
      console.warn('[didww.markup] Magnus user not found when charging markup', { magnusUserId });
    }

    await pool.execute(
      'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
      ['completed', magnusResponse, billingId]
    );
    return true;
  } catch (e) {
    if (DEBUG) console.warn('[didww.markup] MagnusBilling error while charging markup:', e.message || e);
    await pool.execute(
      'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
      ['failed', String(e.message || e), billingId]
    );
    return false;
  }
}

// Best-effort: align markup charges with DIDWW billing cycles based on billing.billed_to
// Uses a database-level idempotency table (user_did_markup_cycles) so each (user, DID, billed_to)
// is billed at most once, even across concurrent requests/processes.
async function billDidMarkupsForUser({ localUserId, magnusUserId, userDids, included, httpsAgent, hostHeader }) {
  if (!pool || !localUserId || !magnusUserId) return;

  const localMarkup = parseFloat(process.env.DID_LOCAL_MONTHLY_MARKUP || '10.20') || 0;
  const tollfreeMarkup = parseFloat(process.env.DID_TOLLFREE_MONTHLY_MARKUP || '25.20') || 0;
  if ((!localMarkup || localMarkup <= 0) && (!tollfreeMarkup || tollfreeMarkup <= 0)) return;

  // Build did_group lookup to help detect toll-free
  const didGroupsMap = {};
  if (Array.isArray(included)) {
    for (const inc of included) {
      if (inc && inc.type === 'did_groups') didGroupsMap[inc.id] = inc;
    }
  }

  const pad2 = (n) => String(n).padStart(2, '0');

  for (const did of userDids || []) {
    try {
      if (!did || !did.id) continue;
      const didId = did.id;
      const attrs = did.attributes || {};
      const billing = attrs.billing || {};
      const billedToStr = billing.billed_to || billing.next_billing || attrs.expires_at || null;
      if (!billedToStr) continue;

      const billedTo = new Date(billedToStr);
      if (!isFinite(billedTo.getTime())) continue;

      const billedToDb = `${billedTo.getFullYear()}-${pad2(billedTo.getMonth() + 1)}-${pad2(billedTo.getDate())} ${pad2(billedTo.getHours())}:${pad2(billedTo.getMinutes())}:${pad2(billedTo.getSeconds())}`;

      // Determine toll-free vs local
      const didType = String(attrs.did_type || '').toLowerCase();
      let isTollfree = didType.includes('toll');
      if (!isTollfree) {
        const didGroupRel = did.relationships?.did_group?.data;
        if (didGroupRel && didGroupsMap[didGroupRel.id]) {
          const name = String(didGroupsMap[didGroupRel.id].attributes?.name || '').toLowerCase();
          if (name.includes('toll')) isTollfree = true;
        }
      }
      // Fallback: detect US/CA toll-free by prefix (800, 833, 844, 855, 866, 877, 888)
      if (!isTollfree) {
        const rawNum = String(attrs.number || '').replace(/\D/g, '');
        if (rawNum) {
          const digits = rawNum.length > 11 ? rawNum.slice(-11) : rawNum;
          const npa = digits.startsWith('1') ? digits.slice(1, 4) : digits.slice(0, 3);
          const tollfreeNpas = new Set(['800','833','844','855','866','877','888']);
          if (tollfreeNpas.has(npa)) isTollfree = true;
        }
      }

      const markupAmount = isTollfree ? tollfreeMarkup : localMarkup;
      if (!markupAmount || markupAmount <= 0) continue;

      // DB-level idempotency: only the first insert per (user, DID, billed_to) bills this cycle
      const [insRes] = await pool.execute(
        'INSERT IGNORE INTO user_did_markup_cycles (user_id, didww_did_id, billed_to) VALUES (?, ?, ?)',
        [localUserId, didId, billedToDb]
      );
      if (!insRes || insRes.affectedRows === 0) {
        // Another request/process already billed this cycle
        continue;
      }

      const didNumber = attrs.number || '';
      const ok = await chargeDidMarkup({
        userId: localUserId,
        magnusUserId,
        didId,
        didNumber,
        markupAmount,
        isTollfree,
        billedTo,
        httpsAgent,
        hostHeader
      });

      if (!ok) {
        // Roll back the cycle marker so we can retry on the next run
        try {
          await pool.execute(
            'DELETE FROM user_did_markup_cycles WHERE user_id = ? AND didww_did_id = ? AND billed_to = ?',
            [localUserId, didId, billedToDb]
          );
        } catch (delErr) {
          if (DEBUG) console.warn('[didww.markup] Failed to rollback markup cycle row after failure:', delErr.message || delErr);
        }
        continue;
      }

      // Update or insert last_billed_to for reporting/debugging
      try {
        await pool.execute(
          'INSERT INTO user_did_markups (user_id, didww_did_id, last_billed_to) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE last_billed_to = VALUES(last_billed_to)',
          [localUserId, didId, billedToDb]
        );
      } catch (e) {
        if (DEBUG) console.warn('[didww.markup] Failed to update user_did_markups:', e.message || e);
      }
    } catch (e) {
      if (DEBUG) console.warn('[didww.markup] Error while processing DID for markup:', e.message || e);
    }
  }
}

// Aggregate and bill inbound CDRs for a user (per-minute retail pricing)
async function billInboundCdrsForUser({ localUserId, magnusUserId, httpsAgent, hostHeader }) {
  if (!pool || !localUserId || !magnusUserId) return;

  const [[agg]] = await pool.execute(
    "SELECT SUM(price) AS total_amount, COUNT(*) AS call_count FROM user_did_cdrs WHERE user_id = ? AND billed = 0 AND direction = 'inbound' AND price IS NOT NULL AND price > 0",
    [localUserId]
  );
  const totalAmount = Number(agg?.total_amount || 0);
  const callCount = Number(agg?.call_count || 0);
  if (!totalAmount || totalAmount <= 0 || !callCount) return;

  const pad2 = (n) => String(n).padStart(2, '0');
  const now = new Date();
  const dateLabel = `${now.getFullYear()}-${pad2(now.getMonth() + 1)}-${pad2(now.getDate())}`;
  const desc = `Inbound call charges - ${dateLabel} - ${callCount} call${callCount === 1 ? '' : 's'}`;

  // Insert pending billing record
  const [insertResult] = await pool.execute(
    'INSERT INTO billing_history (user_id, amount, description, status) VALUES (?, ?, ?, ?)',
    [localUserId, -totalAmount, desc, 'pending']
  );
  const billingId = insertResult.insertId;

  // Mark CDRs as billed and associate them with this billing row. We do this
  // *before* updating MagnusBilling to avoid double-charging on retries; worst
  // case is an undercharge if the MagnusBilling call fails.
  try {
    await pool.execute(
      "UPDATE user_did_cdrs SET billed = 1, billing_history_id = ? WHERE user_id = ? AND billed = 0 AND direction = 'inbound' AND price IS NOT NULL AND price > 0",
      [billingId, localUserId]
    );
  } catch (e) {
    if (DEBUG) console.warn('[didww.cdr.billing] Failed to mark CDRs as billed:', e.message || e);
    // If we can't mark them billed, bail out so we don't charge without a clear marker
    return;
  }

  try {
    let magnusResponse = null;
    let success = false;

    // Primary path: create a negative refill in MagnusBilling so there is a visible
    // ledger entry (similar to how manual fees are recorded).
    try {
      const refillParams = new URLSearchParams();
      refillParams.append('module', 'refill');
      refillParams.append('action', 'save');
      refillParams.append('id_user', String(magnusUserId));
      refillParams.append('credit', String(-totalAmount)); // negative = charge/fee
      refillParams.append('description', desc);
      refillParams.append('payment', '1'); // mark as paid/confirmed
      refillParams.append('refill_type', '0'); // manual/fee

      const refillResp = await mbSignedCall({ relPath: '/index.php/refill/save', params: refillParams, httpsAgent, hostHeader });
      magnusResponse = JSON.stringify(refillResp?.data || refillResp || {});

      if (
        refillResp?.data?.success === true ||
        (Array.isArray(refillResp?.data?.rows) && refillResp.data.rows.length > 0) ||
        (refillResp?.status >= 200 && refillResp?.status < 300)
      ) {
        success = true;
        if (DEBUG) console.log('[didww.cdr.billing.refill] Created negative refill for inbound charges:', {
          magnusUserId,
          userId: localUserId,
          totalAmount,
          callCount
        });
      }
    } catch (e) {
      if (DEBUG) console.warn('[didww.cdr.billing] Refill module failed, falling back to direct credit update:', e.message || e);
    }

    // Fallback: if refill failed, directly adjust user.credit so at least the
    // balance is correct (no visible ledger entry in MagnusBilling though).
    if (!success) {
      try {
        const readParams = new URLSearchParams();
        readParams.append('module', 'user');
        readParams.append('action', 'read');
        readParams.append('start', '0');
        readParams.append('limit', '100');
        const readResp = await mbSignedCall({ relPath: '/index.php/user/read', params: readParams, httpsAgent, hostHeader });
        const allUsers = readResp?.data?.rows || readResp?.data?.data || [];
        const userRow = allUsers.find(u => String(u.id || u.user_id || u.uid || u.id_user || '') === String(magnusUserId));
        magnusResponse = JSON.stringify(readResp?.data || readResp || {});

        if (userRow) {
          const currentCredit = Number(userRow.credit || 0);
          const newCredit = currentCredit - totalAmount; // allow negative balance
          const updateParams = new URLSearchParams();
          updateParams.append('module', 'user');
          updateParams.append('action', 'save');
          updateParams.append('id', String(magnusUserId));
          updateParams.append('credit', String(newCredit));
          const updateResp = await mbSignedCall({ relPath: '/index.php/user/save', params: updateParams, httpsAgent, hostHeader });
          magnusResponse = JSON.stringify(updateResp?.data || updateResp || {});
          success = true;
          if (DEBUG) console.log('[didww.cdr.billing] Deducted inbound charges from MagnusBilling credit (fallback path):', {
            magnusUserId,
            userId: localUserId,
            totalAmount,
            currentCredit,
            newCredit,
            callCount
          });
        } else if (DEBUG) {
          console.warn('[didww.cdr.billing] Magnus user not found when charging inbound calls (fallback path)', { magnusUserId });
        }
      } catch (fallbackErr) {
        if (DEBUG) console.warn('[didww.cdr.billing] Fallback direct credit update failed:', fallbackErr.message || fallbackErr);
      }
    }

    await pool.execute(
      'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
      [success ? 'completed' : 'failed', magnusResponse || 'No MagnusBilling response', billingId]
    );
  } catch (e) {
    if (DEBUG) console.warn('[didww.cdr.billing] MagnusBilling error while charging inbound calls:', e.message || e);
    await pool.execute(
      'UPDATE billing_history SET status = ?, magnus_response = ? WHERE id = ?',
      ['failed', String(e.message || e), billingId]
    );
  }
}

// Wrapper for HTTP routes that still rely on req/session
async function maybeBillDidMarkupsForUser(req, userDids, included) {
  if (!pool || !req.session || !req.session.userId) return;

  const httpsAgent = new https.Agent({
    rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1',
    ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {})
  });
  const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
  const magnusUserId = await ensureMagnusUserId(req, { httpsAgent, hostHeader });
  if (!magnusUserId) {
    if (DEBUG) console.warn('[didww.markup] No Magnus user ID; skipping markup billing');
    return;
  }

  await billDidMarkupsForUser({
    localUserId: req.session.userId,
    magnusUserId,
    userDids,
    included,
    httpsAgent,
    hostHeader
  });
}

// ========== DID Number Purchasing APIs ==========

// List countries for DID purchasing (US and Canada only)
app.get('/api/me/didww/countries', requireAuth, async (req, res) => {
  try {
    const data = await didwwApiCall({ method: 'GET', path: '/countries' });
    // Filter to only US and Canada
    const filtered = (data.data || []).filter(c => ['US', 'CA'].includes(c.attributes?.iso));
    return res.json({ success: true, data: filtered });
  } catch (e) {
    if (DEBUG) console.error('[didww.countries] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch countries' });
  }
});

// List regions for a country
app.get('/api/me/didww/regions', requireAuth, async (req, res) => {
  try {
    const countryId = req.query.country_id;
    if (!countryId) return res.status(400).json({ success: false, message: 'country_id is required' });
    const data = await didwwApiCall({ method: 'GET', path: `/regions?filter[country.id]=${countryId}` });
    return res.json({ success: true, data: data.data || [] });
  } catch (e) {
    if (DEBUG) console.error('[didww.regions] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch regions' });
  }
});

// List cities for a region
app.get('/api/me/didww/cities', requireAuth, async (req, res) => {
  try {
    const regionId = req.query.region_id;
    if (!regionId) return res.status(400).json({ success: false, message: 'region_id is required' });
    const data = await didwwApiCall({ method: 'GET', path: `/cities?filter[region.id]=${regionId}` });
    return res.json({ success: true, data: data.data || [] });
  } catch (e) {
    if (DEBUG) console.error('[didww.cities] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch cities' });
  }
});

// Get DID group types (to find toll-free type ID dynamically)
let cachedTollfreeTypeId = null;
async function getTollfreeTypeId() {
  if (cachedTollfreeTypeId) return cachedTollfreeTypeId;
  try {
    const data = await didwwApiCall({ method: 'GET', path: '/did_group_types' });
    const types = data.data || [];
    if (DEBUG) console.log('[didww.did_group_types] Available types:', types.map(t => ({ id: t.id, name: t.attributes?.name })));
    const tollfreeType = types.find(t => /toll.?free/i.test(t.attributes?.name));
    if (tollfreeType) {
      cachedTollfreeTypeId = tollfreeType.id;
      if (DEBUG) console.log('[didww.did_group_types] Toll-free type ID:', cachedTollfreeTypeId);
    }
    return cachedTollfreeTypeId;
  } catch (e) {
    if (DEBUG) console.error('[didww.did_group_types] Failed to fetch:', e.message);
    return null;
  }
}

// Endpoint to get DID group types (for debugging)
app.get('/api/me/didww/did-group-types', requireAuth, async (req, res) => {
  try {
    const data = await didwwApiCall({ method: 'GET', path: '/did_group_types' });
    return res.json({ success: true, data: data.data || [] });
  } catch (e) {
    if (DEBUG) console.error('[didww.did-group-types] error:', e.message);
    return res.status(500).json({ success: false, message: 'Failed to fetch DID group types' });
  }
});

// List DID groups for a city (to get SKU for ordering)
// Supports tollfree=1 query param to filter only toll-free DID groups
app.get('/api/me/didww/did-groups', requireAuth, async (req, res) => {
  try {
    const cityId = req.query.city_id;
    const countryId = req.query.country_id;
    const tollfree = req.query.tollfree === '1';
    let path = '/did_groups?include=stock_keeping_units,did_group_type';
    if (cityId) path += `&filter[city.id]=${cityId}`;
    else if (countryId) path += `&filter[country.id]=${countryId}`;
    // Filter by DID group type ID for toll-free
    if (tollfree) {
      const tollfreeTypeId = await getTollfreeTypeId();
      if (tollfreeTypeId) {
        path += `&filter[did_group_type.id]=${tollfreeTypeId}`;
      } else {
        if (DEBUG) console.warn('[didww.did-groups] No toll-free type ID found, returning empty');
        return res.json({ success: true, data: [], included: [], message: 'Toll-free type not available' });
      }
    }
    const data = await didwwApiCall({ method: 'GET', path });
    if (DEBUG) {
      const skus = (data.included || []).filter(i => i.type === 'stock_keeping_units');
      console.log('[didww.did-groups] SKU data:', skus.map(s => ({ id: s.id, ...s.attributes })));
    }
    return res.json({ success: true, data: data.data || [], included: data.included || [] });
  } catch (e) {
    if (DEBUG) console.error('[didww.did-groups] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch DID groups' });
  }
});

// Search available DIDs (prefix filter not supported by DIDWW API)
app.get('/api/me/didww/available-dids', requireAuth, async (req, res) => {
  try {
    const { did_group_id } = req.query;
    if (!did_group_id) return res.status(400).json({ success: false, message: 'did_group_id is required' });
    const path = `/available_dids?filter[did_group.id]=${did_group_id}`;
    const data = await didwwApiCall({ method: 'GET', path });
    return res.json({ success: true, data: data.data || [] });
  } catch (e) {
    if (DEBUG) console.error('[didww.available-dids] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to fetch available DIDs' });
  }
});

// Purchase a DID number
app.post('/api/me/didww/orders', requireAuth, async (req, res) => {
  try {
    const { sku_id, did_group_id, available_did_id, is_tollfree } = req.body || {};
    
    if (!sku_id) return res.status(400).json({ success: false, message: 'sku_id is required' });
    
    // Always check MagnusBilling balance before placing order
    // Use TalkUSA monthly markup prices (local vs toll-free)
    const localMarkup = parseFloat(process.env.DID_LOCAL_MONTHLY_MARKUP || '10.20') || 0;
    const tollfreeMarkup = parseFloat(process.env.DID_TOLLFREE_MONTHLY_MARKUP || '25.20') || 0;
    const isTollfreeFlag = Boolean(
      is_tollfree === true ||
      is_tollfree === 1 ||
      is_tollfree === '1' ||
      String(is_tollfree || '').toLowerCase() === 'true'
    );
    let requiredMonthly = isTollfreeFlag
      ? (tollfreeMarkup || localMarkup || 0)
      : (localMarkup || tollfreeMarkup || 0);
    if (!requiredMonthly || requiredMonthly <= 0) {
      requiredMonthly = 1.00; // conservative fallback if markup not configured
    }
    
    // Check MagnusBilling balance before placing order
    try {
      const httpsAgent = new https.Agent({ 
        rejectUnauthorized: process.env.MAGNUSBILLING_TLS_INSECURE !== '1', 
        ...(process.env.MAGNUSBILLING_TLS_SERVERNAME ? { servername: process.env.MAGNUSBILLING_TLS_SERVERNAME } : {}) 
      });
      const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;
      const magnusUserId = await ensureMagnusUserId(req, { httpsAgent, hostHeader });
      
      if (magnusUserId) {
        const readParams = new URLSearchParams();
        readParams.append('module', 'user');
        readParams.append('action', 'read');
        readParams.append('start', '0');
        readParams.append('limit', '100');
        const readResp = await mbSignedCall({ relPath: '/index.php/user/read', params: readParams, httpsAgent, hostHeader });
        const allUsers = readResp?.data?.rows || readResp?.data?.data || [];
        const userRow = allUsers.find(u => String(u.id || u.user_id || '') === String(magnusUserId));
        
        if (userRow) {
          const currentCredit = Number(userRow.credit || 0);
          if (DEBUG) console.log('[didww.order] Balance check:', { magnusUserId, currentCredit, requiredMonthly, isTollfree: isTollfreeFlag });
          
          if (currentCredit < requiredMonthly) {
            return res.status(400).json({ 
              success: false, 
              message: `Insufficient balance in your TalkUSA account. This number costs $${requiredMonthly.toFixed(2)} per month and your current balance is $${currentCredit.toFixed(2)}. Please add funds on the dashboard and try again.` 
            });
          }
        }
      }
    } catch (balanceErr) {
      console.error('[didww.order] Failed to check balance:', balanceErr.message);
      return res.status(500).json({ success: false, message: 'Failed to verify account balance. Please try again.' });
    }
    
    // Build order item attributes
    // When using available_did_id, we should NOT include qty (per DIDWW API docs)
    // When using did_group_id for random number, we need qty
    const itemAttrs = {
      sku_id: sku_id
    };
    
    // Add available_did_id for specific number, or did_group_id for random
    if (available_did_id) {
      itemAttrs.available_did_id = available_did_id;
      // Do NOT add qty when using available_did_id
    } else if (did_group_id) {
      itemAttrs.did_group_id = did_group_id;
      itemAttrs.qty = 1;
    } else {
      // Fallback: if neither provided, default to qty=1
      itemAttrs.qty = 1;
    }
    
    // Build the order body per DIDWW API format
    const body = {
      data: {
        type: 'orders',
        attributes: {
          allow_back_ordering: false,
          items: [
            {
              type: 'did_order_items',
              attributes: itemAttrs
            }
          ]
        }
      }
    };
    
    if (DEBUG) console.log('[didww.order] Creating order:', JSON.stringify(body));
    const data = await didwwApiCall({ method: 'POST', path: '/orders', body });
    let order = data.data || {};
    if (DEBUG) console.log('[didww.order] Order response:', JSON.stringify(data).substring(0, 1000));
    
    // Record purchase in billing history and deduct from MagnusBilling
    const purchaseAmount = parseFloat(order.attributes?.amount || '0');
    if (pool && req.session.userId && order.id && purchaseAmount > 0) {
      try {
        const reference = order.attributes?.reference || order.id;
        const description = `DID Purchase (Order: ${reference})`;
        await pool.execute(
          'INSERT INTO billing_history (user_id, amount, description, status) VALUES (?, ?, ?, ?)',
          [req.session.userId, -purchaseAmount, description, 'completed']
        );
        if (DEBUG) console.log('[didww.order] Recorded billing history:', { amount: -purchaseAmount, reference });
        
        // NOTE: We no longer deduct the DIDWW wholesale purchase amount from the
        // customer's MagnusBilling balance here. The business absorbs the
        // provider cost and only bills the customer the TalkUSA monthly
        // service fee (markup) via the separate monthly billing logic.
      } catch (billingErr) {
        console.error('[didww.order] Failed to record billing history:', billingErr.message);
      }
    }
    
    // Extract DIDs - DIDWW may include them in the response or we need to fetch separately
    let includedDids = (data.included || []).filter(i => i.type === 'dids');
    
    // If order is Pending, poll briefly for completion (DIDWW processes orders async)
    // Only poll for 3 seconds max to avoid blocking the user
    if (order.attributes?.status === 'Pending' && order.id) {
      if (DEBUG) console.log('[didww.order] Order pending, polling briefly...');
      for (let attempt = 0; attempt < 3; attempt++) {
        await new Promise(r => setTimeout(r, 1000));
        try {
          const orderCheck = await didwwApiCall({ method: 'GET', path: `/orders/${order.id}` });
          if (orderCheck.data?.attributes?.status === 'Completed') {
            order = orderCheck.data;
            if (DEBUG) console.log('[didww.order] Order completed on attempt', attempt + 1);
            break;
          }
        } catch (pollErr) {
          if (DEBUG) console.warn('[didww.order] Poll error:', pollErr.message);
        }
      }
    }
    
    // If order completed, fetch the created DIDs by order filter
    if (includedDids.length === 0 && order.attributes?.status === 'Completed') {
      if (DEBUG) console.log('[didww.order] Order completed, fetching DIDs...');
      try {
        const didsData = await didwwApiCall({ method: 'GET', path: `/dids?filter[order.id]=${order.id}` });
        if (didsData.data && didsData.data.length > 0) {
          includedDids = didsData.data;
          if (DEBUG) console.log('[didww.order] Found DIDs by order filter:', includedDids.map(d => d.id));
        }
      } catch (didsFetchErr) {
        if (DEBUG) console.warn('[didww.order] Failed to fetch DIDs by order:', didsFetchErr.message);
      }
    }
    
    // If still pending after polling, store order ID to reconcile later
    // The "My Numbers" tab will pick up new DIDs on next full refresh
    if (order.attributes?.status === 'Pending') {
      if (DEBUG) console.log('[didww.order] Order still pending, will reconcile on next refresh. Order ID:', order.id);
      // Store pending order for later reconciliation
      if (pool && req.session.userId) {
        try {
          // We'll use a simple approach: fetch all DIDs on the account and compare with user_dids
          // to find any unassigned DIDs after order completes
          await pool.execute(
            'INSERT IGNORE INTO pending_orders (user_id, order_id, created_at) VALUES (?, ?, NOW())',
            [req.session.userId, order.id]
          );
        } catch (dbErr) {
          // Table might not exist, that's fine
          if (DEBUG) console.warn('[didww.order] Could not store pending order:', dbErr.message);
        }
      }
    }
    
    if (DEBUG) console.log('[didww.order] DIDs found:', includedDids.length, includedDids.map(d => ({ id: d.id, number: d.attributes?.number })));
    
    // Save purchased DIDs to user_dids table and assign to capacity resources
    if (pool && req.session.userId && includedDids.length > 0) {
      const capacityPoolId = await getCapacityPoolId();
      const sharedCapacityGroupId = await getSharedCapacityGroupId();
      
      for (const did of includedDids) {
        try {
          const didNumber = did.attributes?.number || '';
          const didType = did.attributes?.did_type || null;
          await pool.execute(
            'INSERT INTO user_dids (user_id, didww_did_id, did_number, did_type) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE did_number=VALUES(did_number)',
            [req.session.userId, did.id, didNumber, didType]
          );
          if (DEBUG) console.log('[didww.order] Saved DID to user_dids:', { userId: req.session.userId, didId: did.id, number: didNumber });
          
          // Assign DID to capacity pool / shared capacity group if configured
          if (capacityPoolId || sharedCapacityGroupId) {
            try {
              const relationships = {};
              if (capacityPoolId) {
                relationships.capacity_pool = {
                  data: { type: 'capacity_pools', id: capacityPoolId }
                };
              }
              if (sharedCapacityGroupId) {
                relationships.shared_capacity_group = {
                  data: { type: 'shared_capacity_groups', id: sharedCapacityGroupId }
                };
              }
              if (Object.keys(relationships).length > 0) {
                const assignBody = {
                  data: {
                    type: 'dids',
                    id: did.id,
                    relationships
                  }
                };
                await didwwApiCall({ method: 'PATCH', path: `/dids/${did.id}`, body: assignBody });
                if (DEBUG) console.log('[didww.order] Updated DID capacity relationships:', { didId: did.id, capacityPoolId: capacityPoolId || null, sharedCapacityGroupId: sharedCapacityGroupId || null });
              }
            } catch (cpErr) {
              console.error('[didww.order] Failed to update DID capacity relationships:', cpErr.response?.data || cpErr.message);
            }
          }
        } catch (dbErr) {
          console.error('[didww.order] Failed to save DID to user_dids:', dbErr.message);
        }
      }
    }

    // Send purchase receipt email if we have numbers and a user email
    // Use did_purchase_receipts table for at-most-once semantics per (user, order)
    if (pool && req.session.userId && includedDids.length > 0 && order.id) {
      try {
        const userId = req.session.userId;
        const orderId = order.id;
        let shouldSend = true;
        try {
          const [ins] = await pool.execute(
            'INSERT IGNORE INTO did_purchase_receipts (user_id, order_id) VALUES (?, ?)',
            [userId, orderId]
          );
          if (!ins || ins.affectedRows === 0) {
            shouldSend = false;
            if (DEBUG) console.log('[didww.order] Purchase receipt already sent, skipping email:', { userId, orderId });
          }
        } catch (markerErr) {
          if (DEBUG) console.warn('[didww.order] Failed to upsert receipt marker, may send duplicate email:', markerErr.message || markerErr);
        }

        if (shouldSend) {
          let username = '';
          let firstName = '';
          let lastName = '';
          let userEmail = '';
          if (pool) {
            const [rows] = await pool.execute('SELECT username, firstname, lastname, email FROM signup_users WHERE id=? LIMIT 1', [userId]);
            if (rows && rows[0]) {
              if (rows[0].username) username = String(rows[0].username);
              if (rows[0].firstname) firstName = String(rows[0].firstname);
              if (rows[0].lastname)  lastName  = String(rows[0].lastname);
              if (rows[0].email)     userEmail = String(rows[0].email);
            }
          }
          if (userEmail) {
            const fullName = `${firstName || ''} ${lastName || ''}`.trim();
            const displayName = fullName || username || (req.session.username || 'Customer');

            // Build per-number line items with location and pricing
            let items = [];
            try {
              const didIds = includedDids.map(d => d && d.id).filter(Boolean);
              if (didIds.length > 0) {
                const idsFilter = didIds.join(',');
                const didsResp = await didwwApiCall({
                  method: 'GET',
                  path: `/dids?filter[id]=${idsFilter}&include=did_group.city,did_group.region,did_group.country,did_group.stock_keeping_units`
                });
                items = buildDidPurchaseLineItems(didsResp.data || includedDids, didsResp.included || []);
              }
            } catch (metaErr) {
              if (DEBUG) console.warn('[didww.order] Failed to fetch DID metadata for receipt:', metaErr.message || metaErr);
            }
            if (!items || items.length === 0) {
              items = buildDidPurchaseLineItems(includedDids, []);
            }

            const totalAmount = parseFloat(order.attributes?.amount || String(purchaseAmount || 0)) || purchaseAmount || 0;
            const orderRef = order.attributes?.reference || order.id;
            await sendDidPurchaseReceiptEmail({
              toEmail: userEmail,
              displayName,
              items,
              totalAmount,
              orderReference: orderRef
            });
          }
        }
      } catch (emailErr) {
        if (DEBUG) console.warn('[didww.order] Failed to send purchase receipt email:', emailErr.message || emailErr);
      }
    }
    
    return res.json({ success: true, data: order, dids: includedDids });
  } catch (e) {
    const upstreamStatus = e && e.response ? e.response.status : undefined;
    const didwwErrors = e && e.response && e.response.data ? e.response.data.errors : undefined;

    const errorTexts = [];
    if (Array.isArray(didwwErrors)) {
      for (const er of didwwErrors) {
        if (er && er.detail) errorTexts.push(String(er.detail));
        if (er && er.title) errorTexts.push(String(er.title));
      }
    }
    const joined = errorTexts.join(' | ').toLowerCase();
    const first = Array.isArray(didwwErrors) && didwwErrors.length ? didwwErrors[0] : null;
    const fallbackMsg = (first && (first.detail || first.title)) ? String(first.detail || first.title) : (e && e.message ? String(e.message) : 'Failed to place order');

    if (DEBUG) {
      console.error('[didww.order] error:', {
        upstreamStatus,
        errors: didwwErrors,
        message: e && e.message ? e.message : undefined
      });
    }

    // DIDWW "Insufficient funds" refers to the provider (TalkUSA) DIDWW account balance.
    // Do not tell the customer to "add funds" (that's for MagnusBilling balance) — instead
    // treat as a temporary service issue.
    if (joined.includes('insufficient funds')) {
      return res.status(503).json({
        success: false,
        message: 'Number ordering is temporarily unavailable. Please try again later or contact support.'
      });
    }

    // Pass through common provider validation errors as 400 so the UI shows the message.
    if (upstreamStatus && upstreamStatus >= 400 && upstreamStatus < 500) {
      if (upstreamStatus === 429) {
        return res.status(503).json({ success: false, message: 'Provider is rate limiting requests. Please try again in a moment.' });
      }
      // Treat auth/permission/not-found as an upstream/config problem.
      if (upstreamStatus === 401 || upstreamStatus === 403 || upstreamStatus === 404) {
        return res.status(502).json({ success: false, message: 'Number provider error. Please try again later or contact support.' });
      }
      return res.status(400).json({ success: false, message: fallbackMsg });
    }

    // Provider or network failure.
    return res.status(502).json({ success: false, message: fallbackMsg });
  }
});

// List all DIDs from DIDWW account (My Numbers) - filtered to user's purchased DIDs only
app.get('/api/me/didww/dids', requireAuth, async (req, res) => {
  try {
    // First, check for pending orders and reconcile them
    if (pool && req.session.userId) {
      try {
        const [pendingOrders] = await pool.execute(
          'SELECT order_id FROM pending_orders WHERE user_id = ? AND reconciled = 0',
          [req.session.userId]
        );
        for (const po of pendingOrders) {
          try {
            // Check if order is now completed
            const orderData = await didwwApiCall({ method: 'GET', path: `/orders/${po.order_id}` });
            if (orderData.data?.attributes?.status === 'Completed') {
              // Fetch DIDs created by this order (with location and pricing includes)
              const didsData = await didwwApiCall({ method: 'GET', path: `/dids?filter[order.id]=${po.order_id}&include=did_group.city,did_group.region,did_group.country,did_group.stock_keeping_units` });
              if (didsData.data && didsData.data.length > 0) {
                const capacityPoolId = await getCapacityPoolId();
                const sharedCapacityGroupId = await getSharedCapacityGroupId();
                for (const did of didsData.data) {
                  const didNumber = did.attributes?.number || '';
                  const didType = did.attributes?.did_type || null;
                  await pool.execute(
                    'INSERT INTO user_dids (user_id, didww_did_id, did_number, did_type) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE did_number=VALUES(did_number)',
                    [req.session.userId, did.id, didNumber, didType]
                  );
                  if (DEBUG) console.log('[didww.reconcile] Saved DID from pending order:', { orderId: po.order_id, didId: did.id, number: didNumber });
                  
                  // Assign DID to capacity pool / shared capacity group if configured
                  if (capacityPoolId || sharedCapacityGroupId) {
                    try {
                      const relationships = {};
                      if (capacityPoolId) {
                        relationships.capacity_pool = {
                          data: { type: 'capacity_pools', id: capacityPoolId }
                        };
                      }
                      if (sharedCapacityGroupId) {
                        relationships.shared_capacity_group = {
                          data: { type: 'shared_capacity_groups', id: sharedCapacityGroupId }
                        };
                      }
                      if (Object.keys(relationships).length > 0) {
                        const assignBody = {
                          data: {
                            type: 'dids',
                            id: did.id,
                            relationships
                          }
                        };
                        await didwwApiCall({ method: 'PATCH', path: `/dids/${did.id}`, body: assignBody });
                        if (DEBUG) console.log('[didww.reconcile] Updated DID capacity relationships:', { didId: did.id, capacityPoolId: capacityPoolId || null, sharedCapacityGroupId: sharedCapacityGroupId || null });
                      }
                    } catch (cpErr) {
                      console.error('[didww.reconcile] Failed to update DID capacity relationships:', cpErr.response?.data || cpErr.message);
                    }
                  }
                }

                // After saving and assigning, send purchase receipt email (best-effort, at-most-once)
                try {
                  let shouldSend = true;
                  if (pool && req.session.userId && po.order_id) {
                    try {
                      const [ins] = await pool.execute(
                        'INSERT IGNORE INTO did_purchase_receipts (user_id, order_id) VALUES (?, ?)',
                        [req.session.userId, po.order_id]
                      );
                      if (!ins || ins.affectedRows === 0) {
                        shouldSend = false;
                        if (DEBUG) console.log('[didww.reconcile] Purchase receipt already sent, skipping email:', { userId: req.session.userId, orderId: po.order_id });
                      }
                    } catch (markerErr) {
                      if (DEBUG) console.warn('[didww.reconcile] Failed to upsert receipt marker, may send duplicate email:', markerErr.message || markerErr);
                    }
                  }

                  if (shouldSend) {
                    let username = '';
                    let firstName = '';
                    let lastName = '';
                    let userEmail = '';
                    if (pool) {
                      const [userRows] = await pool.execute('SELECT username, firstname, lastname, email FROM signup_users WHERE id=? LIMIT 1', [req.session.userId]);
                      if (userRows && userRows[0]) {
                        if (userRows[0].username) username = String(userRows[0].username);
                        if (userRows[0].firstname) firstName = String(userRows[0].firstname);
                        if (userRows[0].lastname)  lastName  = String(userRows[0].lastname);
                        if (userRows[0].email)     userEmail = String(userRows[0].email);
                      }
                    }
                    if (userEmail) {
                      const fullName = `${firstName || ''} ${lastName || ''}`.trim();
                      const displayName = fullName || username || (req.session.username || 'Customer');
                      const orderAttrs = orderData.data?.attributes || {};
                      const items = buildDidPurchaseLineItems(didsData.data || [], didsData.included || []);
                      const totalAmount = parseFloat(orderAttrs.amount || '0') || 0;
                      const orderRef = orderAttrs.reference || po.order_id;
                      await sendDidPurchaseReceiptEmail({
                        toEmail: userEmail,
                        displayName,
                        items,
                        totalAmount,
                        orderReference: orderRef
                      });
                    }
                  }
                } catch (emailErr) {
                  if (DEBUG) console.warn('[didww.reconcile] Failed to send purchase receipt email:', emailErr.message || emailErr);
                }
              }
              // Mark order as reconciled
              await pool.execute('UPDATE pending_orders SET reconciled = 1 WHERE order_id = ?', [po.order_id]);
            }
          } catch (reconcileErr) {
            if (DEBUG) console.warn('[didww.reconcile] Error reconciling order:', po.order_id, reconcileErr.message);
          }
        }
      } catch (pendingErr) {
        // Table might not exist yet, that's fine. Only log in DEBUG when it's
        // not the expected "table does not exist" condition.
        if (DEBUG) {
          const code = pendingErr && pendingErr.code;
          const msg = String(pendingErr && pendingErr.message || '');
          const isMissingTable = code === 'ER_NO_SUCH_TABLE' || /doesn['’]t exist/i.test(msg);
          if (!isMissingTable) {
            console.warn('[didww.reconcile] Error checking pending orders:', msg);
          }
        }
      }
    }
    
    // Get user's DID IDs from database
    let userDidIds = [];
    if (pool && req.session.userId) {
      const [rows] = await pool.execute('SELECT didww_did_id FROM user_dids WHERE user_id = ?', [req.session.userId]);
      userDidIds = rows.map(r => r.didww_did_id);
    }
    
    // If user has no DIDs, return empty
    if (userDidIds.length === 0) {
      return res.json({ success: true, data: [], included: [] });
    }
    
    // Fetch all DIDs from DIDWW API with location and pricing info
    const data = await didwwApiCall({ method: 'GET', path: '/dids?include=voice_in_trunk,did_group.city,did_group.region,did_group.country,did_group.stock_keeping_units,capacity_pool' });
    
    // Filter to only user's DIDs
    const allDids = data.data || [];
    const userDids = allDids.filter(d => userDidIds.includes(d.id));
    
    // Best-effort: for any of the user's DIDs that do NOT have capacity relationships yet,
    // attach them to the configured Capacity Pool and/or Shared Capacity Group. This also
    // fixes DIDs purchased before the pool was configured.
    try {
      const capacityPoolId = await getCapacityPoolId();
      const sharedCapacityGroupId = await getSharedCapacityGroupId();
      if (capacityPoolId || sharedCapacityGroupId) {
        for (const did of userDids) {
          const hasCapacityPool = did.relationships?.capacity_pool?.data?.id;
          const hasSharedGroup = did.relationships?.shared_capacity_group?.data?.id;
          if (!hasCapacityPool || !hasSharedGroup) {
            try {
              const relationships = {};
              if (!hasCapacityPool && capacityPoolId) {
                relationships.capacity_pool = {
                  data: { type: 'capacity_pools', id: capacityPoolId }
                };
              }
              if (!hasSharedGroup && sharedCapacityGroupId) {
                relationships.shared_capacity_group = {
                  data: { type: 'shared_capacity_groups', id: sharedCapacityGroupId }
                };
              }
              if (Object.keys(relationships).length === 0) continue;

              const assignBody = {
                data: {
                  type: 'dids',
                  id: did.id,
                  relationships
                }
              };
              await didwwApiCall({ method: 'PATCH', path: `/dids/${did.id}`, body: assignBody });
              if (DEBUG) console.log('[didww.dids.autoCapacity] Updated DID capacity relationships:', {
                didId: did.id,
                addedCapacityPool: !hasCapacityPool && !!capacityPoolId,
                addedSharedGroup: !hasSharedGroup && !!sharedCapacityGroupId
              });
            } catch (cpErr) {
              const status = cpErr.response && cpErr.response.status;
              const errors = (cpErr.response && cpErr.response.data && cpErr.response.data.errors) || [];

              const isAdditionalChannelsError =
                status === 422 &&
                Array.isArray(errors) &&
                errors.length > 0 &&
                errors.every(err => {
                  const title = String(err.title || err.detail || '').toLowerCase();
                  return (
                    title.includes('does not allow additional channels') ||
                    title.includes('group does not allow additional channels')
                  );
                });

              if (isAdditionalChannelsError) {
                if (DEBUG) {
                  const didAttrs = did.attributes || {};
                  console.warn(
                    '[didww.dids.autoCapacity] DID does not allow additional channels, skipping auto capacity for this number:',
                    {
                      didId: did.id,
                      number: didAttrs.number || null,
                      errors
                    }
                  );
                }
                // Do not treat this as a hard error; just skip this DID.
              } else {
                console.error(
                  '[didww.dids.autoCapacity] Failed to update DID capacity relationships:',
                  cpErr.response?.data || cpErr.message || cpErr
                );
              }
            }
          }
        }
      }
    } catch (autoCpErr) {
      if (DEBUG) console.warn('[didww.dids.autoCapacity] Error during auto capacity assignment:', autoCpErr.message);
    }
    
    // Filter included data to only relevant items
    const allIncluded = data.included || [];
    const relevantIncluded = allIncluded.filter(inc => {
      // Keep voice_in_trunks that are assigned to user's DIDs
      if (inc.type === 'voice_in_trunks') {
        return userDids.some(d => d.relationships?.voice_in_trunk?.data?.id === inc.id);
      }
      // Keep did_groups referenced by user's DIDs
      if (inc.type === 'did_groups') {
        return userDids.some(d => d.relationships?.did_group?.data?.id === inc.id);
      }
      // Keep locations (cities, regions, countries) and SKUs and capacity_pools
      return true;
    });
    
    // NOTE: Markup billing for DIDs is now handled by the background
    // scheduler (runMarkupBillingTick/startBillingScheduler), not
    // directly by this HTTP route. This endpoint only returns the
    // current list of numbers and metadata.
    return res.json({ success: true, data: userDids, included: relevantIncluded });
  } catch (e) {
    const errMsg = e.response?.data?.errors?.[0]?.detail || e.message || 'Unknown error';
    const errCode = e.code || e.response?.status || 'UNKNOWN';
    if (DEBUG) console.error('[didww.dids] error:', { code: errCode, message: errMsg, responseData: e.response?.data });
    // Check for timeout
    if (e.code === 'ECONNABORTED' || e.code === 'ETIMEDOUT') {
      return res.status(504).json({ success: false, message: 'Request to DIDWW timed out. Please try again.' });
    }
    return res.status(500).json({ success: false, message: `Failed to fetch DIDs: ${errMsg}` });
  }
});

// Assign a trunk to a DID
app.patch('/api/me/didww/dids/:id/trunk', requireAuth, async (req, res) => {
  try {
    const didId = req.params.id;
    const { trunk_id } = req.body || {};
    
    if (DEBUG) console.log('[didww.did.trunk] Request:', { didId, trunk_id, body: req.body });
    
    // Verify user owns this DID
    if (pool && req.session.userId) {
      const [rows] = await pool.execute('SELECT 1 FROM user_dids WHERE user_id = ? AND didww_did_id = ?', [req.session.userId, didId]);
      if (rows.length === 0) {
        return res.status(403).json({ success: false, message: 'You do not own this DID' });
      }
    }
    
    // Update DID in DIDWW to assign or unassign trunk
    const body = {
      data: {
        type: 'dids',
        id: didId,
        relationships: {
          voice_in_trunk: trunk_id ? { data: { type: 'voice_in_trunks', id: trunk_id } } : { data: null }
        }
      }
    };
    
    if (DEBUG) console.log('[didww.did.trunk] PATCH body:', JSON.stringify(body));
    await didwwApiCall({ method: 'PATCH', path: `/dids/${didId}`, body });
    if (DEBUG) console.log('[didww.did.trunk] Success:', { didId, trunk_id: trunk_id || '(unassigned)' });
    return res.json({ success: true });
  } catch (e) {
    if (DEBUG) console.error('[didww.did.trunk] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to update DID trunk' });
  }
});

// Release/cancel a DID (DIDWW uses PATCH with terminated=true, not DELETE)
app.delete('/api/me/didww/dids/:id', requireAuth, async (req, res) => {
  try {
    const didId = req.params.id;
    
    // Verify user owns this DID
    if (pool && req.session.userId) {
      const [rows] = await pool.execute('SELECT 1 FROM user_dids WHERE user_id = ? AND didww_did_id = ?', [req.session.userId, didId]);
      if (rows.length === 0) {
        return res.status(403).json({ success: false, message: 'You do not own this DID' });
      }
    }
    
    // Cancel/terminate DID in DIDWW (set terminated=true)
    const body = {
      data: {
        type: 'dids',
        id: didId,
        attributes: {
          terminated: true
        }
      }
    };
    await didwwApiCall({ method: 'PATCH', path: `/dids/${didId}`, body });
    if (DEBUG) console.log('[didww.did.cancel] Terminated DID:', didId);
    
    // Remove from user_dids table
    if (pool && req.session.userId) {
      await pool.execute('DELETE FROM user_dids WHERE user_id = ? AND didww_did_id = ?', [req.session.userId, didId]);
    }
    
    return res.json({ success: true });
  } catch (e) {
    if (DEBUG) console.error('[didww.did.cancel] error:', e.response?.data || e.message || e);
    return res.status(500).json({ success: false, message: 'Failed to cancel DID' });
  }
});

// Email verification: start
app.post('/api/verify-email', otpSendLimiter, async (req, res) => {
  try {
    const { username, password, firstname, lastname, email, phone } = req.body || {};
    if (!username || !password || !firstname || !lastname || !email) {
      return res.status(400).json({ success: false, message: 'All fields are required: username, password, firstname, lastname, email' });
    }
    if (!phone || !/^\d{11}$/.test(String(phone))) {
      return res.status(400).json({ success: false, message: 'Phone number is required and must be 11 digits (numbers only).' });
    }
    if (!usernameIsAlnumMax10(username)) {
      return res.status(400).json({ success: false, message: 'Username must be letters and numbers only, maximum 10 characters.' });
    }
    if (!passwordIsAlnumMax10(password)) {
      return res.status(400).json({ success: false, message: 'Password must be letters and numbers only, maximum 10 characters.' });
    }
    const availability = await checkAvailability({ username, email });
    if (!availability.usernameAvailable || !availability.emailAvailable) {
      return res.status(409).json({ success: false, message: 'Username or email already exists', availability });
    }
    const token = crypto.randomBytes(16).toString('hex');
    const code = otp();
    const record = {
      codeHash: sha256(code),
      email,
      expiresAt: Date.now() + OTP_TTL_MS,
      fields: { username, password, firstname, lastname, email, phone }
    };
    await storeVerification({ token, codeHash: record.codeHash, email, expiresAt: record.expiresAt, fields: record.fields });
    await sendVerificationEmail(email, code);
    if (DEBUG) console.debug('Verification code sent', { email, token });
    return res.status(200).json({ success: true, token });
  } catch (err) {
    console.error('verify-email error', err.message || err);
    return res.status(500).json({ success: false, message: 'Failed to send verification code' });
  }
});

// Email verification: complete -> create account
app.post('/api/complete-signup', otpVerifyLimiter, async (req, res) => {
  try {
    const { token, code, email: reqEmail } = req.body || {};
    if (DEBUG) console.log('[complete-signup] Request received:', { token, hasCode: !!code, hasEmail: !!reqEmail });
    if (!code) { return res.status(400).json({ success: false, message: 'code is required' }); }
    // Support legacy flow (email+code) and token+code. Prefer token when provided.
    let rec = null;
    if (token) {
      rec = await fetchVerification(token);
      if (!rec) { if (DEBUG) console.log('[complete-signup] No record found for token:', token); return res.status(400).json({ success: false, message: 'Invalid or expired token' }); }
    } else if (reqEmail) {
      rec = await fetchVerificationLatestByEmail(reqEmail);
      if (!rec) { if (DEBUG) console.log('[complete-signup] No active record for email:', reqEmail); return res.status(400).json({ success: false, message: 'Invalid or expired code' }); }
    } else {
      return res.status(400).json({ success: false, message: 'email or token is required with code' });
    }
    // Ensure we have token for attempts/used updates
    const activeToken = rec.token;
    if (rec.used) { if (DEBUG) console.log('[complete-signup] Code already used:', { token, email: rec.email }); return res.status(400).json({ success: false, message: 'This code was already used' }); }
    if (Date.now() > Number(rec.expires_at)) { if (DEBUG) console.log('[complete-signup] Code expired:', { token: activeToken, email: rec.email, expiresAt: rec.expires_at, now: Date.now() }); await markVerificationUsed(activeToken); return res.status(400).json({ success: false, message: 'Code expired, please request a new one' }); }
    const attempts = Number(rec.attempts || 0);
    if (attempts >= OTP_MAX_ATTEMPTS) {
      if (DEBUG) console.log('[complete-signup] Too many OTP attempts for token:', { token: activeToken, email: rec.email, attempts });
      await markVerificationUsed(activeToken);
      return res.status(400).json({ success: false, message: 'Too many invalid attempts. Please request a new verification code.' });
    }
    if (sha256(code) !== rec.code_hash) {
      if (DEBUG) console.log('[complete-signup] Code mismatch:', { token: activeToken, email: rec.email, attempts: attempts + 1 });
      try {
        await pool.execute('UPDATE email_verifications SET attempts = attempts + 1 WHERE token = ?', [activeToken]);
      } catch (e) {
        if (DEBUG) console.warn('[complete-signup] Failed to increment OTP attempts:', e.message || e);
      }
      if (attempts + 1 >= OTP_MAX_ATTEMPTS) {
        try { await markVerificationUsed(activeToken); } catch {}
        return res.status(400).json({ success: false, message: 'Too many invalid attempts. Please request a new verification code.' });
      }
      return res.status(400).json({ success: false, message: 'Invalid code' });
    }
    if (DEBUG) console.log('[complete-signup] Code validated successfully:', { token: activeToken, email: rec.email });
    // Don't mark as used yet - only after successful account creation

  // proceed to create account using the same logic as /api/signup
  const { username, firstname, lastname, email, phone } = rec;
  if (DEBUG) console.log('[complete-signup] Creating account for:', { username, email });
  if (!usernameIsAlnumMax10(username)) {
    if (DEBUG) console.log('[complete-signup] Username validation failed');
    return res.status(400).json({ success: false, message: 'Username must be letters and numbers only, maximum 10 characters.' });
  }
  // Using stored plaintext password (legacy behavior)
  let plainPassword = String(rec.password || '');
  const looksLikeBcrypt = plainPassword.startsWith('$2a$') || plainPassword.startsWith('$2b$') || plainPassword.startsWith('$2y$');
  if (looksLikeBcrypt || !plainPassword) {
    if (DEBUG) console.log('[complete-signup] Stored password appears to be a hash/empty; cannot proceed');
    return res.status(400).json({ success: false, message: 'Stored verification record is invalid. Please restart signup.' });
  }
  if (!passwordIsAlnumMax10(plainPassword)) {
    if (DEBUG) console.log('[complete-signup] Password validation failed');
    return res.status(400).json({ success: false, message: 'Password must be letters and numbers only, maximum 10 characters.' });
  }

  const availability = await checkAvailability({ username, email });
  if (DEBUG) console.log('[complete-signup] Availability check:', availability);
  if (!availability.usernameAvailable || !availability.emailAvailable) {
    if (DEBUG) console.log('[complete-signup] Username or email already taken');
    return res.status(409).json({ success: false, message: 'Username or email already exists', availability });
  }

    // Prepare user fields (MagnusBilling expects form-encoded fields, not JSON)
    const fields = {
      username,
      password: plainPassword,
      active: '1',
      id_group: parseInt(process.env.DEFAULT_GROUP_ID) || 3,
      id_plan: parseInt(process.env.DEFAULT_PLAN_ID) || 1,
      firstname,
      lastname,
      email,
      phone: phone || '',
      calllimit: parseInt(process.env.DEFAULT_CALL_LIMIT) || 5,
      mix_monitor_format: 'gsm',
      cpslimit: 1
    };

    // MagnusBilling API configuration (per official PHP SDK)
    const apiKey = process.env.MAGNUSBILLING_API_KEY;
    const apiSecret = process.env.MAGNUSBILLING_API_SECRET;
    const magnusBillingUrl = process.env.MAGNUSBILLING_URL; // e.g. https://host/mbilling
    const tlsInsecure = process.env.MAGNUSBILLING_TLS_INSECURE === '1';
    const tlsServername = process.env.MAGNUSBILLING_TLS_SERVERNAME;
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;

    if (!apiKey || !apiSecret || !magnusBillingUrl) {
      console.error('Missing MagnusBilling configuration');
      return res.status(500).json({ success: false, message: 'Server configuration error' });
    }

    const endpoint = joinUrl(magnusBillingUrl, '/index.php/user/save');
    const nowSec = Math.floor(Date.now() / 1000);
    const micro = String(Number(process.hrtime.bigint() % 1000000n)).padStart(6, '0');
    const nonce = `${nowSec}${micro}`;
    const urlParams = new URLSearchParams();
    urlParams.append('module', 'user');
    urlParams.append('action', 'save');
    urlParams.append('id', '0');
    urlParams.append('createUser', '1');
    urlParams.append('nonce', nonce);
    for (const [k, v] of Object.entries(fields)) { if (v !== undefined && v !== null) urlParams.append(k, String(v)); }
    const postData = urlParams.toString();
    const signature = crypto.createHmac('sha512', apiSecret).update(postData).digest('hex');
    const httpsAgent = new https.Agent({ rejectUnauthorized: !tlsInsecure, ...(tlsServername ? { servername: tlsServername } : {}) });

    if (DEBUG) console.log('[complete-signup] Calling MagnusBilling API:', { endpoint, username: fields.username });
    const response = await axios.post(endpoint, postData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(hostHeader ? { 'Host': hostHeader } : {}), 'Key': apiKey, 'Sign': signature },
      httpsAgent,
      timeout: 30000
    });

if (response.status >= 200 && response.status < 300) {
      const result = response.data;
      if (DEBUG) console.log('[complete-signup] MagnusBilling response:', { status: response.status, success: result.status === 'success' || result.success });
      if (result.status === 'success' || result.success) {
        const sipDomain = process.env.SIP_DOMAIN || process.env.MAGNUSBILLING_TLS_SERVERNAME || process.env.MAGNUSBILLING_HOST_HEADER || '';
        const createdId = result?.data?.id || result?.data?.id_user || result?.id || result?.rows?.[0]?.id_user;
        if (DEBUG) console.log('[complete-signup] Account created in MagnusBilling:', { userId: createdId, username });
        // Mark verification as used now that account creation succeeded
        try { await markVerificationUsed(activeToken); } catch (e) { if (DEBUG) console.warn('Failed to mark verification as used:', e.message); }
        try { await purgeExpired(); } catch {}
        // Save to local DB for future availability checks (store password hash for app login)
        let passwordHash = null; try { passwordHash = await bcrypt.hash(plainPassword, 12); } catch {}
        try { await saveUserRow({ magnusUserId: createdId, username, email, firstname, lastname, phone, passwordHash }); } catch (e) { if (DEBUG) console.warn('Save user failed', e.message || e); }
        try { await sendWelcomeEmail(email, username, sipDomain, process.env.MAGNUSBILLING_URL, plainPassword); } catch (e) { if (DEBUG) console.warn('Welcome email failed', e.message || e); }
        if (DEBUG) console.log('[complete-signup] Signup complete! Returning success.');
        return res.status(200).json({ success: true, message: 'Account created successfully!', data: { username, userId: createdId, sipDomain, portalUrl: process.env.MAGNUSBILLING_URL, password: plainPassword } });
      }
      if (DEBUG) console.log('[complete-signup] MagnusBilling returned non-success:', result);
      // Extract error message from MagnusBilling response
      const errorMsg = result.errors || result.message || result.error || 'Failed to create account';
      return res.status(400).json({ success: false, message: errorMsg });
    }

    return res.status(500).json({ success: false, message: 'Unexpected response from server' });
  } catch (error) {
    // Log all error types properly
    if (error.message === 'Database not configured') {
      console.error('[complete-signup] Database not configured');
      return res.status(500).json({ success: false, message: 'Database connection error. Please try again later.' });
    }
    const log = { method: error?.config?.method, url: error?.config?.baseURL ? `${error.config.baseURL}${error.config.url}` : error?.config?.url, status: error?.response?.status, data: error?.response?.data || error?.response?.statusText || error?.message, stack: error?.stack };
    console.error('complete-signup error', log);
    if (error.response) {
      let msg = 'Failed to create account';
      if (typeof error.response.data === 'string') msg = error.response.data; else if (error.response.data?.message) msg = error.response.data.message;
      return res.status(error.response.status).json({ success: false, message: msg, error: error.response.data });
    } else if (error.request) {
      return res.status(503).json({ success: false, message: 'Unable to reach MagnusBilling server' });
    } else {
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }
  }
});

// Username/email availability endpoint
app.get('/api/check-availability', async (req, res) => {
  try {
    const { username, email } = req.query;
    const availability = await checkAvailability({ username, email });
    res.json({ success: true, ...availability });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Error checking availability' });
  }
});




// Signup API endpoint (legacy direct)
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, firstname, lastname, email, phone } = req.body;

// Validate required fields
    if (!username || !password || !firstname || !lastname || !email) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required: username, password, firstname, lastname, email'
      });
    }
    if (!usernameIsAlnumMax10(username)) {
      return res.status(400).json({ success: false, message: 'Username must be letters and numbers only, maximum 10 characters.' });
    }
    if (!passwordIsAlnumMax10(password)) {
      return res.status(400).json({ success: false, message: 'Password must be letters and numbers only, maximum 10 characters.' });
    }

    // Prepare user fields (MagnusBilling expects form-encoded fields, not JSON)
    const fields = {
      username,
      password,
      active: '1',
      id_group: parseInt(process.env.DEFAULT_GROUP_ID) || 3,
      id_plan: parseInt(process.env.DEFAULT_PLAN_ID) || 1,
      firstname,
      lastname,
      email,
      phone: phone || '',
      calllimit: parseInt(process.env.DEFAULT_CALL_LIMIT) || 5,
      mix_monitor_format: 'gsm',
      cpslimit: 1
    };

    // MagnusBilling API configuration (per official PHP SDK)
    const apiKey = process.env.MAGNUSBILLING_API_KEY;
    const apiSecret = process.env.MAGNUSBILLING_API_SECRET;
    const magnusBillingUrl = process.env.MAGNUSBILLING_URL; // e.g. https://host/mbilling
    const tlsInsecure = process.env.MAGNUSBILLING_TLS_INSECURE === '1';
    const tlsServername = process.env.MAGNUSBILLING_TLS_SERVERNAME; // set to domain when using IP with a domain cert
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER; // force Host header (use domain) when connecting to IP

    if (!apiKey || !apiSecret || !magnusBillingUrl) {
      console.error('Missing MagnusBilling configuration');
      return res.status(500).json({
        success: false,
        message: 'Server configuration error'
      });
    }

    // Target: {public_url}/index.php/user/save
    const endpoint = joinUrl(magnusBillingUrl, '/index.php/user/save');

    // Build POST data per SDK: include nonce, module, action, id, createUser
    const nowSec = Math.floor(Date.now() / 1000);
    const micro = String(Number(process.hrtime.bigint() % 1000000n)).padStart(6, '0');
    const nonce = `${nowSec}${micro}`;
    const urlParams = new URLSearchParams();
    urlParams.append('module', 'user');
    urlParams.append('action', 'save');
    urlParams.append('id', '0');
    urlParams.append('createUser', '1');
    urlParams.append('nonce', nonce);
    for (const [k, v] of Object.entries(fields)) {
      if (v !== undefined && v !== null) urlParams.append(k, String(v));
    }
    const postData = urlParams.toString();

    // HMAC-SHA512 signature over the urlencoded body, headers 'Key' and 'Sign'
    const signature = crypto.createHmac('sha512', apiSecret).update(postData).digest('hex');

    if (DEBUG) {
      console.debug('Signup request prepared', {
        endpoint,
        method: 'POST',
        hasApiKey: Boolean(apiKey),
        hasApiSecret: Boolean(apiSecret),
        group: fields.id_group,
        plan: fields.id_plan,
        tls: { insecure: tlsInsecure, servername: tlsServername || null },
        hostHeader: hostHeader || null
      });
    }

    // Make request to MagnusBilling API
    const httpsAgent = new https.Agent({
      rejectUnauthorized: !tlsInsecure,
      ...(tlsServername ? { servername: tlsServername } : {})
    });

    const response = await axios.post(endpoint, postData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(hostHeader ? { 'Host': hostHeader } : {}),
        'Key': apiKey,
        'Sign': signature
      },
      httpsAgent,
      timeout: 30000 // 30 second timeout
    });

    // Handle successful response
    if (response.status >= 200 && response.status < 300) {
      const result = response.data;
      
      if (result.status === 'success' || result.success) {
        const sipDomain = process.env.SIP_DOMAIN || process.env.MAGNUSBILLING_TLS_SERVERNAME || process.env.MAGNUSBILLING_HOST_HEADER || '';
        // Fire-and-forget welcome email
        const createdId = result?.data?.id || result?.data?.id_user || result?.id || result?.rows?.[0]?.id_user;
        const createdUsername = result?.data?.username || username;
        try { await sendWelcomeEmail(email, createdUsername, sipDomain, process.env.MAGNUSBILLING_URL, password); } catch (e) { if (DEBUG) console.warn('Welcome email failed', e.message || e); }
        // Save to local DB (store password hash for app login)
        let passwordHash = null; try { passwordHash = await bcrypt.hash(password, 12); } catch {}
        try { await saveUserRow({ magnusUserId: createdId, username: createdUsername, email, firstname, lastname, phone, passwordHash }); } catch (e) { if (DEBUG) console.warn('Save user failed', e.message || e); }
        return res.status(200).json({
          success: true,
          message: 'Account created successfully!',
          data: {
            username: result.data?.username || username,
            userId: result.data?.id,
            sipDomain,
            portalUrl: process.env.MAGNUSBILLING_URL,
            password // one-time echo so the client can display it after signup
          }
        });
      }
      return res.status(400).json({ success: false, message: result.message || 'Failed to create account' });
    }

    // Handle unexpected response
    return res.status(500).json({
      success: false,
      message: 'Unexpected response from server'
    });

  } catch (error) {
    // Structured error logging to capture the exact request URL and status
    const log = {
      method: error?.config?.method,
      url: error?.config?.baseURL ? `${error.config.baseURL}${error.config.url}` : error?.config?.url,
      status: error?.response?.status,
      data: error?.response?.data || error?.response?.statusText || error?.message
    };
    console.error('Signup error', log);

    if (error.response) {
      // Pass through raw body when available; MagnusBilling often returns text/HTML on errors
      let msg = 'Failed to create account';
      if (typeof error.response.data === 'string') msg = error.response.data;
      else if (error.response.data?.message) msg = error.response.data.message;
      return res.status(error.response.status).json({ success: false, message: msg, error: error.response.data });
    } else if (error.request) {
      return res.status(503).json({
        success: false,
        message: 'Unable to reach MagnusBilling server'
      });
    } else {
      return res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }
});

// Lightweight periodic billing runner (runs independently of HTTP requests)
// To keep things safe, this uses the same DB-level idempotency as the
// /api/me/didww/dids route, so running both is harmless.
async function runMarkupBillingTick() {
  if (!pool) return;
  try {
    const [users] = await pool.execute('SELECT id, magnus_user_id FROM signup_users WHERE magnus_user_id IS NOT NULL');
    if (!users || users.length === 0) {
      if (DEBUG) console.log('[billing.markup] No users with magnus_user_id; skipping tick');
      return;
    }

    // Build a fast lookup of which users actually have DIDs
    const [userDidRows] = await pool.execute('SELECT user_id, didww_did_id FROM user_dids');
    if (!userDidRows || userDidRows.length === 0) {
      if (DEBUG) console.log('[billing.markup] No user_dids rows; skipping tick');
      return;
    }
    const userIdSet = new Set(users.map(u => String(u.id)));
    const didsByUser = new Map(); // localUserId -> [didww_did_id]
    for (const row of userDidRows) {
      const uid = String(row.user_id);
      if (!userIdSet.has(uid)) continue;
      if (!didsByUser.has(uid)) didsByUser.set(uid, []);
      didsByUser.get(uid).push(row.didww_did_id);
    }

    const data = await didwwApiCall({
      method: 'GET',
      path: '/dids?include=voice_in_trunk,did_group.city,did_group.region,did_group.country,did_group.stock_keeping_units,capacity_pool'
    });
    const allDids = data.data || [];
    const allIncluded = data.included || [];
    if (!allDids.length) {
      if (DEBUG) console.log('[billing.markup] No DIDs on DIDWW account; skipping tick');
      return;
    }

    // Build a fast lookup from DIDWW DID id -> DID object
    const didById = new Map();
    for (const d of allDids) {
      if (d && d.id) didById.set(d.id, d);
    }

    const httpsAgent = magnusBillingAgent;
    const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;

    for (const u of users) {
      const localUserId = String(u.id);
      const magnusUserId = String(u.magnus_user_id || '').trim();
      if (!magnusUserId) continue;

      const userDidIds = didsByUser.get(localUserId) || [];
      if (!userDidIds.length) continue;

      const userDids = userDidIds
        .map(id => didById.get(id))
        .filter(Boolean);
      if (!userDids.length) continue;

      await billDidMarkupsForUser({
        localUserId,
        magnusUserId,
        userDids,
        included: allIncluded,
        httpsAgent,
        hostHeader
      });

      // Also bill inbound CDR usage for this user (if any)
      await billInboundCdrsForUser({
        localUserId,
        magnusUserId,
        httpsAgent,
        hostHeader
      });
    }
  } catch (e) {
    if (DEBUG) console.warn('[billing.markup] Error during scheduler tick:', e.message || e);
  }
}

// Start a simple interval-based scheduler.
// Controlled by BILLING_MARKUP_INTERVAL_MINUTES; if unset or 0, scheduler is disabled.
function startBillingScheduler() {
  const intervalMs = (parseInt(process.env.BILLING_MARKUP_INTERVAL_MINUTES || '0', 10) || 0) * 60 * 1000;
    if (!intervalMs) {
      if (DEBUG) console.log('[billing.scheduler] Disabled (no interval set)');
      return;
    }
    if (DEBUG) console.log('[billing.scheduler] Enabled with interval (ms):', intervalMs);
    setInterval(() => {
      runMarkupBillingTick();
    }, intervalMs);
}

// Start server after DB + session store are initialized
async function startServer() {
  try {
    await initDb().catch(err => console.error('DB init error', err));

    if (sessionStore) {
      sessionConfig.store = sessionStore;
      sessionMiddleware = session(sessionConfig);
      console.log('MySQL session store initialized');
    } else {
      sessionMiddleware = session(sessionConfig);
      console.warn('MySQL session store not available; using in-memory sessions');
    }

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`TalkUSA Signup Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV}`);
      if (DEBUG) console.log('Debug logging enabled');
      startBillingScheduler();
      startCdrImportScheduler();
    });
  } catch (e) {
    console.error('Fatal startup error', e.message || e);
    process.exit(1);
  }
}

startServer();

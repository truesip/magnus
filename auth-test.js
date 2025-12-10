#!/usr/bin/env node
'use strict';
require('dotenv').config();
const axios = require('axios');
const https = require('https');
const crypto = require('crypto');

function joinUrl(base, p) {
  if (!base) return p || '';
  let b = String(base);
  let s = String(p || '');
  if (b.endsWith('/')) b = b.slice(0, -1);
  if (s && !s.startsWith('/')) s = '/' + s;
  return b + s;
}

(async () => {
  const base = process.env.MAGNUSBILLING_URL || '';
  const rawUserPath = process.env.MAGNUSBILLING_USER_PATH;
  const configuredPath = (rawUserPath === undefined) ? '/user' : rawUserPath; // empty string allowed

  const candidates = new Set();
  candidates.add(joinUrl(base, configuredPath));
  candidates.add(joinUrl(base, '/api/user'));
  const baseWithApi = joinUrl(base, '/api');
  candidates.add(joinUrl(baseWithApi, configuredPath));
  // Also try common PHP front-controller style paths
  candidates.add(joinUrl(base, '/index.php/api/user'));
  candidates.add(joinUrl(base, '/index.php/api'));

  const apiKey = process.env.MAGNUSBILLING_API_KEY || '';
  const apiSecret = process.env.MAGNUSBILLING_API_SECRET || '';
  const tlsInsecure = process.env.MAGNUSBILLING_TLS_INSECURE === '1';
  const tlsServername = process.env.MAGNUSBILLING_TLS_SERVERNAME;
  const hostHeader = process.env.MAGNUSBILLING_HOST_HEADER;

  const ts = Math.floor(Date.now() / 1000);
  let signature = '';
  try {
    signature = crypto.createHmac('sha256', apiSecret).update(apiKey + ts).digest('hex');
  } catch (e) {
    // ignore if missing secret
  }

  const httpsAgent = new https.Agent({
    rejectUnauthorized: !tlsInsecure,
    ...(tlsServername ? { servername: tlsServername } : {})
  });

  const headers = {
    'Content-Type': 'application/json',
    ...(hostHeader ? { 'Host': hostHeader } : {}),
    ...(apiKey ? { 'X-API-KEY': apiKey } : {}),
    ...(apiSecret ? { 'X-API-SECRET': apiSecret } : {}),
    ...(signature ? { 'X-Signature': signature } : {}),
    'X-Timestamp': ts
  };

  const results = [];
  // Probe with header-based auth
  for (const url of candidates) {
    try {
      const resp = await axios.get(url, {
        headers,
        httpsAgent,
        timeout: 15000,
        validateStatus: () => true
      });
      let hint;
      if (resp.status === 401 || resp.status === 403) hint = 'auth likely invalid but endpoint reachable (headers)';
      else if (resp.status === 404) hint = 'endpoint exists? got 404 (path may be wrong)';
      else if (resp.status === 405) hint = 'method not allowed (try POST here) -> path likely correct';
      else if (resp.status >= 200 && resp.status < 300) hint = 'OK';
      else hint = 'unexpected';
      results.push({ mode: 'headers', url, status: resp.status, hint, sample: typeof resp.data === 'string' ? resp.data.slice(0, 200) : JSON.stringify(resp.data).slice(0, 200) });
    } catch (err) {
      results.push({ mode: 'headers', url, error: err.message, code: err.code });
    }
  }

  // Probe with HTTP Basic auth (apiKey:apiSecret)
  if (apiKey && apiSecret) {
    for (const url of candidates) {
      try {
        const resp = await axios.get(url, {
          headers: { ...(hostHeader ? { 'Host': hostHeader } : {}) },
          auth: { username: apiKey, password: apiSecret },
          httpsAgent,
          timeout: 15000,
          validateStatus: () => true
        });
        let hint;
        if (resp.status === 401 || resp.status === 403) hint = 'auth likely invalid but endpoint reachable (basic)';
        else if (resp.status === 404) hint = 'endpoint exists? got 404 (path may be wrong)';
        else if (resp.status === 405) hint = 'method not allowed (try POST here) -> path likely correct';
        else if (resp.status >= 200 && resp.status < 300) hint = 'OK';
        else hint = 'unexpected';
        results.push({ mode: 'basic', url, status: resp.status, hint, sample: typeof resp.data === 'string' ? resp.data.slice(0, 200) : JSON.stringify(resp.data).slice(0, 200) });
      } catch (err) {
        results.push({ mode: 'basic', url, error: err.message, code: err.code });
      }
    }

    // POST with empty body to the most likely create-user endpoint. This should be safe (validation should fail if auth accepted).
    const postUrl = joinUrl(base, '/index.php/api/user');
    try {
      const respPostHeaders = await axios.post(postUrl, {}, {
        headers,
        httpsAgent,
        timeout: 15000,
        validateStatus: () => true
      });
      results.push({ mode: 'headers-post-empty', url: postUrl, status: respPostHeaders.status, sample: typeof respPostHeaders.data === 'string' ? respPostHeaders.data.slice(0, 200) : JSON.stringify(respPostHeaders.data).slice(0, 200) });
    } catch (err) {
      results.push({ mode: 'headers-post-empty', url: postUrl, error: err.message, code: err.code });
    }
    try {
      const respPostBasic = await axios.post(postUrl, {}, {
        headers: { ...(hostHeader ? { 'Host': hostHeader } : {}) },
        auth: { username: apiKey, password: apiSecret },
        httpsAgent,
        timeout: 15000,
        validateStatus: () => true
      });
      results.push({ mode: 'basic-post-empty', url: postUrl, status: respPostBasic.status, sample: typeof respPostBasic.data === 'string' ? respPostBasic.data.slice(0, 200) : JSON.stringify(respPostBasic.data).slice(0, 200) });
    } catch (err) {
      results.push({ mode: 'basic-post-empty', url: postUrl, error: err.message, code: err.code });
    }
  }

  const safe = {
    configuredBase: base,
    configuredPath,
    tried: Array.from(candidates),
    hasApiKey: Boolean(apiKey),
    hasApiSecret: Boolean(apiSecret),
    tls: { insecure: tlsInsecure, servername: tlsServername || null },
    hostHeader: hostHeader || null,
    results
  };

  console.log(JSON.stringify(safe, null, 2));
})();

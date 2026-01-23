'use strict';

const axios = require('axios');

function getTelecomCenterConfig() {
  const baseUrl = String(process.env.TELECOM_CENTER_BASE_URL || '').trim().replace(/\/$/, '');
  const username = String(process.env.TELECOM_CENTER_USERNAME || '').trim();
  const password = String(process.env.TELECOM_CENTER_PASSWORD || '').trim();

  if (!baseUrl) throw new Error('TELECOM_CENTER_BASE_URL not configured');
  if (!username || !password) throw new Error('TELECOM_CENTER_USERNAME/TELECOM_CENTER_PASSWORD not configured');

  return { baseUrl, username, password };
}

function tcOperatorBaseUrl() {
  const { baseUrl } = getTelecomCenterConfig();
  return `${baseUrl}/api/rest/public/operator`;
}

function normalizeTcError(resp) {
  try {
    const status = resp?.status;
    const data = resp?.data;

    // JSON:API errors
    const first = Array.isArray(data?.errors) ? data.errors[0] : null;
    if (first && (first.detail || first.title)) {
      return {
        status,
        message: String(first.detail || first.title),
        error: first,
        data
      };
    }

    if (data && typeof data === 'object') {
      if (data.message) return { status, message: String(data.message), data };
      if (data.error) return { status, message: String(data.error), data };
    }

    if (typeof data === 'string' && data.trim()) {
      return { status, message: data.trim(), data };
    }

    return { status, message: `telecom.center API error (${status || 'unknown'})`, data };
  } catch (e) {
    return { status: resp?.status, message: 'telecom.center API error', data: resp?.data };
  }
}

async function telecomCenterApiCall({ method, path, params, body, timeoutMs = 30000 }) {
  const { username, password } = getTelecomCenterConfig();
  const urlBase = tcOperatorBaseUrl();
  const rel = String(path || '').trim();
  const url = rel.startsWith('http') ? rel : `${urlBase}${rel.startsWith('/') ? '' : '/'}${rel}`;

  const resp = await axios.request({
    method,
    url,
    params,
    data: body,
    timeout: timeoutMs,
    auth: { username, password },
    headers: {
      'Content-Type': 'application/vnd.api+json',
      'Accept': 'application/vnd.api+json'
    },
    validateStatus: () => true
  });

  if (resp.status >= 200 && resp.status < 300) return resp.data;

  const err = normalizeTcError(resp);
  const e = new Error(err.message);
  e.status = err.status;
  e.data = err.data;
  e.error = err.error;
  throw e;
}

module.exports = {
  telecomCenterApiCall
};

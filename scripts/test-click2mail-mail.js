/*
  Test Click2Mail physical mail integration.

  Usage:
    node scripts/test-click2mail-mail.js

  By default this performs a cost estimate only (no batch submit).

  To actually submit a batch (may incur cost / send mail), set:
    TEST_MAIL_SUBMIT=1

  Required env:
    CLICK2MAIL_USERNAME
    CLICK2MAIL_PASSWORD

  Optional env for submission:
    TEST_MAIL_FROM_ADDRESS1, TEST_MAIL_FROM_CITY, TEST_MAIL_FROM_STATE, TEST_MAIL_FROM_POSTAL_CODE
    TEST_MAIL_TO_ADDRESS1, TEST_MAIL_TO_CITY, TEST_MAIL_TO_STATE, TEST_MAIL_TO_POSTAL_CODE
    TEST_MAIL_BODY
*/

const fs = require('fs');
const path = require('path');

const envLocalPath = path.join(__dirname, '..', '.env.local');
if (fs.existsSync(envLocalPath)) {
  require('dotenv').config({ path: envLocalPath });
  console.log('Loaded environment from .env.local');
} else {
  require('dotenv').config();
}

const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');
const PDFDocument = require('pdfkit');

const username = String(process.env.CLICK2MAIL_USERNAME || '').trim();
const password = String(process.env.CLICK2MAIL_PASSWORD || '').trim();

const restBase = String(process.env.CLICK2MAIL_REST_BASE_URL || 'https://stage-rest.click2mail.com').trim().replace(/\/+$/, '');
const batchBase = String(process.env.CLICK2MAIL_BATCH_BASE_URL || 'https://stage-batch.click2mail.com').trim().replace(/\/+$/, '');

const appSignature = String(process.env.CLICK2MAIL_APP_SIGNATURE || 'TalkUSA').trim() || 'TalkUSA';

// Default product options (match server.js defaults)
const documentClass = String(process.env.CLICK2MAIL_DEFAULT_DOCUMENT_CLASS || 'Priority Mail Letter 8.5 x 11').trim();
const layout = String(process.env.CLICK2MAIL_DEFAULT_LAYOUT || 'Address on Separate Page').trim();
const productionTime = String(process.env.CLICK2MAIL_DEFAULT_PRODUCTION_TIME || 'Same Day').trim();
const envelope = String(process.env.CLICK2MAIL_DEFAULT_ENVELOPE || 'Flat Rate USPS Priority Mail').trim();
const color = String(process.env.CLICK2MAIL_DEFAULT_COLOR || 'Black and White').trim();
const paperType = String(process.env.CLICK2MAIL_DEFAULT_PAPER_TYPE || 'White 24#').trim();
const printOption = String(process.env.CLICK2MAIL_DEFAULT_PRINT_OPTION || 'Printing both sides').trim();
const mailClass = String(process.env.CLICK2MAIL_DEFAULT_MAIL_CLASS || 'Priority Mail with Delivery Confirmation').trim();

const submit = ['1', 'true', 'yes', 'on'].includes(String(process.env.TEST_MAIL_SUBMIT || '').trim().toLowerCase());

function xmlEscape(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function parseXml(xmlText) {
  try {
    const s = String(xmlText || '').trim();
    if (!s) return null;
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '',
      removeNSPrefix: true,
      trimValues: true,
      parseTagValue: true,
      parseAttributeValue: false,
    });
    return parser.parse(s);
  } catch {
    return null;
  }
}

function pickFirst(obj, paths) {
  for (const p of paths) {
    try {
      const v = p.split('.').reduce((acc, k) => (acc && acc[k] != null ? acc[k] : undefined), obj);
      if (v != null) return v;
    } catch {}
  }
  return undefined;
}

function estimatePdfPageCount(pdfBuffer) {
  try {
    if (!pdfBuffer || !Buffer.isBuffer(pdfBuffer)) return 0;
    const s = pdfBuffer.toString('latin1');
    const m = s.match(/\/Type\s*\/Page\b/g);
    return m ? m.length : 0;
  } catch {
    return 0;
  }
}

async function click2mailGetCostEstimate({ numberOfPages = 1 }) {
  const client = axios.create({
    baseURL: restBase,
    auth: { username, password },
    timeout: 30000,
    transformResponse: [(d) => d],
  });

  const params = {
    documentClass,
    layout,
    productionTime,
    envelope,
    color,
    paperType,
    printOption,
    mailClass,
    quantity: '1',
    nonStandardQuantity: '0',
    internationalQuantity: '0',
    numberOfPages: String(Math.max(1, parseInt(String(numberOfPages || 1), 10) || 1)),
    paymentType: 'User Credit',
  };

  const resp = await client.get('/molpro/costEstimate', {
    params,
    headers: { Accept: 'application/xml' },
  });

  return { status: resp.status, raw: resp.data, parsed: parseXml(resp.data) };
}

async function buildPdfBuffer({ subject, body, includeBlankAddressPage }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'LETTER', margin: 72 });
    const chunks = [];

    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // Match server.js behavior: for "Address on Separate Page", generate a blank first page.
    if (includeBlankAddressPage) {
      doc.font('Helvetica').fontSize(1).fillColor('white').text(' ', 0, 0);
      doc.fillColor('black');
      doc.addPage();
    }

    const title = String(subject || 'Test Letter').trim();
    const text = String(body || 'Hello from Click2Mail test script.').trim();

    if (title) {
      doc.font('Helvetica-Bold').fontSize(14).text(title, { align: 'left' });
      doc.moveDown(0.75);
    }
    doc.font('Helvetica').fontSize(11).text(text, { align: 'left', lineGap: 4 });

    doc.end();
  });
}

async function click2mailBatchCreate() {
  const client = axios.create({
    baseURL: batchBase,
    auth: { username, password },
    timeout: 30000,
    transformResponse: [(d) => d],
  });
  const resp = await client.post('/v1/batches', null, { headers: { Accept: 'application/xml' } });
  const parsed = parseXml(resp.data);
  const batchId = String(pickFirst(parsed, ['batchjob.id', 'batchJob.id', 'batchjob.batchId', 'batchjob.id']) || '').trim();
  return { status: resp.status, raw: resp.data, parsed, batchId };
}

async function click2mailBatchUploadPdf(batchId, pdfBuffer, { filename }) {
  const client = axios.create({
    baseURL: batchBase,
    auth: { username, password },
    timeout: 30000,
    transformResponse: [(d) => d],
  });
  const resp = await client.put(`/v1/batches/${encodeURIComponent(String(batchId))}`, pdfBuffer, {
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${String(filename || 'document.pdf').replace(/\"/g, '')}"`,
    },
  });
  return { status: resp.status };
}

async function click2mailBatchUploadXml(batchId, xmlText, { filename }) {
  const client = axios.create({
    baseURL: batchBase,
    auth: { username, password },
    timeout: 30000,
    transformResponse: [(d) => d],
  });
  const resp = await client.put(`/v1/batches/${encodeURIComponent(String(batchId))}`, xmlText, {
    headers: {
      'Content-Type': 'application/xml',
      Accept: 'application/xml',
      'Content-Disposition': `attachment; filename="${String(filename || 'batch.xml').replace(/\"/g, '')}"`,
    },
  });
  return { status: resp.status, raw: resp.data };
}

async function click2mailBatchSubmit(batchId) {
  const client = axios.create({
    baseURL: batchBase,
    auth: { username, password },
    timeout: 30000,
    transformResponse: [(d) => d],
  });
  const resp = await client.post(`/v1/batches/${encodeURIComponent(String(batchId))}`, null, {
    headers: { Accept: 'application/xml' },
  });
  return { status: resp.status, raw: resp.data, parsed: parseXml(resp.data) };
}

function requireEnv(name) {
  const v = String(process.env[name] || '').trim();
  if (!v) throw new Error(`Missing required env: ${name}`);
  return v;
}

async function main() {
  const missing = [];
  if (!username) missing.push('CLICK2MAIL_USERNAME');
  if (!password) missing.push('CLICK2MAIL_PASSWORD');

  if (missing.length) {
    console.error('Cannot test Click2Mail: missing env vars:', missing.join(', '));
    process.exitCode = 2;
    return;
  }

  console.log('Click2Mail config:', {
    restBase,
    batchBase,
    documentClass,
    layout,
    productionTime,
    envelope,
    color,
    paperType,
    printOption,
    mailClass,
    submit,
  });

  // 1) Cost estimate (this is where "Invalid product options" typically shows up)
  const includeBlankAddressPage = /separate\s*page/i.test(layout || '');
  const estPages = includeBlankAddressPage ? 2 : 1;
  try {
    const est = await click2mailGetCostEstimate({ numberOfPages: estPages });
    const amount = pickFirst(est.parsed, [
      'costEstimate.grandTotal',
      'costestimate.grandtotal',
      'grandTotal',
      'grandtotal',
      'total',
    ]);
    console.log('Cost estimate OK:', { status: est.status, amount: amount != null ? String(amount) : '(see raw)' });
  } catch (e) {
    const httpStatus = e?.response?.status;
    const body = (typeof e?.response?.data === 'string') ? e.response.data : '';
    const parsed = parseXml(body);
    const msg = String(pickFirst(parsed, ['error.description', 'errors.error.description', 'description', 'message']) || e?.message || 'Cost estimate failed');
    console.error('Cost estimate FAILED:', { httpStatus: httpStatus || null, message: msg });
    process.exitCode = 1;
    return;
  }

  if (!submit) {
    console.log('Dry-run complete (set TEST_MAIL_SUBMIT=1 to create+submit a batch).');
    return;
  }

  // 2) Submit a real batch (may incur cost / send mail)
  const from = {
    name: String(process.env.TEST_MAIL_FROM_NAME || '').trim(),
    organization: String(process.env.TEST_MAIL_FROM_ORGANIZATION || '').trim(),
    address1: requireEnv('TEST_MAIL_FROM_ADDRESS1'),
    address2: String(process.env.TEST_MAIL_FROM_ADDRESS2 || '').trim(),
    city: requireEnv('TEST_MAIL_FROM_CITY'),
    state: requireEnv('TEST_MAIL_FROM_STATE'),
    postalCode: requireEnv('TEST_MAIL_FROM_POSTAL_CODE'),
    country: String(process.env.TEST_MAIL_FROM_COUNTRY || 'US').trim() || 'US',
  };

  const to = {
    name: String(process.env.TEST_MAIL_TO_NAME || '').trim(),
    organization: String(process.env.TEST_MAIL_TO_ORGANIZATION || '').trim(),
    address1: requireEnv('TEST_MAIL_TO_ADDRESS1'),
    address2: String(process.env.TEST_MAIL_TO_ADDRESS2 || '').trim(),
    address3: String(process.env.TEST_MAIL_TO_ADDRESS3 || '').trim(),
    city: requireEnv('TEST_MAIL_TO_CITY'),
    state: requireEnv('TEST_MAIL_TO_STATE'),
    postalCode: requireEnv('TEST_MAIL_TO_POSTAL_CODE'),
    country: String(process.env.TEST_MAIL_TO_COUNTRY || 'US').trim() || 'US',
  };

  // Click2Mail batch XSD expects <name> as the first element inside returnAddress/address.
  // Provide a safe fallback so missing TEST_MAIL_*_NAME doesn't break XML validation.
  const fromName = (from.name || from.organization || 'Sender').trim();
  const toName = (to.name || to.organization || 'Recipient').trim();
  const fromOrg = String(from.organization || '').trim();
  const toOrg = String(to.organization || '').trim();

  const subject = String(process.env.TEST_MAIL_SUBJECT || 'Test Letter').trim();
  const body = requireEnv('TEST_MAIL_BODY');

  const pdf = await buildPdfBuffer({ subject, body, includeBlankAddressPage });
  const pageCount = Math.max(1, estimatePdfPageCount(pdf) || 0);

  const pdfFilename = `test-mail-${Date.now()}.pdf`;
  const xmlFilename = `test-mail-${Date.now()}.xml`;

  let batch = null;
  try {
    batch = await click2mailBatchCreate();
  } catch (e) {
    e.step = 'batch_create';
    throw e;
  }
  if (!batch.batchId) throw new Error('Click2Mail batch id missing');
  console.log('Batch created:', { batchId: batch.batchId });

  try {
    await click2mailBatchUploadPdf(batch.batchId, pdf, { filename: pdfFilename });
  } catch (e) {
    e.step = 'upload_pdf';
    e.batchId = batch.batchId;
    throw e;
  }
  console.log('PDF uploaded:', { filename: pdfFilename, bytes: pdf.length, pageCount });

  const batchXml =
    `<?xml version=\"1.0\" encoding=\"UTF-8\"?>` +
    `<batch xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">` +
    `<filename>${xmlEscape(pdfFilename)}</filename>` +
    `<appSignature>${xmlEscape(appSignature)}</appSignature>` +
    `<job>` +
    `<startingPage>1</startingPage>` +
    `<endingPage>${xmlEscape(String(pageCount))}</endingPage>` +
    `<printProductionOptions>` +
    `<documentClass>${xmlEscape(documentClass)}</documentClass>` +
    `<layout>${xmlEscape(layout)}</layout>` +
    `<productionTime>${xmlEscape(productionTime)}</productionTime>` +
    `<envelope>${xmlEscape(envelope)}</envelope>` +
    `<color>${xmlEscape(color)}</color>` +
    `<paperType>${xmlEscape(paperType)}</paperType>` +
    `<printOption>${xmlEscape(printOption)}</printOption>` +
    `<mailClass>${xmlEscape(mailClass)}</mailClass>` +
    `</printProductionOptions>` +
    `<returnAddress>` +
    `<name>${xmlEscape(fromName)}</name>` +
    `<organization>${xmlEscape(fromOrg)}</organization>` +
    `<address1>${xmlEscape(from.address1)}</address1>` +
    `<address2>${from.address2 ? xmlEscape(from.address2) : ''}</address2>` +
    `<city>${xmlEscape(from.city)}</city>` +
    `<state>${xmlEscape(from.state)}</state>` +
    `<postalCode>${xmlEscape(from.postalCode)}</postalCode>` +
    `<country>${xmlEscape(from.country)}</country>` +
    `</returnAddress>` +
    `<recipients>` +
    `<address>` +
    `<name>${xmlEscape(toName)}</name>` +
    `<organization>${xmlEscape(toOrg)}</organization>` +
    `<address1>${xmlEscape(to.address1)}</address1>` +
    `<address2>${to.address2 ? xmlEscape(to.address2) : ''}</address2>` +
    `<address3>${to.address3 ? xmlEscape(to.address3) : ''}</address3>` +
    `<city>${xmlEscape(to.city)}</city>` +
    `<state>${xmlEscape(to.state)}</state>` +
    `<postalCode>${xmlEscape(to.postalCode)}</postalCode>` +
    `<country>${xmlEscape(to.country)}</country>` +
    `<c2m_uniqueid/>` +
    `</address>` +
    `</recipients>` +
    `</job>` +
    `</batch>`;

  try {
    await click2mailBatchUploadXml(batch.batchId, batchXml, { filename: xmlFilename });
  } catch (e) {
    e.step = 'upload_xml';
    e.batchId = batch.batchId;
    throw e;
  }
  console.log('XML uploaded:', { filename: xmlFilename });

  let submitted = null;
  try {
    submitted = await click2mailBatchSubmit(batch.batchId);
  } catch (e) {
    e.step = 'submit_batch';
    e.batchId = batch.batchId;
    throw e;
  }
  console.log('Batch submitted:', { status: submitted.status, batchId: batch.batchId });
}

main().catch((e) => {
  const httpStatus = e?.response?.status;
  const contentType = e?.response?.headers?.['content-type'] || null;
  const body = (typeof e?.response?.data === 'string') ? String(e.response.data) : '';
  const parsed = parseXml(body);

  const detail = String(pickFirst(parsed, [
    'error.description',
    'errors.error.description',
    'description',
    'message',
    'faultstring',
    'faultString'
  ]) || '').trim();

  const bodySnippet = body
    ? body
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 800)
    : '';

  const msg = detail || bodySnippet || String(e?.message || 'Test failed');

  console.error('Test FAILED:', {
    step: e?.step || null,
    batchId: e?.batchId || null,
    httpStatus: httpStatus || null,
    contentType,
    message: msg,
    bodySnippet: detail ? null : (bodySnippet || null)
  });
  process.exitCode = 1;
});

const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

const envPath = path.join(__dirname, '.env');

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return '';
  const raw = fs.readFileSync(filePath);
  let text = raw.toString('utf8');
  if (text.includes('\u0000')) {
    text = raw.toString('utf16le');
  }
  if (text.charCodeAt(0) === 0xFEFF) {
    text = text.slice(1);
  }
  return text;
}

dotenv.config({ path: envPath });

const envText = loadEnvFile(envPath);
if (envText) {
  envText.split(/\r?\n/).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const separatorIndex = trimmed.indexOf('=');
    if (separatorIndex === -1) return;
    const key = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim().replace(/^['"]|['"]$/g, '');
    if (!process.env[key]) {
      process.env[key] = value;
    }
  });
}
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'text/plain',
      'text/csv',
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/msword',
      'application/octet-stream'
    ];
    if (allowed.includes(file.mimetype) || /\.(txt|csv|pdf|docx|doc)$/i.test(file.originalname)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type. Please upload a text, CSV, PDF, or Word document.'));
    }
  }
});

const PORT = process.env.PORT || 4000;
const DB_FILE = path.join(__dirname, 'db.json');
const FETCH_INTERVAL = (parseInt(process.env.FETCH_INTERVAL_SECONDS) || 300) * 1000;
const DEFAULT_VT_API_KEY = 'a7f6f9dd70509548daf623f2fdee21064f1ffd9d0c6802539dcea3782ca29057';
process.env.VT_API_KEY = process.env.VT_API_KEY || DEFAULT_VT_API_KEY;
const VT_API_KEY = process.env.VT_API_KEY || '';
const VT_BASE_URL = 'https://www.virustotal.com/api/v3';

// Load or init DB
function readDB(){
  try{
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return JSON.parse(raw);
  }catch(e){
    return { items: [] };
  }
}
function writeDB(db){
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// SSE clients
const clients = [];
function sendSSE(data){
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  clients.forEach(res => res.write(msg));
}

function getFileFormat(file, mimeType) {
  const ext = (file.originalname || '').toLowerCase();
  if (ext.endsWith('.pdf') || mimeType === 'application/pdf') return 'PDF';
  if (ext.endsWith('.docx') || mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') return 'Word DOCX';
  if (ext.endsWith('.doc') || mimeType === 'application/msword') return 'Word DOC';
  if (ext.endsWith('.csv') || mimeType === 'text/csv') return 'CSV';
  return 'Text/Plain';
}

async function extractTextFromUpload(file, mimeType) {
  const buffer = file.buffer || Buffer.from('');
  if (!buffer.length) return '';

  if (mimeType === 'application/pdf') {
    const pdfData = await pdfParse(buffer);
    return pdfData.text || '';
  }

  if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
    const result = await mammoth.extractRawText({ buffer });
    return result.value || '';
  }

  if (mimeType === 'application/msword') {
    return buffer.toString('utf8');
  }

  return buffer.toString('utf8');
}

function extractIndicators(text) {
  const source = (text || '').toString();
  const seen = new Set();
  const results = [];

  const addIndicator = (value, type) => {
    const normalized = value.trim();
    if (!normalized || seen.has(`${type}:${normalized.toLowerCase()}`)) return;
    seen.add(`${type}:${normalized.toLowerCase()}`);
    results.push({ type, value: normalized });
  };

  const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/gi;
  const ipRegex = /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g;
  const domainRegex = /(?:[a-z0-9-]+\.)+[a-z]{2,}/gi;
  const urlRegex = /https?:\/\/[^\s,;]+/gi;
  const hashRegex = /\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g;

  source.matchAll(cveRegex).forEach((match) => addIndicator(match[0], 'cve'));
  source.matchAll(ipRegex).forEach((match) => addIndicator(match[0], 'ip'));
  source.matchAll(domainRegex).forEach((match) => addIndicator(match[0], 'domain'));
  source.matchAll(urlRegex).forEach((match) => addIndicator(match[0], 'url'));
  source.matchAll(hashRegex).forEach((match) => addIndicator(match[0], 'hash'));

  return results;
}

function buildSecurityScore(stats) {
  const total = Object.values(stats || {}).reduce((sum, value) => sum + Number(value || 0), 0);
  if (!total) return { securityScore: 50, riskLevel: 'unknown' };

  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const safeScore = Math.max(0, Math.min(100, Math.round(100 - ((malicious + suspicious) / total) * 100)));
  let riskLevel = 'low';
  if (safeScore < 40) riskLevel = 'high';
  else if (safeScore < 70) riskLevel = 'medium';
  return { securityScore: safeScore, riskLevel };
}

async function queryVirusTotal(indicator) {
  const encodedValue = encodeURIComponent(indicator.value);
  const apiKey = (process.env.VT_API_KEY || VT_API_KEY || '').trim();
  const headers = {
    accept: 'application/json',
    'x-apikey': apiKey,
    ...(apiKey ? {} : {})
  };

  try {
    console.log('[VT]', 'querying', indicator.value, 'with key', apiKey ? 'present' : 'missing');
    const response = await fetch(`${VT_BASE_URL}/search?query=${encodedValue}`, { method: 'GET', headers });
    const responseText = await response.text();
    if (!response.ok) {
      console.log('[VT]', 'request failed', response.status, responseText);
      return {
        indicator: indicator.value,
        type: indicator.type,
        status: 'error',
        message: `VirusTotal lookup failed with status ${response.status}`
      };
    }

    const json = JSON.parse(responseText);
    const entry = Array.isArray(json.data) ? json.data[0] : null;
    const attributes = entry && entry.attributes ? entry.attributes : {};
    const stats = attributes.last_analysis_stats || {};
    const security = buildSecurityScore(stats);

    return {
      indicator: indicator.value,
      type: indicator.type,
      status: 'ok',
      securityScore: security.securityScore,
      riskLevel: security.riskLevel,
      vtUrl: `https://www.virustotal.com/gui/search/${encodedValue}`,
      malicious: Number(stats.malicious || 0),
      suspicious: Number(stats.suspicious || 0),
      undetected: Number(stats.undetected || 0),
      harmless: Number(stats.harmless || 0),
      totalEngines: Object.values(stats).reduce((sum, value) => sum + Number(value || 0), 0)
    };
  } catch (error) {
    return {
      indicator: indicator.value,
      type: indicator.type,
      status: 'error',
      message: error.message || 'VirusTotal request failed'
    };
  }
}

// API: latest items
app.get('/api/latest', (req, res) => {
  const db = readDB();
  const items = Array.isArray(db.items) ? db.items.slice() : [];
  const sorted = items.sort((a, b) => new Date(b.published).getTime() - new Date(a.published).getTime());
  const limit = parseInt(req.query.limit, 10);
  const responseItems = Number.isInteger(limit) && limit > 0 ? sorted.slice(0, limit) : sorted;
  res.json({ count: responseItems.length, items: responseItems });
});

// API: stream (SSE)
app.get('/api/stream', (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders();
  res.write('retry: 10000\n\n');
  clients.push(res);
  req.on('close', () => {
    const idx = clients.indexOf(res);
    if(idx !== -1) clients.splice(idx, 1);
  });
});

app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Please upload a file.' });
    }

    const mimeType = req.file.mimetype || 'text/plain';
    const detectedFormat = getFileFormat(req.file, mimeType);
    const extractedText = await extractTextFromUpload(req.file, mimeType);
    const indicators = extractIndicators(extractedText).slice(0, 10);

    const vtResults = await Promise.all(indicators.map((indicator) => queryVirusTotal(indicator)));

    res.json({
      ok: true,
      fileName: req.file.originalname,
      detectedFormat,
      extractedTextPreview: extractedText.slice(0, 4000),
      indicatorsFound: indicators.length,
      indicators,
      vtResults,
      note: VT_API_KEY ? 'VirusTotal lookup completed with the configured API key.' : 'Set VT_API_KEY in your environment to enable live VirusTotal results.'
    });
  } catch (error) {
    console.error('[UPLOAD]', error);
    res.status(500).json({ error: error.message || 'Unable to process upload.' });
  }
});

// Serve static frontend
app.use('/', express.static(path.join(__dirname, 'public')));

// 1. Fetch from NVD v2.0 API
async function fetchNVD(){
  let added = 0;
  const db = readDB();
  try{
    console.log('[NVD]', 'Fetching latest CVEs...');
    const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50';
    const resp = await fetch(url, { timeout: 20000 });
    if(!resp.ok) throw new Error('NVD API error: ' + resp.status);
    const json = await resp.json();
    const results = json.vulnerabilities || [];
    results.slice(0, 15).forEach(vuln => {
      const cveId = vuln.cve && vuln.cve.id;
      if(!cveId || db.items.find(x => x.id === cveId)) return;
      
      const desc = vuln.cve.descriptions && vuln.cve.descriptions[0] ? vuln.cve.descriptions[0].value : 'CVE found';
      const cvssScore = vuln.cve.metrics && vuln.cve.metrics.cvssV31 ? vuln.cve.metrics.cvssV31[0].cvssData.baseSeverity : 'MEDIUM';
      
      const item = {
        id: cveId,
        published: vuln.cve.published || new Date().toISOString(),
        description: desc.substring(0, 200),
        severity: cvssScore,
        type: 'CVE - NVD',
        source: 'NVD'
      };
      db.items.push(item);
      added++;
      sendSSE({ type: 'new', item });
    });
    if(added > 0) writeDB(db);
    console.log('[NVD]', 'added', added);
  }catch(e){
    console.log('[NVD]', 'error:', e.message);
  }
  return added;
}

// 2. Fetch from CISA KEV (GitHub mirror - avoids 403 blocks)
async function fetchCISAKEV(){
  let added = 0;
  const db = readDB();
  try{
    console.log('[CISA-KEV]', 'Fetching known exploited vulnerabilities...');
    const url = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';
    const resp = await fetch(url, { timeout: 20000 });
    if(!resp.ok) throw new Error('CISA KEV error: ' + resp.status);
    const json = await resp.json();
    const results = json.vulnerabilities || [];
    results.slice(0, 10).forEach(vuln => {
      const id = 'CISA-' + vuln.cveID;
      if(db.items.find(x => x.id === id)) return;
      
      const item = {
        id,
        published: new Date(vuln.dateAdded).toISOString(),
        description: vuln.shortDescription || 'Known exploited vulnerability',
        severity: vuln.cvssv3_baseSeverity || 'HIGH',
        type: 'Exploited CVE - CISA KEV',
        source: 'CISA'
      };
      db.items.push(item);
      added++;
      sendSSE({ type: 'new', item });
    });
    if(added > 0) writeDB(db);
    console.log('[CISA-KEV]', 'added', added);
  }catch(e){
    console.log('[CISA-KEV]', 'error:', e.message);
  }
  return added;
}

// 3. Fetch from CIRCL cve-search (no auth needed)
async function fetchCIRCL(){
  let added = 0;
  const db = readDB();
  try{
    console.log('[CIRCL]', 'Fetching aggregated CVE data...');
    const url = 'https://cve.circl.lu/api/last?limit=50';
    const resp = await fetch(url, { timeout: 20000 });
    if(!resp.ok) throw new Error('CIRCL error: ' + resp.status);
    const results = await resp.json();
    
    (Array.isArray(results) ? results : results.data || []).slice(0, 10).forEach(cve => {
      const id = cve.id;
      if(!id || db.items.find(x => x.id === id)) return;
      
      const item = {
        id,
        published: cve.modified || new Date().toISOString(),
        description: cve.summary || 'CVE data aggregated',
        severity: cve.cvssv3 && cve.cvssv3.base_score >= 7.0 ? (cve.cvssv3.base_score >= 9 ? 'CRITICAL' : 'HIGH') : 'MEDIUM',
        type: 'CVE - CIRCL',
        source: 'CIRCL'
      };
      db.items.push(item);
      added++;
      sendSSE({ type: 'new', item });
    });
    if(added > 0) writeDB(db);
    console.log('[CIRCL]', 'added', added);
  }catch(e){
    console.log('[CIRCL]', 'error:', e.message);
  }
  return added;
}

// 4. Fetch from AlienVault OTX
async function fetchOTX(){
  if(!process.env.OTX_API_KEY) {
    console.log('[OTX]', 'skipped (no API key)');
    return 0;
  }
  let added = 0;
  const db = readDB();
  try{
    console.log('[OTX]', 'Fetching threat pulses...');
    const url = 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=30';
    const resp = await fetch(url, { headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY }, timeout: 15000 });
    if(!resp.ok) throw new Error('OTX API error: ' + resp.status);
    const json = await resp.json();
    const results = json.results || [];
    results.slice(0, 10).forEach(pulse => {
      const id = 'OTX-' + pulse.id;
      if(db.items.find(x => x.id === id)) return;
      
      const item = {
        id,
        published: pulse.created || new Date().toISOString(),
        description: (pulse.name || 'Threat pulse') + (pulse.description ? ' - ' + pulse.description.substring(0, 100) : ''),
        severity: pulse.severity && pulse.severity.toUpperCase() === 'HIGH' ? 'HIGH' : 'MEDIUM',
        type: 'Threat Pulse - OTX',
        source: 'OTX'
      };
      db.items.push(item);
      added++;
      sendSSE({ type: 'new', item });
    });
    if(added > 0) writeDB(db);
    console.log('[OTX]', 'added', added);
  }catch(e){
    console.log('[OTX]', 'error:', e.message);
  }
  return added;
}

// 6. Fetch from URLhaus (Malicious URLs - no auth needed)
async function fetchURLhaus(){
  let added = 0;
  const db = readDB();
  try{
    console.log('[URLhaus]', 'Fetching malicious URLs...');
    const url = 'https://urlhaus.abuse.ch/feeds/json_recent_100/';
    const resp = await fetch(url, { timeout: 20000 });
    if(!resp.ok) throw new Error('URLhaus error: ' + resp.status);
    const json = await resp.json();
    const results = json.urls || [];
    
    results.slice(0, 15).forEach(item => {
      const id = 'URLHAUS-' + item.id;
      if(db.items.find(x => x.id === id)) return;
      
      const threat = {
        id,
        published: item.date_submitted || new Date().toISOString(),
        description: 'Malicious URL: ' + (item.url || 'Unknown').substring(0, 100),
        severity: item.threat === 'phishing' ? 'HIGH' : 'MEDIUM',
        type: 'Malicious URL - URLhaus',
        source: 'URLhaus',
        indicatorType: 'URL',
        url: item.url,
        threat: item.threat
      };
      db.items.push(threat);
      added++;
      sendSSE({ type: 'new', item: threat });
    });
    if(added > 0) writeDB(db);
    console.log('[URLhaus]', 'added', added);
  }catch(e){
    console.log('[URLhaus]', 'error:', e.message);
  }
  return added;
}

// 7. Fetch from MalwareBazaar (Malware Hashes - no auth needed)
async function fetchMalwareBazaar(){
  let added = 0;
  const db = readDB();
  try{
    console.log('[MalwareBazaar]', 'Fetching recent malware submissions...');
    const url = 'https://mb-api.abuse.ch/api/v1/query/get_recent/';
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'query=get_recent&limit=50',
      timeout: 20000
    });
    if(!resp.ok) throw new Error('MalwareBazaar error: ' + resp.status);
    const json = await resp.json();
    const results = json.data || [];
    
    (Array.isArray(results) ? results : Object.values(results)).slice(0, 12).forEach(item => {
      const id = 'MBZR-' + (item.sha256 || item.md5 || Math.random()).toString().substring(0, 16);
      if(db.items.find(x => x.id === id)) return;
      
      const threat = {
        id,
        published: item.first_submission_time || new Date().toISOString(),
        description: 'Malware: ' + (item.malware_family || 'Unknown family') + ' | Hash: ' + (item.sha256 || item.md5 || 'N/A').substring(0, 16),
        severity: 'CRITICAL',
        type: 'Malware Hash - MalwareBazaar',
        source: 'MalwareBazaar',
        indicatorType: 'HASH',
        hash: item.sha256 || item.md5,
        family: item.malware_family
      };
      db.items.push(threat);
      added++;
      sendSSE({ type: 'new', item: threat });
    });
    if(added > 0) writeDB(db);
    console.log('[MalwareBazaar]', 'added', added);
  }catch(e){
    console.log('[MalwareBazaar]', 'error:', e.message);
  }
  return added;
}

// 8. Fetch from OpenPhish (Phishing URLs - no auth needed)
async function fetchOpenPhish(){
  let added = 0;
  const db = readDB();
  try{
    console.log('[OpenPhish]', 'Fetching phishing URLs...');
    const url = 'https://openphish.com/feed.txt';
    const resp = await fetch(url, { timeout: 20000 });
    if(!resp.ok) throw new Error('OpenPhish error: ' + resp.status);
    const text = await resp.text();
    const urls = text.split('\n').filter(u => u.trim()).slice(0, 20);
    
    urls.forEach((phishUrl, idx) => {
      const id = 'OPENPHISH-' + idx;
      if(db.items.find(x => x.id === id)) return;
      
      const threat = {
        id,
        published: new Date().toISOString(),
        description: 'Phishing URL: ' + (phishUrl.substring(0, 80) || 'Unknown'),
        severity: 'HIGH',
        type: 'Phishing URL - OpenPhish',
        source: 'OpenPhish',
        indicatorType: 'PHISHING_URL',
        url: phishUrl
      };
      db.items.push(threat);
      added++;
      sendSSE({ type: 'new', item: threat });
    });
    if(added > 0) writeDB(db);
    console.log('[OpenPhish]', 'added', added);
  }catch(e){
    console.log('[OpenPhish]', 'error:', e.message);
  }
  return added;
}

// 9. Fetch from urlscan.io (URL Scanning Results - no auth for recent)
async function fetchUrlscan(){
  let added = 0;
  const db = readDB();
  try{
    console.log('[urlscan.io]', 'Fetching recent URL scan results...');
    const url = 'https://urlscan.io/api/v1/search/?q=date:%3E2024-01-01&size=50';
    const resp = await fetch(url, { timeout: 20000 });
    if(!resp.ok) throw new Error('urlscan.io error: ' + resp.status);
    const json = await resp.json();
    const results = json.results || [];
    
    results.slice(0, 12).forEach(item => {
      const id = 'URLSCAN-' + item.task.uuid;
      if(db.items.find(x => x.id === id)) return;
      
      const threat = {
        id,
        published: item.task.time || new Date().toISOString(),
        description: 'Scanned URL: ' + (item.page.domain || item.task.url).substring(0, 80),
        severity: item.verdicts && item.verdicts.overall && item.verdicts.overall.malicious ? 'HIGH' : 'MEDIUM',
        type: 'URL Scan - urlscan.io',
        source: 'urlscan.io',
        indicatorType: 'URL_SCAN',
        url: item.task.url,
        malicious: item.verdicts && item.verdicts.overall && item.verdicts.overall.malicious
      };
      db.items.push(threat);
      added++;
      sendSSE({ type: 'new', item: threat });
    });
    if(added > 0) writeDB(db);
    console.log('[urlscan.io]', 'added', added);
  }catch(e){
    console.log('[urlscan.io]', 'error:', e.message);
  }
  return added;
}

// 10. Fetch from AbuseIPDB (Malicious IPs - API key optional)
async function fetchAbuseIPDB(){
  if(!process.env.ABUSEIPDB_API_KEY) {
    console.log('[AbuseIPDB]', 'skipped (no API key)');
    return 0;
  }
  let added = 0;
  const db = readDB();
  try{
    console.log('[AbuseIPDB]', 'Fetching malicious IPs...');
    const url = 'https://api.abuseipdb.com/api/v2/blacklist?limit=100&plaintext';
    const resp = await fetch(url, {
      headers: { 'Key': process.env.ABUSEIPDB_API_KEY },
      timeout: 20000
    });
    if(!resp.ok) throw new Error('AbuseIPDB error: ' + resp.status);
    const text = await resp.text();
    const ips = text.split('\n').filter(ip => ip.trim() && !ip.startsWith('#')).slice(0, 15);
    
    ips.forEach((ip, idx) => {
      const id = 'ABUSEIPDB-' + ip;
      if(db.items.find(x => x.id === id)) return;
      
      const threat = {
        id,
        published: new Date().toISOString(),
        description: 'Malicious IP Address: ' + ip,
        severity: 'HIGH',
        type: 'Malicious IP - AbuseIPDB',
        source: 'AbuseIPDB',
        indicatorType: 'IP',
        ip: ip
      };
      db.items.push(threat);
      added++;
      sendSSE({ type: 'new', item: threat });
    });
    if(added > 0) writeDB(db);
    console.log('[AbuseIPDB]', 'added', added);
  }catch(e){
    console.log('[AbuseIPDB]', 'error:', e.message);
  }
  return added;
}

// Aggregate all sources (10 different threat intel feeds)
async function fetchLatest(){
  let added = 0;

  // VULNERABILITY INTELLIGENCE
  // 1. NVD - National Vulnerability Database
  added += await fetchNVD();

  // 2. CISA KEV - Known Exploited Vulnerabilities
  added += await fetchCISAKEV();

  // 3. CIRCL cve-search - Aggregated CVE data
  added += await fetchCIRCL();

  // 4. AlienVault OTX - Threat community intel
  added += await fetchOTX();

  // IOC ENRICHMENT & MALWARE/PHISHING FEEDS
  // 6. URLhaus - Malicious URLs
  added += await fetchURLhaus();

  // 7. MalwareBazaar - Malware hashes & families
  added += await fetchMalwareBazaar();

  // 8. OpenPhish - Phishing URLs
  added += await fetchOpenPhish();

  // 9. urlscan.io - URL scanning intelligence
  added += await fetchUrlscan();

  // 10. AbuseIPDB - Malicious IP addresses
  added += await fetchAbuseIPDB();

  const db = readDB();
  console.log('[' + new Date().toISOString() + '] fetchLatest: total added', added, '| db size:', db.items.length);
}

// Start periodic fetch
fetchLatest();
setInterval(fetchLatest, FETCH_INTERVAL);

if (require.main === module) {
  app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
}

module.exports = { app, extractIndicators };

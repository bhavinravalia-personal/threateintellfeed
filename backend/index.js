require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const DB_FILE = path.join(__dirname, 'db.json');
const FETCH_INTERVAL = (parseInt(process.env.FETCH_INTERVAL_SECONDS) || 300) * 1000;

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

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

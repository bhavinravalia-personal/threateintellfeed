const tableBody = document.querySelector('#feedTable tbody');
const searchBox = document.getElementById('searchBox');
const severityFilter = document.getElementById('severityFilter');
const sourceFilter = document.getElementById('sourceFilter');
const indicatorTypeFilter = document.getElementById('indicatorTypeFilter');
const uploadForm = document.getElementById('uploadForm');
const uploadInput = document.getElementById('uploadInput');
const uploadStatus = document.getElementById('uploadStatus');
const uploadResults = document.getElementById('uploadResults');
var items = [];
let currentModalItem = null;

function escapeHtml(s){
  if(!s) return '';
  return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
}

function getSeverityColor(severity) {
  if (!severity) return 'low';
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MEDIUM') return 'medium';
  return 'low';
}

function calculateRiskScore(item) {
  const severityWeights = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25, UNKNOWN: 10 };
  const typeWeights = { 
    'CVE - NVD': 35,
    'Exploited CVE - CISA KEV': 50,
    'CVE - CIRCL': 40,
    'Threat Pulse - OTX': 30,
    'Malicious URL - URLhaus': 60,
    'Malware Hash - MalwareBazaar': 80,
    'Phishing URL - OpenPhish': 65,
    'URL Scan - urlscan.io': 55,
    'Malicious IP - AbuseIPDB': 70
  };
  const severity = (item.severity || 'UNKNOWN').toUpperCase();
  const type = item.type || 'Unknown';
  return (severityWeights[severity] || 10) + (typeWeights[type] || 20);
}

function getIndicatorType(item) {
  const itemType = (item.type || '').toUpperCase();
  const itemSource = (item.source || '').toUpperCase();
  if (item.indicatorType && item.indicatorType.toUpperCase() !== 'UNKNOWN') return item.indicatorType;
  if (itemType.includes('CVE') || itemSource === 'NVD' || itemSource === 'CISA' || itemSource === 'CIRCL') return 'CVE';
  if (itemType.includes('MALICIOUS IP') || /\bIP\b/.test(itemType) || itemSource === 'ABUSEIPDB') return 'IP';
  if (itemType.includes('URL_SCAN') || itemSource === 'URLSCAN.IO') return 'URL_SCAN';
  if (itemType.includes('PHISHING') || itemSource === 'OPENPHISH') return 'PHISHING_URL';
  if (itemType.includes('HASH') || itemSource === 'MALWAREBAZAAR') return 'HASH';
  if (itemType.includes('URL') || itemSource === 'URLHAUS') return 'URL';
  return 'UNKNOWN';
}

function normalizeItem(it) {
  const item = { ...it };
  const type = (item.type || '').toString();
  const upperType = type.toUpperCase();
  const id = (item.id || '').toString().toUpperCase();
  const desc = (item.description || '').toString().toUpperCase();

  if (!item.source) {
    if (upperType.includes('OTX') || id.startsWith('OTX-')) item.source = 'OTX';
    else if (upperType.includes('URLHAUS') || id.startsWith('URLHAUS-')) item.source = 'URLhaus';
    else if (upperType.includes('MALWAREBAZAAR') || id.startsWith('MBZR-')) item.source = 'MalwareBazaar';
    else if (upperType.includes('OPENPHISH') || id.startsWith('OPENPHISH-') || desc.includes('OPENPHISH')) item.source = 'OpenPhish';
    else if (upperType.includes('URLSCAN') || id.startsWith('URLSCAN-')) item.source = 'urlscan.io';
    else if (upperType.includes('MALICIOUS IP') || id.startsWith('ABUSE-') || desc.includes('ABUSEIPDB')) item.source = 'AbuseIPDB';
    else if (upperType.includes('CISA')) item.source = 'CISA';
    else if (upperType.includes('CIRCL')) item.source = 'CIRCL';
    else if (upperType.includes('NVD') || id.startsWith('CVE-')) item.source = 'NVD';
  }

  item.indicatorType = getIndicatorType(item);
  return item;
}

function normalizeItems(rawItems) {
  return rawItems.map(normalizeItem);
}

window.normalizeItems = normalizeItems;
window.normalizeItem = normalizeItem;

// Get source links based on indicator type and source
function getSourceLinks(item) {
  // Extract CVE ID from various formats
  const cveMatch = item.id.match(/CVE-\d{4}-\d{4,}/i);
  const cveId = cveMatch ? cveMatch[0] : item.id;
  const itemType = (item.type || '').toUpperCase();
  const itemSource = (item.source || '').toUpperCase();
  
  const links = [];
  
  // CVE Sources
  if (itemType.includes('NVD') || itemSource === 'NVD') {
    links.push({ 
      name: 'NVD (NIST)', 
      url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
      isPrimary: true 
    });
  }
  if (itemType.includes('CISA') || itemSource === 'CISA') {
    links.push({ 
      name: 'CISA KEV Catalog', 
      url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
      isPrimary: true 
    });
  }
  if (itemType.includes('CIRCL') || itemSource === 'CIRCL') {
    links.push({ 
      name: 'CIRCL CVE Search', 
      url: `https://cve.circl.lu/search/${cveId}`,
      isPrimary: true 
    });
  }
  if (itemType.includes('OTX') || itemSource === 'OTX') {
    links.push({ 
      name: 'OTX Pulses', 
      url: `https://otx.alienvault.com/browse/vulnerabilities`,
      isPrimary: true 
    });
  }
  
  // IOC Sources
  if (itemType.includes('URLHAUS') || itemSource === 'URLHAUS') {
    links.push({ 
      name: 'URLhaus Database', 
      url: `https://urlhaus.abuse.ch/`,
      isPrimary: true 
    });
  }
  if (itemType.includes('MALWAREBAZAAR') || itemSource === 'MALWAREBAZAAR') {
    links.push({ 
      name: 'MalwareBazaar', 
      url: `https://mb-api.abuse.ch/`,
      isPrimary: true 
    });
  }
  if (itemType.includes('OPENPHISH') || itemSource === 'OPENPHISH') {
    links.push({ 
      name: 'OpenPhish Feed', 
      url: `https://openphish.com/`,
      isPrimary: true 
    });
  }
  if (itemType.includes('URLSCAN') || itemSource === 'URLSCAN' || itemSource === 'URLSCAN.IO') {
    links.push({ 
      name: 'urlscan.io Scans', 
      url: `https://urlscan.io/`,
      isPrimary: true 
    });
  }
  if (itemType.includes('ABUSEIPDB') || itemType.includes('MALICIOUS IP') || itemSource === 'ABUSEIPDB') {
    links.push({ 
      name: 'AbuseIPDB Check', 
      url: `https://www.abuseipdb.com/`,
      isPrimary: true 
    });
  }
  
  // Add Google search as fallback
  if (!links.length) {
    links.push({ 
      name: 'Google Search', 
      url: `https://www.google.com/search?q=${item.id}`,
      isPrimary: false 
    });
  }
  
  return links;
}

// Modal functions
function openCveModal(item) {
  currentModalItem = item;
  const modal = document.getElementById('cveModal');
  
  document.getElementById('modalCveId').textContent = item.id;
  document.getElementById('modalId').textContent = item.id;
  document.getElementById('modalType').textContent = item.type || 'Unknown';
  document.getElementById('modalSource').textContent = item.source || 'Unknown';
  document.getElementById('modalSeverity').textContent = (item.severity || 'UNKNOWN').toUpperCase();
  document.getElementById('modalScore').textContent = calculateRiskScore(item);
  document.getElementById('modalPublished').textContent = new Date(item.published).toLocaleString();
  document.getElementById('modalDescription').textContent = item.description || 'No description available';
  
  // Show/hide type-specific fields
  const derivedIp = item.ip ||
    (item.id && item.id.startsWith('ABUSE-') ? item.id.replace(/^ABUSE-/, '') : null) ||
    ((item.description || '').match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/) || [])[0] || null;
  const showIp = !!derivedIp;

  document.getElementById('urlRow').style.display = (item.url) ? 'table-row' : 'none';
  document.getElementById('ipRow').style.display = showIp ? 'table-row' : 'none';
  document.getElementById('hashRow').style.display = (item.hash) ? 'table-row' : 'none';
  document.getElementById('familyRow').style.display = (item.family) ? 'table-row' : 'none';
  
  if (item.url) document.getElementById('modalUrl').textContent = item.url;
  if (showIp) document.getElementById('modalIp').textContent = derivedIp;
  if (item.hash) document.getElementById('modalHash').textContent = item.hash;
  if (item.family) document.getElementById('modalFamily').textContent = item.family;
  
  const links = getSourceLinks(item);
  const linksDiv = document.getElementById('modalLinks');
  linksDiv.innerHTML = '';
  links.forEach(link => {
    const a = document.createElement('a');
    a.href = link.url;
    a.target = '_blank';
    a.textContent = link.name + ' ↗';
    linksDiv.appendChild(a);
  });
  
  modal.classList.add('show');
}

function closeCveModal() {
  document.getElementById('cveModal').classList.remove('show');
  currentModalItem = null;
}

function openSourceLink() {
  if (currentModalItem) {
    const links = getSourceLinks(currentModalItem);
    if (links.length > 0) {
      window.open(links[0].url, '_blank');
    }
  }
}

function renderTable(){
  tableBody.innerHTML = '';
  const searchTerm = searchBox.value.toLowerCase();
  const severityVal = severityFilter.value;
  const sourceVal = sourceFilter.value;
  const indicatorVal = indicatorTypeFilter.value;

  const filtered = items.filter(it => {
    const matchSearch = searchTerm === '' || 
      it.id.toLowerCase().includes(searchTerm) ||
      (it.description && it.description.toLowerCase().includes(searchTerm)) ||
      (it.type && it.type.toLowerCase().includes(searchTerm));
    
    const matchSeverity = severityVal === '' || (it.severity && it.severity.toUpperCase() === severityVal);
    const matchSource = sourceVal === '' ||
      (it.source && it.source === sourceVal) ||
      (it.type && it.type.toUpperCase().includes(sourceVal.toUpperCase()));
    
    let matchIndicator = true;
    if (indicatorVal !== '') {
      const itemIndicatorType = getIndicatorType(it);
      matchIndicator = itemIndicatorType === indicatorVal;
    }
    
    return matchSearch && matchSeverity && matchSource && matchIndicator;
  });

  if (!filtered.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td colspan="7" class="empty-row">No threats match the selected filters.</td>
    `;
    tableBody.appendChild(tr);
  }

  filtered.slice(0, 100).forEach(it => {
    const tr = document.createElement('tr');
    const severityClass = `severity-${getSeverityColor(it.severity)}`;
    const typeDisplay = (it.type || 'Unknown').split('-')[0].trim();
    const indicatorDisplay = getIndicatorType(it);
    const riskScore = calculateRiskScore(it);
    
    tr.innerHTML = `
      <td><span class="severity-badge ${severityClass}">${escapeHtml((it.severity || 'LOW').toUpperCase())}</span></td>
      <td><span class="indicator-badge">${escapeHtml(indicatorDisplay)}</span></td>
      <td>${escapeHtml(it.id)}</td>
      <td><span class="source-badge">${escapeHtml(it.source || 'Unknown')}</span></td>
      <td>${new Date(it.published).toLocaleDateString()}</td>
      <td>${riskScore}</td>
      <td title="${escapeHtml(it.description)}">${escapeHtml((it.description || '').substring(0, 50))}...</td>
    `;
    
    tr.onclick = () => openCveModal(it);
    tr.style.cursor = 'pointer';
    tableBody.appendChild(tr);
  });

  updateStats();
  updateChart();
  updateTypeChart();
  updateTimeline();
  updateRiskScores();
}

function updateStats(){
  const total = items.length;
  const critical = items.filter(i => i.severity && i.severity.toUpperCase() === 'CRITICAL').length;
  const high = items.filter(i => i.severity && i.severity.toUpperCase() === 'HIGH').length;
  const uniqueSources = new Set(items.map(i => (i.source || 'Unknown').toUpperCase()));

  document.getElementById('totalCount').textContent = total;
  document.getElementById('criticalCount').textContent = critical;
  document.getElementById('highCount').textContent = high;
  document.getElementById('sourceCount').textContent = `${uniqueSources.size} sources`; 
  document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
}

// Severity Distribution Chart
let severityChart = null;
function updateChart(){
  const counts = {};
  items.forEach(i => {
    const s = (i.severity || 'UNKNOWN').toUpperCase();
    counts[s] = (counts[s] || 0) + 1;
  });
  
  const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const data = labels.map(l => counts[l] || 0);
  const colors = ['#ff4444', '#ffaa00', '#ffc800', '#00ff99'];
  
  const ctx = document.getElementById('severityChart').getContext('2d');
  if(severityChart) severityChart.destroy();
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors,
        borderColor: '#0a1419',
        borderWidth: 2
      }]
    },
    options: { 
      responsive: true, 
      maintainAspectRatio: true,
      plugins: {
        legend: { labels: { color: '#00d4ff', font: { size: 12 } } }
      }
    }
  });
}

// Threat Types Chart
let typeChart = null;
function updateTypeChart(){
  const counts = {};
  items.forEach(i => {
    const t = (i.type || 'Unknown').split('-')[0].trim();
    counts[t] = (counts[t] || 0) + 1;
  });
  
  const labels = Object.keys(counts);
  const data = labels.map(l => counts[l]);
  
  const ctx = document.getElementById('typeChart').getContext('2d');
  if(typeChart) typeChart.destroy();
  typeChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Count',
        data,
        backgroundColor: '#00d4ff',
        borderRadius: 6,
        borderColor: '#00ff99',
        borderWidth: 1
      }]
    },
    options: { 
      responsive: true, 
      indexAxis: 'y',
      plugins: {
        legend: { labels: { color: '#00d4ff', font: { size: 12 } } }
      },
      scales: {
        x: { ticks: { color: '#00d4ff' }, grid: { color: 'rgba(0, 212, 255, 0.1)' } },
        y: { ticks: { color: '#00d4ff' }, grid: { color: 'rgba(0, 212, 255, 0.1)' } }
      }
    }
  });
}

// Timeline Chart
let timelineChart = null;
function updateTimeline(){
  const now = new Date();
  const buckets = {};
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now);
    d.setHours(d.getHours() - i);
    const key = d.getHours() + ':00';
    buckets[key] = 0;
  }

  items.forEach(i => {
    const d = new Date(i.published);
    if (!isNaN(d.getTime())) {
      const key = d.getHours() + ':00';
      if (key in buckets) buckets[key]++;
    }
  });

  const labels = Object.keys(buckets);
  const data = Object.values(buckets);

  const ctx = document.getElementById('timelineChart').getContext('2d');
  if(timelineChart) timelineChart.destroy();
  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Threats/Hour',
        data,
        borderColor: '#00ff99',
        backgroundColor: 'rgba(0, 255, 153, 0.1)',
        tension: 0.4,
        fill: true,
        borderWidth: 2
      }]
    },
    options: { 
      responsive: true, 
      maintainAspectRatio: true,
      plugins: {
        legend: { labels: { color: '#00d4ff', font: { size: 12 } } }
      },
      scales: {
        y: { ticks: { color: '#00d4ff' }, grid: { color: 'rgba(0, 212, 255, 0.1)' } },
        x: { ticks: { color: '#00d4ff' }, grid: { color: 'rgba(0, 212, 255, 0.1)' } }
      }
    }
  });
}

// Risk Scores
function updateRiskScores(){
  const types = {};
  items.forEach(i => {
    const t = i.type || 'Unknown';
    types[t] = (types[t] || []).concat([i]);
  });

  const riskDiv = document.getElementById('riskScores');
  riskDiv.innerHTML = '';

  Object.keys(types).forEach(type => {
    const typeItems = types[type];
    const avgRisk = typeItems.reduce((s, i) => s + calculateRiskScore(i), 0) / typeItems.length;
    const pct = Math.round((avgRisk / 100) * 100);
    const filterValue = type.toUpperCase().includes('IP') ? 'IP' : '';

    const item = document.createElement('div');
    item.className = 'risk-item';
    item.innerHTML = `
      <strong>${type.split('-')[0].trim()}</strong>
      <div class="risk-bar"><div class="risk-fill" style="width: ${pct}%"></div></div>
      <div class="risk-percent">${pct}% risk | ${typeItems.length} items</div>
    `;
    item.addEventListener('click', () => {
      if (filterValue) {
        indicatorTypeFilter.value = filterValue;
        sourceFilter.value = '';
        renderTable();
      }
    });
    riskDiv.appendChild(item);
  });
}

async function loadLatest(){
  try{
    const resp = await fetch('/api/latest');
    const json = await resp.json();
    items = normalizeItems(json.items || []);
    renderTable();
  }catch(e){
    console.error(e);
  }
}

function renderUploadResults(data) {
  uploadResults.innerHTML = '';
  if (!data || !data.ok) {
    uploadStatus.textContent = data?.error || 'Upload failed.';
    return;
  }

  uploadStatus.innerHTML = `Processed <strong>${escapeHtml(data.fileName || 'file')}</strong> as <strong>${escapeHtml(data.detectedFormat || 'unknown')}</strong>. Found <strong>${data.indicatorsFound || 0}</strong> indicators.`;

  if (!data.vtResults || !data.vtResults.length) {
    uploadResults.innerHTML = '<div class="upload-card">No indicators were detected in the uploaded content.</div>';
    return;
  }

  const rows = data.vtResults.map((result) => {
    const riskClass = (result.riskLevel || 'low') === 'high' ? 'risk-high' : (result.riskLevel || 'low') === 'medium' ? 'risk-medium' : '';
    const scoreText = result.status === 'ok' ? `${result.securityScore}/100` : 'Unavailable';
    return `
      <div class="upload-card">
        <h3>${escapeHtml(result.indicator || 'Indicator')}</h3>
        <div class="result-meta">Type: ${escapeHtml(result.type || 'unknown')} • ${escapeHtml(result.status === 'ok' ? 'VirusTotal analyzed' : result.message || 'No result')}</div>
        <div>
          <span class="score-pill ${riskClass}">${escapeHtml(result.status === 'ok' ? `${result.securityScore}/100 security score` : 'Lookup failed')}</span>
          ${result.status === 'ok' ? `<span class="score-pill">Risk: ${escapeHtml((result.riskLevel || 'low').toUpperCase())}</span>` : ''}
        </div>
        ${result.status === 'ok' ? `<div class="result-meta">Malicious: ${result.malicious || 0} • Suspicious: ${result.suspicious || 0} • Undetected: ${result.undetected || 0}</div>` : ''}
        ${result.vtUrl ? `<div><a href="${result.vtUrl}" target="_blank" rel="noopener">View on VirusTotal ↗</a></div>` : ''}
      </div>
    `;
  }).join('');

  uploadResults.innerHTML = rows;
}

uploadForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = uploadInput.files[0];
  if (!file) {
    uploadStatus.textContent = 'Please choose a file to analyze.';
    return;
  }

  const formData = new FormData();
  formData.append('file', file);
  uploadStatus.textContent = 'Analyzing file and querying VirusTotal...';
  uploadResults.innerHTML = '';

  try {
    const response = await fetch('/api/upload', { method: 'POST', body: formData });
    const data = await response.json();
    renderUploadResults(data);
  } catch (error) {
    uploadStatus.textContent = 'Upload failed. Please try again.';
    uploadResults.innerHTML = '<div class="upload-card">Unable to reach the backend.</div>';
  }
});

// Search/Filter listeners
searchBox.addEventListener('input', renderTable);
severityFilter.addEventListener('change', renderTable);
sourceFilter.addEventListener('change', renderTable);
indicatorTypeFilter.addEventListener('change', renderTable);

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeCveModal();
});

// Close modal on background click
document.getElementById('cveModal').addEventListener('click', (e) => {
  if (e.target.id === 'cveModal') closeCveModal();
});

// SSE
const es = new EventSource('/api/stream');
es.onmessage = (ev) => {
  try{
    const obj = JSON.parse(ev.data);
    if(obj && obj.type === 'new' && obj.item){
      items.unshift(normalizeItem(obj.item));
      renderTable();
    }
  }catch(e){console.error(e)}
}

loadLatest();

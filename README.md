# Threat Intelligence Feed Dashboard

A professional SOC blue team threat intelligence dashboard that aggregates real-time data from **10 official threat intelligence sources** including CVEs, phishing attacks, malware hashes, malicious IPs, and URL scanning intelligence.

## Features

✅ **9 Comprehensive Threat Intelligence Sources**

**Vulnerability Intelligence (4 sources):**
- **NVD** - National Vulnerability Database (official CVE records)
- **CISA KEV** - Known Exploited Vulnerabilities
- **CIRCL** - CVE aggregation with vendor advisories
- **AlienVault OTX** - Community threat pulses

**IOC Enrichment & Malware/Phishing Feeds (5 sources):**
- **URLhaus** - Malicious URL database
- **MalwareBazaar** - Malware hashes & families
- **OpenPhish** - Phishing URL detection
- **urlscan.io** - URL scanning & reputation
- **AbuseIPDB** - Malicious IP addresses & reputation

✅ **Advanced Filtering & Display**
- Filter by **Severity** (Critical, High, Medium, Low)
- Filter by **Source** (all 10 sources)
- Filter by **IOC Type** (CVE, Malicious URL, Phishing, Hash, IP, URL Scan)
- Search by threat ID, description, or keyword
- Type-specific modal details (shows URL, Hash, IP based on indicator type)

✅ **Real-Time Updates**
- Server-Sent Events (SSE) for live threat streaming
- Automatic feed refreshes every 5 minutes from all 10 sources
- Persistent local threat database

✅ **Professional SOC Dashboard**
- Severity distribution chart (doughnut)
- Threat sources breakdown (bar chart)
- 24-hour threat timeline (line chart)
- Risk scoring by threat type
- Color-coded severity badges
- Live statistics header (total, critical, high, sources active)
- Direct links to official threat detail pages

## Quick Start

### Prerequisites
- Node.js 14+ and npm
- API keys (free tier available):
  - AlienVault OTX: https://otx.alienvault.com/auth/signin
  - AbuseIPDB: https://www.abuseipdb.com/register

### Installation

1. Navigate to the backend folder:
```bash
cd backend
```

2. Install dependencies:
```bash
npm install
```

3. Create `.env` file with your API keys:
```bash
copy .env.example .env
```

4. Edit `.env` and add your API keys:
```
PORT=4000
FETCH_INTERVAL_SECONDS=300

# Vulnerability Intelligence APIs (Optional)
OTX_API_KEY=your_otx_api_key

# IOC Enrichment APIs (Optional)
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# Public feeds below require NO API key
# URLhaus, MalwareBazaar, OpenPhish, urlscan.io - all public
```

5. Start the server locally:
```bash
cd backend
npm start
```

### One-step local start on Windows
If you want a single helper to prepare and launch locally, run from the repo root:
```powershell
./deploy.ps1
```

Then start the backend from `backend`:
```powershell
cd backend
./start-local.ps1
```

6. Open http://localhost:4000 in your browser

## API Endpoints

- `GET /api/latest` - Get all collected threats (JSON)
- `GET /api/stream` - Server-Sent Events stream for real-time updates

## Data Sources

### Vulnerability Intelligence (CVE Data)

| Source | Description | Requires Key | Update Freq |
|--------|-------------|--------------|-------------|
| **NVD** | Official CVE records, CVSS scores | Optional | Real-time |
| **CISA KEV** | Actively exploited vulnerabilities | None | Daily |
| **CIRCL** | Aggregates NVD + CPE + CWE + vendors | None | Real-time |
| **AlienVault OTX** | Community threat pulses & research | Free API key | Real-time |

### IOC Enrichment & Malware/Phishing Feeds

| Source | Description | Requires Key | Update Freq |
|--------|-------------|--------------|-------------|
| **URLhaus** | Malicious URL database | None | Real-time |
| **MalwareBazaar** | Malware hashes, families, metadata | None | Real-time |
| **OpenPhish** | Phishing URLs & phishing kit tracking | None | Real-time |
| **urlscan.io** | URL scanning intelligence & reputation | Optional | Real-time |
| **AbuseIPDB** | Malicious IP addresses & reputation | Free API key | Real-time |

### Getting API Keys

**⚠️ Important:** Many sources work WITHOUT API keys! Only get keys if you want enhanced features:

**Optional APIs (Free Tier Available):**

**AlienVault OTX:**
- Visit: https://otx.alienvault.com/auth/signin
- Sign up (free)
- Go to Settings → API Integration
- Copy API Key and add to `.env`

**AbuseIPDB:**
- Visit: https://www.abuseipdb.com/register?plan=free
- Sign up (free tier available)
- Go to Account → API
- Copy API Key and add to `.env`

**No API Key Required:**
- ✅ URLhaus - public feed
- ✅ MalwareBazaar - public API
- ✅ OpenPhish - public feed
- ✅ urlscan.io - free public API
- ✅ NVD - free API (optional key for rate limits)
- ✅ CISA KEV - public GitHub mirror
- ✅ CIRCL - public API

## File Structure

```
backend/
├── index.js              # Express server & fetchers
├── public/
│   ├── index.html        # Dashboard UI
│   ├── main.js           # Frontend logic
│   └── style.css         # Styling
├── db.json               # Local threat database
├── package.json          # Dependencies
├── .env                  # API keys (local only)
└── .env.example          # Template
```

## Dashboard Features

**Search & Filter**
- Search by threat ID, description, or type
- Filter by severity level (Critical, High, Medium, Low)
- Filter by threat type (CVE, OTX, Phishing, etc.)

**Visualizations**
- Severity distribution (critical, high, medium, low)
- Threat types breakdown
- 24-hour threat timeline
- Risk scores per threat type

**Live Stats**
- Total threat count
- Critical threat count
- High threat count
- Last update timestamp

## Configuration

### Fetch Interval
Edit `FETCH_INTERVAL_SECONDS` in `.env`:
```
FETCH_INTERVAL_SECONDS=300  # 5 minutes
```

### Adding New Data Sources
Edit `backend/index.js` and add new `fetchXXX()` functions, then call them in `fetchLatest()`.

## Deployment

### Railway.app (Recommended)
1. Push code to GitHub
2. Connect to Railway.app
3. Add environment variables in Railway dashboard
4. Deploy

### Render.com
1. Create new Web Service
2. Connect GitHub repo
3. Set build command: `cd backend && npm install`
4. Set start command: `cd backend && npm start`
5. Add environment variables
6. Deploy

### Local Development
```bash
npm start
# Server runs on http://localhost:4000
```

## Security Notes

⚠️ **Important:**
- Never commit `.env` file (add to .gitignore)
- Keep API keys private
- Use HTTPS in production
- Consider rate limiting for public deployment
- Add authentication if exposed to internet

## Monitoring

The backend logs all 9 data source activities:

**Vulnerability Intelligence:**
- `[NVD]` - National Vulnerability Database
- `[CISA-KEV]` - CISA Known Exploited Vulnerabilities
- `[CIRCL]` - CIRCL CVE aggregation
- `[OTX]` - AlienVault OTX threat pulses

**IOC & Malware/Phishing:**
- `[URLhaus]` - Malicious URL database
- `[MalwareBazaar]` - Malware hash submissions
- `[OpenPhish]` - Phishing URL detection
- `[urlscan.io]` - URL scanning results
- `[AbuseIPDB]` - Malicious IP addresses

Each log shows: `[SOURCE] added X | db size: Y`

## Troubleshooting

**Port 4000 already in use:**
```bash
# Windows
netstat -ano | findstr :4000
taskkill /PID <PID> /F

# Mac/Linux
lsof -i :4000
kill -9 <PID>
```

**Empty dashboard:**
- Check `.env` file has correct API keys
- Check backend logs for fetch errors
- Wait 5+ minutes for first data fetch
- Clear browser cache

**API errors:**
- Verify API keys are valid
- Check internet connection
- Review rate limits on each API
- Check backend logs for details

## License

MIT - Open Source

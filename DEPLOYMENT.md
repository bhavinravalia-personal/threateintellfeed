# Deployment Guide for Threat Intelligence Dashboard

This repository contains a Node.js backend that serves a live SOC threat intelligence dashboard with real-time feeds.

## Prepare GitHub

If this repo is not yet under version control, create a Git repo and push to GitHub before deploying.

### Windows PowerShell commands
```powershell
cd C:\Users\Bhavin\Desktop\TI
git init
git add .
git commit -m "Initial threat intelligence dashboard deploy"
git branch -M main
# create a GitHub repo in your GitHub account, then:
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

### If the repo already exists locally
```powershell
cd C:\Users\Bhavin\Desktop\TI
git status
git add .
git commit -m "Update deployment helpers and docs"
git push
```

If `git` is not installed, download and install it from https://git-scm.com/ then rerun the commands.

## Render Deployment

### 1. Create a Render web service
1. Go to https://dashboard.render.com.
2. Click **New** → **Web Service**.
3. Connect your GitHub account and select your repo.
4. For **Root Directory**, use `backend`.

### 2. Configure build and start commands
- Build command: `npm install`
- Start command: `npm start`
- Environment: `Node` or `Node.js`

### 3. Add environment variables
Add the following in Render’s environment section:
- `PORT=4000`
- `FETCH_INTERVAL_SECONDS=300`
- `OTX_API_KEY=your_otx_api_key`
- `ABUSEIPDB_API_KEY=your_abuseipdb_api_key`

### 4. Deploy
Click **Create Web Service**. Render will build and deploy your app.

### 5. Open the live site
When deployment completes, click the URL shown in Render.

## Recommended Hosting Services

### Render.com
1. Push the repository to GitHub.
2. Create a new Web Service on Render.
3. Connect the repo and select the `backend` directory.
4. Set build command:
   ```bash
   npm install
   ```
5. Set start command:
   ```bash
   npm start
   ```
6. Add environment variables in Render:
   - `PORT` (optional)
   - `FETCH_INTERVAL_SECONDS` (optional)
   - `OTX_API_KEY` (optional)
   - `ABUSEIPDB_API_KEY` (optional)
7. Deploy and open the live URL.

### Railway.app
1. Push repo to GitHub.
2. Create a new Railway project.
3. Link the repo and choose `backend`.
4. Set build command:
   ```bash
   npm install
   ```
5. Set start command:
   ```bash
   npm start
   ```
6. Add the same environment variables.

## Required Files
- `backend/index.js` — Express app + feed collectors
- `backend/package.json` — dependency manifest and start script
- `backend/public/` — dashboard UI and assets
- `backend/.env.example` — sample environment variables

## Local Deployment
```bash
cd backend
npm install
copy .env.example .env
# edit .env with your API keys
npm start
```

Open `http://localhost:4000` in your browser.

## Notes
- Keep `.env` private. Do not commit it.
- If you want to use live feeds from OTX or AbuseIPDB, add keys.
- The backend uses SSE for real-time updates.

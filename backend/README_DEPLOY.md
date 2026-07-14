# Hosting Your Threat Intelligence Dashboard

## Quick deployment checklist

- Ensure `backend/package.json` exists and contains:
  - `node` dependencies
  - `start` script set to `node index.js`
- Do not commit `.env`
- Add environment variables in your host:
  - `PORT`
  - `FETCH_INTERVAL_SECONDS`
  - `OTX_API_KEY`
  - `ABUSEIPDB_API_KEY`
- If this repo is not yet version controlled, initialize git and push to GitHub.

## Docker and Deployment Files

This folder includes deployment helpers:

- `Dockerfile` — build a container image for Docker-based hosts.
- `.dockerignore` — exclude local files from Docker builds.
- `Procfile` — useful for platforms like Heroku or Railway.

## Recommended hosts

### Render
- Root: `backend`
- Build: `npm install`
- Start: `npm start`

### Railway
- Root: `backend`
- Build: `npm install`
- Start: `npm start`

### Azure App Service
- Root: `backend`
- Startup command: `npm start`
- Add `web.config` if using Windows/IIS mode

## Notes
- The app is not static-only; it requires the Express server.
- Use the live URL provided by the host after deploy.
- If your host supports Docker, you can containerize `backend/index.js`.

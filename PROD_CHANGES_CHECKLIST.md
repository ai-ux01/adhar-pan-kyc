# Why changes aren’t showing on production

Use this checklist so updates (frontend + backend) actually appear on prod.

---

## 1. Code is on the branch that prod deploys from

- Most setups deploy from **main** (or **master**).
- If you only committed locally or on another branch, prod won’t have your changes.

```bash
git status
git branch
# If you're on a feature branch:
git checkout main
git merge <your-branch>
git push origin main
```

---

## 2. Frontend: new build was deployed

Production serves the **built** app (e.g. `frontend/build/`), not your source. Edits in `QrVerification.tsx` etc. only show after a new build is deployed.

- **Vercel / Netlify / Amplify:** Pushing to the deploy branch (e.g. `main`) should trigger a new build. Check the dashboard for the latest build and that it succeeded.
- **Manual / shared hosting:** You must build and upload the new build:

```bash
cd frontend
npm install
npm run build
# Then upload the contents of frontend/build/ to your hosting (e.g. via FTP or your deploy script).
```

---

## 3. Backend: server was restarted

Backend runs the **current code** only after a restart.

- **Vercel / serverless:** Redeploy the API (e.g. push to main or “Redeploy” in dashboard).
- **PM2 / Node on VPS:**
  ```bash
  pm2 restart all
  # or
  pm2 restart your-app-name
  ```
- **Docker:** Rebuild and restart:
  ```bash
  docker-compose up -d --build
  ```
- **Render / Railway:** Trigger a new deploy from the dashboard or by pushing to the connected branch.

---

## 4. Cache (browser / CDN)

Even after a new deploy, you might still see the old UI.

- Hard refresh: **Ctrl+Shift+R** (Windows/Linux) or **Cmd+Shift+R** (Mac).
- Or open the site in an incognito/private window.
- If you use a CDN (Cloudflare, etc.), purge cache for the site or the deploy URL.

---

## Quick checklist

| Step | Action |
|------|--------|
| 1 | Changes committed and pushed to the branch that prod uses (e.g. `main`) |
| 2 | Frontend: new build triggered and completed (or manual build uploaded) |
| 3 | Backend: server restarted or API redeployed |
| 4 | Hard refresh or incognito to avoid cache |

If you tell me how you deploy (e.g. Vercel + Render, or shared hosting), I can give exact commands for your setup.

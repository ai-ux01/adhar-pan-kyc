# 404 on production (Render)

If a route works locally but returns **404** on Render (`{"error":"Route not found","path":"/api/..."}`), the backend is running an **old build** that doesn’t include that route.

## Fix: redeploy the backend on Render

1. **Push** your latest code to the branch Render uses (e.g. `main`):
   ```bash
   git add -A && git commit -m "Backend routes" && git push origin main
   ```
2. Open [Render Dashboard](https://dashboard.render.com) → your **backend** service (e.g. `adhar-pan-kyc-1` or `kyc-aadhaar-backend`).
3. **Manual Deploy** → **Deploy latest commit**.
4. Wait for **Build** and **Deploy** to finish (logs should show "Your service is live").
5. Try the API again.

## Routes that must be in the deployed backend

All in `backend/src/routes/aadhaarVerification.js`:

| Method | Path (relative to /api/aadhaar-verification) | Purpose |
|--------|----------------------------------------------|---------|
| GET    | `/dynamic-field-keys`                        | Fetch custom field keys for edit form |
| PATCH  | `/records/:id`                               | Update dynamic fields for a record     |

- Full URLs:  
  `GET  https://adhar-pan-kyc.onrender.com/api/aadhaar-verification/dynamic-field-keys`  
  `PATCH https://adhar-pan-kyc.onrender.com/api/aadhaar-verification/records/:id` (body: `{ "dynamicFields": [ { "label": "...", "value": "..." } ] }`)

If either returns 404, the deploy does not include the latest `aadhaarVerification.js`. Redeploy from a commit that has these routes.

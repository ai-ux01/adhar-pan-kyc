# 404 on production (e.g. /api/aadhaar-verification/dynamic-field-keys)

If a route works locally but returns **404** on Render, the backend service is almost certainly running an **old build** that doesn’t include that route.

## Fix: redeploy the backend on Render

1. Open [Render Dashboard](https://dashboard.render.com) → your **backend** service (e.g. `kyc-aadhaar-backend`).
2. **Manual Deploy** → **Deploy latest commit** (or push your latest code to the connected branch, then deploy).
3. Wait for the build and deploy to finish.
4. Call the API again (e.g. `GET .../api/aadhaar-verification/dynamic-field-keys`).

Ensure the branch connected in Render has the commit that adds the route (e.g. `GET /dynamic-field-keys` in `backend/src/routes/aadhaarVerification.js`).

## Check that the route is in the repo

- File: `backend/src/routes/aadhaarVerification.js`
- Route: `router.get('/dynamic-field-keys', protect, ...)`
- Mount: `app.use('/api/aadhaar-verification', aadhaarVerificationRoutes)` in `server.js`

So the full URL is: `https://your-app.onrender.com/api/aadhaar-verification/dynamic-field-keys`.

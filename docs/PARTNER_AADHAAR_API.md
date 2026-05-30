# Partner Aadhaar Verification API — Integration Guide

Third-party integration for Aadhaar OTP KYC with **tenant isolation**, **API key authentication**, and **cache-first** verification (Sandbox is called only for new or previously failed Aadhaar numbers).

**Base URL (production):** `https://adhar-pan-kyc.onrender.com/api/v1/partner`  
**Base URL (local):** `http://localhost:3002/api/v1/partner`

---

## Overview

| Step | Endpoint | Purpose |
|------|----------|---------|
| 1 | `POST /aadhaar/entry` | Check if Aadhaar is already verified for your tenant |
| 2 | `POST /aadhaar/otp/send` | Send OTP (skipped if cached verified record exists) |
| 3 | `POST /aadhaar/otp/verify` | Verify OTP and store KYC (Sandbox only when not cached) |
| — | `GET /aadhaar/verification/:id` | Fetch a verification record by ID |

### Cache behaviour

- Data is scoped by **`tenantId`** (your partner account).
- If the same Aadhaar was **successfully verified** before for your tenant, **entry** and **otp/send** return cached KYC — **no Sandbox OTP call**.
- Failed / invalid attempts are **not** cached as verified; the next request goes through OTP again.
- Each tenant’s data is isolated; another tenant’s verified Aadhaar does not satisfy your cache.

---

## Authentication

Every partner request must include your API key.

**Option A — Authorization header (recommended)**

```http
Authorization: Bearer ak_live_yourtenant_abc123...
```

**Option B — Custom header**

```http
X-API-Key: ak_live_yourtenant_abc123...
```

Keys are issued once when an admin creates your tenant (`POST /api/admin/partners`). Store the key securely; it cannot be retrieved again (rotate if lost).

### Rate limiting

Default: **60 requests/minute per tenant** (configurable by admin).  
HTTP `429` when exceeded.

---

## Admin: Create a partner tenant

Requires **admin JWT** (same as your admin panel login).

```http
POST /api/admin/partners
Authorization: Bearer <admin_jwt>
Content-Type: application/json

{
  "tenantId": "acme_kyc",
  "name": "Acme KYC Pvt Ltd",
  "contactEmail": "api@acme.com",
  "rateLimitPerMinute": 120
}
```

**Response (201):**

```json
{
  "success": true,
  "message": "Partner tenant created. Store the API key securely; it will not be shown again.",
  "data": {
    "tenantId": "acme_kyc",
    "apiKey": "ak_live_acme_kyc_a1b2c3d4e5f6...",
    "apiKeyPrefix": "ak_live_acme_kyc_",
    "isActive": true,
    "rateLimitPerMinute": 120
  }
}
```

**Other admin routes**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/partners` | List tenants (no secrets) |
| `PATCH` | `/api/admin/partners/:tenantId` | Activate/deactivate, update limits |
| `POST` | `/api/admin/partners/:tenantId/rotate-key` | New API key (old key stops working) |

---

## 1. Aadhaar entry (cache check)

```http
POST /api/v1/partner/aadhaar/entry
Authorization: Bearer <partner_api_key>
Content-Type: application/json

{
  "aadhaarNumber": "697798350410",
  "consent": true,
  "externalReferenceId": "YOUR-ORDER-12345"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `aadhaarNumber` | Yes | 12-digit Aadhaar |
| `consent` | Recommended | `true` / `"y"` — required before OTP send |
| `externalReferenceId` | No | Your internal reference (stored on verify) |

### Response — cache hit (already verified)

```json
{
  "success": true,
  "cached": true,
  "otpRequired": false,
  "message": "Aadhaar already verified for this tenant. Returning cached KYC data.",
  "data": {
    "verificationId": "665a1b2c3d4e5f678901234",
    "tenantId": "acme_kyc",
    "aadhaarMasked": "XXXX-XXXX-0410",
    "name": "Ashul Kumar",
    "dateOfBirth": "01-03-1990",
    "gender": "M",
    "address": "...",
    "status": "verified",
    "source": "tenant_cache",
    "cached": true,
    "verifiedAt": "2026-05-23T10:00:00.000Z"
  }
}
```

### Response — cache miss (OTP required)

```json
{
  "success": true,
  "cached": false,
  "otpRequired": true,
  "message": "No verified record found. Proceed with OTP send.",
  "data": {
    "tenantId": "acme_kyc",
    "aadhaarMasked": "XXXX-XXXX-0410",
    "externalReferenceId": "YOUR-ORDER-12345"
  }
}
```

---

## 2. Send OTP

Skip this step if **entry** returned `cached: true`.

```http
POST /api/v1/partner/aadhaar/otp/send
Authorization: Bearer <partner_api_key>
Content-Type: application/json

{
  "aadhaarNumber": "697798350410",
  "consent": true,
  "externalReferenceId": "YOUR-ORDER-12345",
  "reason": "KYC Verification"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `consent` | **Yes** | Must be `true` |
| `reason` | No | Audit purpose (default: `KYC Verification`) |

### Response — OTP sent

```json
{
  "success": true,
  "cached": false,
  "otpSent": true,
  "message": "OTP sent successfully",
  "data": {
    "tenantId": "acme_kyc",
    "aadhaarMasked": "XXXX-XXXX-0410",
    "transactionId": "76530688",
    "expiresAt": "2026-05-23T10:15:00.000Z",
    "processingTime": 1200
  }
}
```

**Important:** Use `data.transactionId` exactly as returned in the verify step. It is the Sandbox **`reference_id`** (often numeric), not a UUID.

If a verified cache exists, response matches entry cache hit with `otpSent: false`.

---

## 3. Verify OTP

```http
POST /api/v1/partner/aadhaar/otp/verify
Authorization: Bearer <partner_api_key>
Content-Type: application/json

{
  "aadhaarNumber": "697798350410",
  "otp": "776813",
  "transactionId": "76530688",
  "externalReferenceId": "YOUR-ORDER-12345"
}
```

### Response — success

```json
{
  "success": true,
  "cached": false,
  "message": "Aadhaar verification completed successfully",
  "data": {
    "verificationId": "665a1b2c3d4e5f678901234",
    "status": "verified",
    "source": "sandbox_api",
    "name": "Ashul Kumar",
    "dateOfBirth": "01-03-1990",
    "gender": "M",
    "address": "...",
    "photo": "data:image/jpeg;base64,...",
    "verifiedAt": "2026-05-23T10:05:00.000Z"
  }
}
```

### Response — invalid OTP

```json
{
  "success": false,
  "cached": false,
  "message": "Invalid OTP. Verification rejected.",
  "data": {
    "status": "invalid",
    ...
  }
}
```

After a failed verify, call **otp/send** again for a new OTP session.

---

## 4. Get verification by ID

```http
GET /api/v1/partner/aadhaar/verification/{verificationId}
Authorization: Bearer <partner_api_key>
```

Returns the stored record for your tenant only.

---

## Recommended integration flow

```text
1. POST /aadhaar/entry
   ├─ cached=true  → use data, STOP
   └─ cached=false → continue

2. POST /aadhaar/otp/send (consent=true)
   ├─ cached=true  → use data, STOP
   └─ otpSent=true → show OTP UI to user

3. POST /aadhaar/otp/verify with OTP + transactionId
   ├─ success=true  → store verificationId, use KYC fields
   └─ success=false → allow retry from step 2
```

---

## Error codes

| HTTP | Meaning |
|------|---------|
| `400` | Validation error (Aadhaar format, missing consent, expired OTP session) |
| `401` | Missing or invalid API key |
| `404` | Verification ID not found for your tenant |
| `429` | Rate limit exceeded |
| `500` / `502` | Server or Sandbox provider error |

---

## CORS and browser vs server calls

### Correct API URL (important)

Partner APIs live on the **backend**, not under `/partner/login`:

| ✅ Correct | ❌ Wrong |
|-----------|---------|
| `https://adhar-pan-kyc.onrender.com/api/v1/partner/me` | `https://adhar-pan-kyc.onrender.com/partner/login/api/v1/partner/me` |

The `/partner/login` path is the **React UI only**. Never append `/api/...` to that path.

**Base URL for all partner calls:**

```text
https://adhar-pan-kyc.onrender.com/api/v1/partner
```

Example: `GET https://adhar-pan-kyc.onrender.com/api/v1/partner/me`

### Recommended: call from your backend

Third parties should call these APIs **server-to-server** (Node, Java, Python, etc.) with the API key. **No CORS issues** with curl or backend HTTP clients.

```javascript
// Node.js example — runs on YOUR server, not in browser
const res = await fetch('https://adhar-pan-kyc.onrender.com/api/v1/partner/aadhaar/entry', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    Authorization: 'Bearer ' + process.env.PARTNER_API_KEY
  },
  body: JSON.stringify({ aadhaarNumber: '697798350410', consent: true })
});
```

### Browser / JavaScript from another website

If a partner calls the API **from their website’s JavaScript**, the browser sends a CORS preflight. Their origin must be allowlisted.

On **Render → backend → Environment**, add:

```env
PARTNER_ALLOWED_ORIGINS=https://partner-site.com,https://app.partner-site.com
```

Then redeploy the backend. Comma-separated list of exact origins (scheme + host, no trailing slash).

Also allowed by default: your Vercel app, `localhost:8080` (HTML tester), and `https://adhar-pan-kyc.onrender.com`.

**Security note:** Do not embed the API key in public frontend JavaScript. Use browser calls only for testing; production integrations should use the partner’s **backend**.

---

## Environment variables (server)

Set on Render / `.env`:

```env
PARTNER_AADHAAR_HASH_PEPPER=long-random-secret-for-aadhaar-hashing
PARTNER_OTP_SESSION_TTL_MINUTES=15
# Comma-separated origins allowed to call partner API from browser (CORS)
PARTNER_ALLOWED_ORIGINS=https://your-partner-frontend.com
SANDBOX_API_KEY=...
SANDBOX_API_SECRET=...
```

---

## cURL examples

```bash
export BASE=https://adhar-pan-kyc.onrender.com
export KEY=ak_live_yourtenant_yoursecret

# Entry
curl -s -X POST "$BASE/api/v1/partner/aadhaar/entry" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"aadhaarNumber":"697798350410","consent":true,"externalReferenceId":"ORD-1"}'

# Send OTP
curl -s -X POST "$BASE/api/v1/partner/aadhaar/otp/send" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"aadhaarNumber":"697798350410","consent":true}'

# Verify OTP
curl -s -X POST "$BASE/api/v1/partner/aadhaar/otp/verify" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"aadhaarNumber":"697798350410","otp":"123456","transactionId":"76530688"}'
```

---

## Security notes

- Use **HTTPS** only in production.
- Do not log full Aadhaar or OTP in your systems.
- Rotate API keys if compromised (`POST /api/admin/partners/:tenantId/rotate-key`).
- Obtain explicit user **consent** before OTP (`consent: true`).
- Comply with UIDAI / DPDP requirements for your use case.

---

## Support

For tenant provisioning or key rotation, contact your AVIHR IDSYS administrator.

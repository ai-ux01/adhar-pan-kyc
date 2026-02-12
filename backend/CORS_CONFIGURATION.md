# CORS Configuration Guide

This guide explains how to configure CORS (Cross-Origin Resource Sharing) for your application when deploying on different servers.

## Overview

The application now supports flexible CORS configuration through environment variables, allowing you to easily configure allowed origins for different deployment environments.

## Configuration Options

### Environment Variables

#### `FRONTEND_URL` (Recommended)
The primary frontend URL for your production environment.

**Example:**
```bash
FRONTEND_URL=https://yourdomain.com
```

#### `ALLOWED_ORIGINS` (Production)
A comma-separated list of allowed origins for production. This is useful when you have multiple domains or subdomains.

**Example:**
```bash
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com,https://app.yourdomain.com
```

#### `DEV_ALLOWED_ORIGINS` (Development)
A comma-separated list of additional allowed origins for development (in addition to `http://localhost:3000`).

**Example:**
```bash
DEV_ALLOWED_ORIGINS=http://localhost:3001,http://192.168.1.100:3000
```

## How It Works

1. **Production Mode:**
   - If `ALLOWED_ORIGINS` is set, it uses those origins
   - If `FRONTEND_URL` is set, it adds that to the allowed origins
   - If neither is set, it falls back to default Vercel/Netlify patterns

2. **Development Mode:**
   - Defaults to `http://localhost:3000` and `http://127.0.0.1:3000`
   - Adds any origins from `DEV_ALLOWED_ORIGINS`
   - Allows all origins for flexibility during development

## Setting Up for Different Deployment Scenarios

### Scenario 1: Single Domain Deployment

If your frontend and backend are on the same domain or subdomain:

```bash
FRONTEND_URL=https://yourdomain.com
```

### Scenario 2: Different Domains

If your frontend is on a different domain:

```bash
FRONTEND_URL=https://app.yourdomain.com
ALLOWED_ORIGINS=https://app.yourdomain.com,https://www.yourdomain.com
```

### Scenario 3: Multiple Environments

For multiple environments (staging, production):

```bash
# Staging
ALLOWED_ORIGINS=https://staging.yourdomain.com,https://staging-app.yourdomain.com

# Production
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com,https://app.yourdomain.com
```

### Scenario 4: Vercel/Netlify Deployment

If you're using Vercel or Netlify, the default patterns will work, but you can also be explicit:

```bash
FRONTEND_URL=https://your-app.vercel.app
ALLOWED_ORIGINS=https://your-app.vercel.app,https://*.vercel.app
```

Note: Regex patterns are supported, so `https://*.vercel.app` will match any Vercel app subdomain.

## Quick Setup

1. **Copy the example environment file:**
   ```bash
   cp backend/env.example backend/.env
   ```

2. **Edit `.env` and add your frontend URL:**
   ```bash
   FRONTEND_URL=https://your-frontend-domain.com
   ALLOWED_ORIGINS=https://your-frontend-domain.com,https://www.your-frontend-domain.com
   ```

3. **Restart your backend server**

## Troubleshooting

### CORS Error: "No 'Access-Control-Allow-Origin' header"

**Solution:**
1. Check that your `FRONTEND_URL` or `ALLOWED_ORIGINS` matches your frontend domain exactly (including protocol: `https://` or `http://`)
2. Ensure there are no trailing slashes in your URLs
3. Check the backend logs for blocked origin warnings

### CORS Error in Development

**Solution:**
- Development mode allows all origins by default
- If you're still seeing errors, check that `NODE_ENV` is set to `development` or not set

### CORS Error After Deployment

**Solution:**
1. Verify your environment variables are set correctly in your production environment
2. Check that the frontend URL matches exactly (case-sensitive)
3. Review server logs for the blocked origin message

## Testing

To test your CORS configuration:

1. **From Browser Console:**
   ```javascript
   fetch('https://your-backend-domain.com/api/health', {
     method: 'GET',
     credentials: 'include'
   })
   .then(response => console.log('CORS OK:', response))
   .catch(error => console.error('CORS Error:', error));
   ```

2. **Check Backend Logs:**
   Look for messages like:
   ```
   CORS blocked origin: https://unallowed-domain.com
   ```

## Security Notes

- **Never use `*` for `Access-Control-Allow-Origin` in production** when credentials are enabled
- Always specify exact domains or use environment variables
- Regularly review and update your allowed origins
- Use HTTPS in production

## Support

If you continue to experience CORS issues after following this guide:
1. Check the browser console for the exact error message
2. Check the backend logs for blocked origin warnings
3. Verify your environment variables are correctly set
4. Ensure your frontend is making requests with the correct origin header


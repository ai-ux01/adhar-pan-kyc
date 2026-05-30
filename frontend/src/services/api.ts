import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';
import { handleCreditsHttpError, syncCreditsFromPayload } from '../utils/creditsSync';

const PRODUCTION_API_BASE = 'https://adhar-pan-kyc.onrender.com/api';

/** Always return an absolute API base URL (never a path-relative "api" that breaks on /partner/login). */
const getApiBaseURL = () => {
  const envUrl = process.env.REACT_APP_API_URL?.trim();

  if (envUrl) {
    if (envUrl.startsWith('http://') || envUrl.startsWith('https://')) {
      return envUrl.replace(/\/$/, '');
    }
    // "/api" — same-origin proxy (Vercel). Only use relative URL on hosts that proxy /api → backend.
    if (envUrl.startsWith('/')) {
      const host = window.location.hostname;
      const canUseSameOriginProxy =
        host.includes('vercel.app') ||
        host.includes('netlify.app') ||
        host.includes('amplifyapp.com') ||
        host === 'localhost' ||
        host === '127.0.0.1';
      if (canUseSameOriginProxy) {
        return envUrl.replace(/\/$/, '');
      }
      return PRODUCTION_API_BASE;
    }
    // Misconfigured "api" without leading slash — would resolve to /partner/login/api/...
    console.warn('REACT_APP_API_URL should be absolute or start with /. Using production API URL.');
    return PRODUCTION_API_BASE;
  }

  const isLocal =
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1' ||
    window.location.hostname.startsWith('192.168.');

  return isLocal ? 'http://localhost:3002/api' : PRODUCTION_API_BASE;
};

const apiBaseURL = getApiBaseURL();

export { getApiBaseURL };

/** Use for heavy GETs (bulk export, many DB decrypts). Default axios timeout is too short after Render cold start. */
export const HEAVY_REQUEST_TIMEOUT_MS = 180000;

// Log the API URL being used (helpful for debugging)
if (process.env.NODE_ENV !== 'production' || window.location.hostname === 'localhost') {
  console.log('🔗 API Base URL:', apiBaseURL);
  console.log('🔗 REACT_APP_API_URL:', process.env.REACT_APP_API_URL || 'Not set');
}

// Create axios instance with longer timeout for API calls
const api = axios.create({
  baseURL: apiBaseURL,
  timeout: 60000, // 60 seconds timeout
  headers: {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache'
  },
});

// Retry configuration for connection errors (Render free tier sleep issue)
const MAX_RETRIES = 2;
const RETRY_DELAY = 3000; // 3 seconds

// Helper function to check if error is retryable (connection errors)
const isRetryableError = (error: AxiosError): boolean => {
  if (!error.response) {
    // Network errors or connection closed errors
    const errorCode = (error as any).code;
    const errorMessage = error.message || '';
    return (
      errorCode === 'ECONNABORTED' || // Timeout errors
      errorCode === 'ECONNRESET' || // Connection reset
      errorCode === 'ETIMEDOUT' || // Timeout
      errorMessage.includes('timeout') || // Timeout message
      errorMessage.includes('ERR_CONNECTION_CLOSED') ||
      errorMessage.includes('Network Error') ||
      errorMessage.includes('ERR_NETWORK')
    );
  }
  return false;
};

// Helper function to get token from storage (same as AuthContext)
const getStoredToken = (): string | null => {
  return localStorage.getItem('token') || sessionStorage.getItem('token');
};

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = getStoredToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    // Initialize retry count if not present
    if (!(config as InternalAxiosRequestConfig & { _retryCount?: number })._retryCount) {
      (config as InternalAxiosRequestConfig & { _retryCount?: number })._retryCount = 0;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to retry on connection errors
api.interceptors.response.use(
  (response) => {
    syncCreditsFromPayload(response.data);
    return response;
  },
  async (error: AxiosError) => {
    const config = error.config as (InternalAxiosRequestConfig & { _retryCount?: number }) | undefined;
    
    if (!config) {
      return Promise.reject(error);
    }

    const retryCount = config._retryCount || 0;

    // Retry on connection errors
    if (isRetryableError(error) && retryCount < MAX_RETRIES) {
      config._retryCount = retryCount + 1;
      
      // Wait before retrying (exponential backoff)
      const delay = RETRY_DELAY * Math.pow(2, retryCount);
      
      console.log(`🔄 Connection error detected, retrying in ${delay}ms (attempt ${retryCount + 1}/${MAX_RETRIES})...`);
      
      await new Promise(resolve => setTimeout(resolve, delay));
      
      return api(config);
    }

    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response) {
      handleCreditsHttpError(error.response.status, error.response.data);
    }
    return Promise.reject(error);
  }
);

// Note: Response interceptor for 401 handling is managed in AuthContext.tsx
// to avoid conflicts and ensure proper token refresh flow

export default api;

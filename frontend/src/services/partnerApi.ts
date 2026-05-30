import axios, { AxiosError } from 'axios';
import { getApiBaseURL } from './api';

const getPartnerToken = (): string | null => {
  return localStorage.getItem('partner_token') || sessionStorage.getItem('partner_token');
};

const partnerApi = axios.create({
  baseURL: getApiBaseURL(),
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json'
  }
});

partnerApi.interceptors.request.use((config) => {
  const token = getPartnerToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

partnerApi.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('partner_token');
      sessionStorage.removeItem('partner_token');
      localStorage.removeItem('partner_tenant');
      sessionStorage.removeItem('partner_tenant');
      if (window.location.pathname.startsWith('/partner') && window.location.pathname !== '/partner/login') {
        window.location.href = '/partner/login';
      }
    }
    return Promise.reject(error);
  }
);

export default partnerApi;

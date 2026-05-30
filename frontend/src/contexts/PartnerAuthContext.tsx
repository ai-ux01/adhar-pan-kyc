import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import axios from 'axios';
import { getApiBaseURL } from '../services/api';

export interface PartnerTenant {
  tenantId: string;
  name: string;
  contactEmail?: string;
  portalEmail?: string;
  rateLimitPerMinute?: number;
  authMode?: 'portal' | 'apiKey';
}

interface PartnerAuthContextType {
  tenant: PartnerTenant | null;
  loading: boolean;
  isAuthenticated: boolean;
  authMode: 'portal' | 'apiKey' | null;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
  loginWithApiKey: (apiKey: string, rememberMe?: boolean) => Promise<void>;
  logout: () => void;
}

const PartnerAuthContext = createContext<PartnerAuthContextType | undefined>(undefined);

const getStoredPartnerToken = (): string | null => {
  return localStorage.getItem('partner_token') || sessionStorage.getItem('partner_token');
};

const getStoredPartnerTenant = (): PartnerTenant | null => {
  const raw = localStorage.getItem('partner_tenant') || sessionStorage.getItem('partner_tenant');
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
};

async function fetchPartnerSession(token: string): Promise<PartnerTenant> {
  const isApiKey = token.startsWith('ak_live_');
  const url = isApiKey
    ? `${getApiBaseURL()}/v1/partner/me`
    : `${getApiBaseURL()}/partner-auth/me`;

  const res = await axios.get(url, {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!res.data?.tenant) {
    throw new Error('Invalid session response');
  }

  return {
    ...res.data.tenant,
    authMode: isApiKey ? 'apiKey' : 'portal'
  };
}

export const PartnerAuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [tenant, setTenant] = useState<PartnerTenant | null>(getStoredPartnerTenant());
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const bootstrap = async () => {
      const token = getStoredPartnerToken();
      if (!token) {
        setLoading(false);
        return;
      }

      try {
        const tenantData = await fetchPartnerSession(token);
        setTenant(tenantData);
      } catch {
        localStorage.removeItem('partner_token');
        sessionStorage.removeItem('partner_token');
        localStorage.removeItem('partner_tenant');
        sessionStorage.removeItem('partner_tenant');
        setTenant(null);
      } finally {
        setLoading(false);
      }
    };

    bootstrap();
  }, []);

  const persistSession = (token: string, tenantData: PartnerTenant, rememberMe: boolean) => {
    const storage = rememberMe ? localStorage : sessionStorage;
    storage.setItem('partner_token', token);
    storage.setItem('partner_tenant', JSON.stringify(tenantData));
    setTenant(tenantData);
  };

  const login = async (email: string, password: string, rememberMe = false) => {
    const res = await axios.post(`${getApiBaseURL()}/partner-auth/login`, { email, password });
    const { token, tenant: tenantData } = res.data;

    if (!token || !tenantData) {
      throw new Error('Invalid login response');
    }

    persistSession(token, { ...tenantData, authMode: 'portal' }, rememberMe);
  };

  const loginWithApiKey = async (apiKey: string, rememberMe = false) => {
    const trimmed = apiKey.trim();
    if (!trimmed.startsWith('ak_live_')) {
      throw new Error('API key must start with ak_live_');
    }

    const tenantData = await fetchPartnerSession(trimmed);
    persistSession(trimmed, tenantData, rememberMe);
  };

  const logout = () => {
    localStorage.removeItem('partner_token');
    sessionStorage.removeItem('partner_token');
    localStorage.removeItem('partner_tenant');
    sessionStorage.removeItem('partner_tenant');
    setTenant(null);
  };

  return (
    <PartnerAuthContext.Provider
      value={{
        tenant,
        loading,
        isAuthenticated: !!tenant && !!getStoredPartnerToken(),
        authMode: tenant?.authMode || null,
        login,
        loginWithApiKey,
        logout
      }}
    >
      {children}
    </PartnerAuthContext.Provider>
  );
};

export const usePartnerAuth = (): PartnerAuthContextType => {
  const context = useContext(PartnerAuthContext);
  if (!context) {
    throw new Error('usePartnerAuth must be used within PartnerAuthProvider');
  }
  return context;
};

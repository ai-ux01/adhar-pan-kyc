import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import axios from 'axios';
import { getApiBaseURL } from '../services/api';

export interface PartnerTenant {
  tenantId: string;
  name: string;
  contactEmail?: string;
  portalEmail?: string;
  rateLimitPerMinute?: number;
}

interface PartnerAuthContextType {
  tenant: PartnerTenant | null;
  loading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
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
        const res = await axios.get(`${getApiBaseURL()}/partner-auth/me`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.data?.tenant) {
          setTenant(res.data.tenant);
        }
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

  const login = async (email: string, password: string, rememberMe = false) => {
    const res = await axios.post(`${getApiBaseURL()}/partner-auth/login`, { email, password });
    const { token, tenant: tenantData } = res.data;

    if (!token || !tenantData) {
      throw new Error('Invalid login response');
    }

    const storage = rememberMe ? localStorage : sessionStorage;
    storage.setItem('partner_token', token);
    storage.setItem('partner_tenant', JSON.stringify(tenantData));
    setTenant(tenantData);
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
        login,
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

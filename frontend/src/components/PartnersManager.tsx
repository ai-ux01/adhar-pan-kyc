import React, { useState, useEffect } from 'react';
import api from '../services/api';
import { useToast } from '../contexts/ToastContext';
import {
  PlusIcon,
  KeyIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClipboardDocumentIcon
} from '@heroicons/react/24/outline';

interface PartnerTenant {
  _id: string;
  tenantId: string;
  name: string;
  contactEmail?: string;
  portalEmail?: string;
  isActive: boolean;
  rateLimitPerMinute: number;
  createdAt: string;
}

interface CreateCredentials {
  tenantId: string;
  name: string;
  apiKey: string;
  portalEmail: string;
  portalPassword: string;
}

const PartnersManager: React.FC = () => {
  const { showToast } = useToast();
  const [tenants, setTenants] = useState<PartnerTenant[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createdCredentials, setCreatedCredentials] = useState<CreateCredentials | null>(null);
  const [formData, setFormData] = useState({
    tenantId: '',
    name: '',
    contactEmail: '',
    portalEmail: '',
    portalPassword: '',
    rateLimitPerMinute: 60
  });

  const fetchTenants = async () => {
    setLoading(true);
    try {
      const res = await api.get('/admin/partners');
      setTenants(res.data.data || []);
    } catch (error: any) {
      showToast(error.response?.data?.message || 'Failed to load partners', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTenants();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const payload: Record<string, unknown> = {
        tenantId: formData.tenantId.trim(),
        name: formData.name.trim(),
        contactEmail: formData.contactEmail.trim() || undefined,
        portalEmail: formData.portalEmail.trim(),
        rateLimitPerMinute: formData.rateLimitPerMinute
      };
      if (formData.portalPassword.trim()) {
        payload.portalPassword = formData.portalPassword.trim();
      }

      const res = await api.post('/admin/partners', payload);
      const data = res.data.data;

      setCreatedCredentials({
        tenantId: data.tenantId,
        name: data.name,
        apiKey: data.apiKey,
        portalEmail: data.portalEmail,
        portalPassword: data.portalPassword
      });

      setShowCreateModal(false);
      setFormData({
        tenantId: '',
        name: '',
        contactEmail: '',
        portalEmail: '',
        portalPassword: '',
        rateLimitPerMinute: 60
      });
      fetchTenants();
      showToast('Partner tenant created', 'success');
    } catch (error: any) {
      showToast(error.response?.data?.message || 'Failed to create partner', 'error');
    }
  };

  const toggleActive = async (tenant: PartnerTenant) => {
    try {
      await api.patch(`/admin/partners/${tenant.tenantId}`, { isActive: !tenant.isActive });
      showToast(`Partner ${tenant.isActive ? 'deactivated' : 'activated'}`, 'success');
      fetchTenants();
    } catch (error: any) {
      showToast(error.response?.data?.message || 'Update failed', 'error');
    }
  };

  const rotateKey = async (tenantId: string) => {
    if (!window.confirm('Rotate API key? The old key will stop working immediately.')) return;
    try {
      const res = await api.post(`/admin/partners/${tenantId}/rotate-key`);
      const apiKey = res.data.data?.apiKey;
      if (apiKey) {
        setCreatedCredentials({
          tenantId,
          name: tenants.find((t) => t.tenantId === tenantId)?.name || tenantId,
          apiKey,
          portalEmail: tenants.find((t) => t.tenantId === tenantId)?.portalEmail || '',
          portalPassword: '(unchanged — portal login password not rotated)'
        });
      }
      showToast('API key rotated', 'success');
    } catch (error: any) {
      showToast(error.response?.data?.message || 'Rotate failed', 'error');
    }
  };

  const resetPortalPassword = async (tenantId: string) => {
    if (!window.confirm('Reset portal login password for this tenant?')) return;
    try {
      const res = await api.post(`/admin/partners/${tenantId}/reset-portal-password`);
      const data = res.data.data;
      setCreatedCredentials({
        tenantId,
        name: tenants.find((t) => t.tenantId === tenantId)?.name || tenantId,
        apiKey: '(unchanged — API key not rotated)',
        portalEmail: data.portalEmail,
        portalPassword: data.portalPassword
      });
      showToast('Portal password reset', 'success');
    } catch (error: any) {
      showToast(error.response?.data?.message || 'Reset failed', 'error');
    }
  };

  const copyText = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      showToast(`${label} copied`, 'success');
    } catch {
      showToast('Copy failed', 'error');
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold text-gray-900">Partner Tenants</h2>
            <p className="text-sm text-gray-600 mt-1">
              Create tenant accounts for third-party Aadhaar API access. Tenants log in at{' '}
              <code className="text-xs bg-gray-100 px-1 rounded">/partner/login</code>.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-purple-500 to-indigo-600 text-white rounded-xl font-medium hover:shadow-lg transition-all"
          >
            <PlusIcon className="h-5 w-5 mr-2" />
            Create Tenant
          </button>
        </div>
      </div>

      <div className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-gray-500">Loading partners...</div>
        ) : tenants.length === 0 ? (
          <div className="p-8 text-center text-gray-500">No partner tenants yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tenant</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Portal login</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rate limit</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {tenants.map((tenant) => (
                  <tr key={tenant._id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <div className="font-medium text-gray-900">{tenant.name}</div>
                      <div className="text-sm text-gray-500">{tenant.tenantId}</div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-700">{tenant.portalEmail || '—'}</td>
                    <td className="px-6 py-4 text-sm text-gray-700">{tenant.rateLimitPerMinute}/min</td>
                    <td className="px-6 py-4">
                      {tenant.isActive ? (
                        <span className="inline-flex items-center text-green-700 text-sm">
                          <CheckCircleIcon className="h-4 w-4 mr-1" /> Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center text-red-700 text-sm">
                          <XCircleIcon className="h-4 w-4 mr-1" /> Inactive
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => toggleActive(tenant)}
                          className="text-sm px-3 py-1 rounded-lg border border-gray-300 hover:bg-gray-100"
                        >
                          {tenant.isActive ? 'Deactivate' : 'Activate'}
                        </button>
                        <button
                          type="button"
                          onClick={() => rotateKey(tenant.tenantId)}
                          className="text-sm px-3 py-1 rounded-lg border border-gray-300 hover:bg-gray-100 inline-flex items-center"
                        >
                          <KeyIcon className="h-4 w-4 mr-1" /> Rotate API key
                        </button>
                        <button
                          type="button"
                          onClick={() => resetPortalPassword(tenant.tenantId)}
                          className="text-sm px-3 py-1 rounded-lg border border-gray-300 hover:bg-gray-100 inline-flex items-center"
                        >
                          <ArrowPathIcon className="h-4 w-4 mr-1" /> Reset portal password
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-2xl shadow-xl max-w-lg w-full p-6 max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-bold text-gray-900 mb-4">Create Partner Tenant</h3>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Tenant ID</label>
                <input
                  required
                  pattern="[a-z0-9_-]{3,64}"
                  title="Lowercase letters, numbers, _ or -"
                  value={formData.tenantId}
                  onChange={(e) => setFormData({ ...formData, tenantId: e.target.value.toLowerCase() })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2"
                  placeholder="acme_kyc"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Company name</label>
                <input
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2"
                  placeholder="Acme KYC Pvt Ltd"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Contact email</label>
                <input
                  type="email"
                  value={formData.contactEmail}
                  onChange={(e) => setFormData({ ...formData, contactEmail: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2"
                  placeholder="api@acme.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Portal login email</label>
                <input
                  required
                  type="email"
                  value={formData.portalEmail}
                  onChange={(e) => setFormData({ ...formData, portalEmail: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2"
                  placeholder="partner@acme.com"
                />
                <p className="text-xs text-gray-500 mt-1">Tenant uses this to log in at /partner/login</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Portal password (optional)</label>
                <input
                  type="text"
                  minLength={8}
                  value={formData.portalPassword}
                  onChange={(e) => setFormData({ ...formData, portalPassword: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2"
                  placeholder="Auto-generated if blank (min 8 chars)"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Rate limit (req/min)</label>
                <input
                  type="number"
                  min={1}
                  max={1000}
                  value={formData.rateLimitPerMinute}
                  onChange={(e) => setFormData({ ...formData, rateLimitPerMinute: Number(e.target.value) })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2"
                />
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 border border-gray-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-indigo-600 text-white rounded-lg font-medium"
                >
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {createdCredentials && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-2xl shadow-xl max-w-lg w-full p-6">
            <h3 className="text-lg font-bold text-gray-900 mb-2">Save credentials now</h3>
            <p className="text-sm text-amber-700 bg-amber-50 border border-amber-200 rounded-lg p-3 mb-4">
              These secrets are shown once. Share the portal login with the tenant so they can use{' '}
              <strong>/partner/login</strong>. The API key is for server-to-server integration.
            </p>
            <div className="space-y-3 text-sm">
              <div>
                <span className="text-gray-500">Tenant:</span>{' '}
                <strong>{createdCredentials.name}</strong> ({createdCredentials.tenantId})
              </div>
              <div className="flex items-start gap-2">
                <div className="flex-1 break-all">
                  <span className="text-gray-500 block">API key</span>
                  <code className="text-xs bg-gray-100 p-2 rounded block mt-1">{createdCredentials.apiKey}</code>
                </div>
                {createdCredentials.apiKey.startsWith('ak_') && (
                  <button type="button" onClick={() => copyText(createdCredentials.apiKey, 'API key')} className="mt-5 p-2 border rounded-lg">
                    <ClipboardDocumentIcon className="h-4 w-4" />
                  </button>
                )}
              </div>
              <div>
                <span className="text-gray-500">Portal email:</span>{' '}
                <strong>{createdCredentials.portalEmail}</strong>
              </div>
              <div className="flex items-start gap-2">
                <div className="flex-1">
                  <span className="text-gray-500 block">Portal password</span>
                  <code className="text-xs bg-gray-100 p-2 rounded block mt-1">{createdCredentials.portalPassword}</code>
                </div>
                {!createdCredentials.portalPassword.startsWith('(') && (
                  <button
                    type="button"
                    onClick={() => copyText(createdCredentials.portalPassword, 'Portal password')}
                    className="mt-5 p-2 border rounded-lg"
                  >
                    <ClipboardDocumentIcon className="h-4 w-4" />
                  </button>
                )}
              </div>
            </div>
            <button
              type="button"
              onClick={() => setCreatedCredentials(null)}
              className="mt-6 w-full px-4 py-2 bg-indigo-600 text-white rounded-lg font-medium"
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default PartnersManager;

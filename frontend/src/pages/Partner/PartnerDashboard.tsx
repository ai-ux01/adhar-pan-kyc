import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { usePartnerAuth } from '../../contexts/PartnerAuthContext';
import partnerApi from '../../services/partnerApi';
import { ArrowRightOnRectangleIcon, CheckCircleIcon } from '@heroicons/react/24/outline';

type FlowStep = 1 | 2 | 3 | 4 | 'done';

const STEPS: { id: FlowStep; label: string }[] = [
  { id: 1, label: 'Entry' },
  { id: 2, label: 'Send OTP' },
  { id: 3, label: 'Verify OTP' },
  { id: 4, label: 'Get record' }
];

const PartnerDashboard: React.FC = () => {
  const { tenant, loading, isAuthenticated, authMode, logout } = usePartnerAuth();
  const [aadhaarNumber, setAadhaarNumber] = useState('');
  const [externalReferenceId, setExternalReferenceId] = useState('');
  const [consent, setConsent] = useState(true);
  const [transactionId, setTransactionId] = useState('');
  const [otp, setOtp] = useState('');
  const [verificationId, setVerificationId] = useState('');
  const [apiLoading, setApiLoading] = useState(false);
  const [lastResponse, setLastResponse] = useState<unknown>(null);
  const [lastStatus, setLastStatus] = useState<number | null>(null);
  const [currentStep, setCurrentStep] = useState<FlowStep>(1);
  const [stepHint, setStepHint] = useState('Step 1: Check if Aadhaar is already verified (cache).');
  const [listPage, setListPage] = useState(1);
  const [listStatus, setListStatus] = useState('all');
  const [records, setRecords] = useState<Array<Record<string, unknown>>>([]);
  const [pagination, setPagination] = useState<{ page: number; total: number; totalPages: number } | null>(null);

  if (!loading && !isAuthenticated) {
    return <Navigate to="/partner/login" replace />;
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-100">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600" />
      </div>
    );
  }

  const validateAadhaar = (): boolean => {
    const n = aadhaarNumber.replace(/\s/g, '');
    if (!/^\d{12}$/.test(n)) {
      setLastResponse({ success: false, message: 'Enter a valid 12-digit Aadhaar number' });
      setLastStatus(400);
      return false;
    }
    return true;
  };

  const sharedBody = () => ({
    aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
    consent,
    externalReferenceId: externalReferenceId.trim() || undefined
  });

  const runRequest = async (label: string, method: 'get' | 'post', url: string, body?: object) => {
    setApiLoading(true);
    setStepHint(label);
    try {
      const res = method === 'get'
        ? await partnerApi.get(url)
        : await partnerApi.post(url, body);
      setLastResponse(res.data);
      setLastStatus(res.status);

      const data = res.data?.data;
      if (data?.transactionId) setTransactionId(String(data.transactionId));
      if (data?.verificationId) setVerificationId(String(data.verificationId));

      return res.data;
    } catch (error: any) {
      setLastResponse(error.response?.data || { message: error.message });
      setLastStatus(error.response?.status || 0);
      throw error;
    } finally {
      setApiLoading(false);
    }
  };

  const handleEntry = async () => {
    if (!validateAadhaar()) return;
    try {
      const result = await runRequest('Step 1 — Entry (cache check)', 'post', '/v1/partner/aadhaar/entry', sharedBody());
      if (result.cached) {
        setCurrentStep('done');
        setStepHint('Done — cache hit. KYC data returned below. No OTP needed.');
      } else {
        setCurrentStep(2);
        setStepHint('Step 2 — No cache. Click Send OTP or use Run complete flow.');
      }
    } catch {
      /* shown in response panel */
    }
  };

  const handleSendOtp = async () => {
    if (!validateAadhaar()) return;
    if (!consent) {
      setLastResponse({ success: false, message: 'Consent must be checked before sending OTP' });
      setLastStatus(400);
      return;
    }
    try {
      const result = await runRequest('Step 2 — Send OTP', 'post', '/v1/partner/aadhaar/otp/send', {
        ...sharedBody(),
        reason: 'KYC Verification'
      });
      if (result.cached) {
        setCurrentStep('done');
        setStepHint('Done — verified from cache.');
      } else if (result.otpSent) {
        setCurrentStep(3);
        setStepHint('Step 3 — OTP sent to Aadhaar mobile. Enter OTP + click Verify OTP.');
      }
    } catch {
      /* shown in response panel */
    }
  };

  const handleVerifyOtp = async () => {
    if (!validateAadhaar()) return;
    if (!otp.trim() || !transactionId.trim()) {
      setLastResponse({ success: false, message: 'OTP and transaction ID are required' });
      setLastStatus(400);
      return;
    }
    try {
      const result = await runRequest('Step 3 — Verify OTP', 'post', '/v1/partner/aadhaar/otp/verify', {
        aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
        otp: otp.trim(),
        transactionId: transactionId.trim(),
        externalReferenceId: externalReferenceId.trim() || undefined
      });
      if (result.success) {
        setCurrentStep(4);
        setStepHint('Step 4 — Verified! Optional: click Get record to fetch by verificationId.');
      }
    } catch {
      /* shown in response panel */
    }
  };

  const handleGetVerification = async () => {
    if (!verificationId.trim()) {
      setLastResponse({ success: false, message: 'Enter verificationId first' });
      setLastStatus(400);
      return;
    }
    try {
      await runRequest(
        'Step 4 — Get verification record',
        'get',
        `/v1/partner/aadhaar/verification/${encodeURIComponent(verificationId.trim())}`
      );
      setCurrentStep('done');
      setStepHint('Complete flow finished.');
    } catch {
      /* shown in response panel */
    }
  };

  const handleCompleteFlow = async () => {
    if (!validateAadhaar()) return;
    try {
      const entry = await runRequest('Complete flow — entry', 'post', '/v1/partner/aadhaar/entry', sharedBody());
      if (entry.cached) {
        setCurrentStep('done');
        setStepHint('Complete — already verified (cache).');
        return;
      }

      if (!consent) {
        setLastResponse({ success: false, message: 'Enable consent before running OTP flow' });
        setLastStatus(400);
        return;
      }

      const send = await runRequest('Complete flow — send OTP', 'post', '/v1/partner/aadhaar/otp/send', {
        ...sharedBody(),
        reason: 'KYC Verification'
      });
      if (send.cached) {
        setCurrentStep('done');
        return;
      }

      setCurrentStep(3);
      setStepHint('OTP sent. Enter the 6-digit code from the phone, then click Verify OTP.');
    } catch {
      /* shown in response panel */
    }
  };

  const handleListRecords = async (page = listPage) => {
    setApiLoading(true);
    try {
      const params: Record<string, string | number> = { page, limit: 20 };
      if (listStatus !== 'all') params.status = listStatus;
      const res = await partnerApi.get('/v1/partner/aadhaar/verifications', { params });
      setRecords(res.data.data || []);
      setPagination(res.data.pagination || null);
      setListPage(page);
      setLastResponse(res.data);
      setLastStatus(res.status);
      setStepHint(`Loaded ${res.data.pagination?.total ?? 0} verification record(s) for your tenant.`);
    } catch (error: any) {
      setLastResponse(error.response?.data || { message: error.message });
      setLastStatus(error.response?.status || 0);
    } finally {
      setApiLoading(false);
    }
  };

  const stepIndex = (s: FlowStep) => (s === 'done' ? 4 : s);

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between gap-4">
          <div>
            <h1 className="text-lg font-bold text-slate-900">Partner Aadhaar — Test Console</h1>
            <p className="text-sm text-slate-600">
              {tenant?.name} · <span className="font-mono text-xs">{tenant?.tenantId}</span>
              {authMode === 'apiKey' && (
                <span className="ml-2 text-xs bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded-full">API key</span>
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={logout}
            className="inline-flex items-center text-sm text-slate-600 hover:text-slate-900 px-3 py-2 rounded-lg border border-slate-200 shrink-0"
          >
            <ArrowRightOnRectangleIcon className="h-4 w-4 mr-2" />
            Logout
          </button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8 space-y-6">
        {/* Step progress */}
        <div className="bg-white rounded-xl border border-slate-200 p-4">
          <div className="flex flex-wrap gap-2 justify-between mb-3">
            {STEPS.map((step) => {
              const done = stepIndex(currentStep) > step.id || currentStep === 'done';
              const active = currentStep === step.id;
              return (
                <div
                  key={step.id}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium ${
                    done
                      ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                      : active
                        ? 'bg-indigo-50 text-indigo-800 border border-indigo-200'
                        : 'bg-slate-50 text-slate-500 border border-slate-100'
                  }`}
                >
                  {done ? (
                    <CheckCircleIcon className="h-4 w-4" />
                  ) : (
                    <span className="w-5 h-5 rounded-full bg-current/10 flex items-center justify-center text-xs">
                      {step.id}
                    </span>
                  )}
                  {step.label}
                </div>
              );
            })}
          </div>
          <p className="text-sm text-indigo-900 bg-indigo-50 border border-indigo-100 rounded-lg p-3">{stepHint}</p>
        </div>

        <div className="grid md:grid-cols-2 gap-6">
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <h2 className="font-semibold text-slate-900">Request fields</h2>
            <div>
              <label className="text-sm text-slate-600">Aadhaar number *</label>
              <input
                value={aadhaarNumber}
                onChange={(e) => setAadhaarNumber(e.target.value.replace(/\D/g, '').slice(0, 12))}
                maxLength={12}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 font-mono"
                placeholder="697798350410"
              />
            </div>
            <div>
              <label className="text-sm text-slate-600">External reference ID</label>
              <input
                value={externalReferenceId}
                onChange={(e) => setExternalReferenceId(e.target.value)}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2"
                placeholder="ORDER-12345"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-700">
              <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
              Consent (required for OTP)
            </label>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <h2 className="font-semibold text-slate-900">OTP verify</h2>
            <div>
              <label className="text-sm text-slate-600">Transaction ID (from Send OTP)</label>
              <input
                value={transactionId}
                onChange={(e) => setTransactionId(e.target.value)}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 font-mono text-sm"
                placeholder="76530688"
              />
            </div>
            <div>
              <label className="text-sm text-slate-600">OTP from phone</label>
              <input
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                maxLength={6}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-lg tracking-widest font-mono"
                placeholder="123456"
              />
            </div>
            <div>
              <label className="text-sm text-slate-600">Verification ID (auto-filled after verify)</label>
              <input
                value={verificationId}
                onChange={(e) => setVerificationId(e.target.value)}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 font-mono text-sm"
              />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <h2 className="font-semibold text-slate-900">Run flow</h2>
          <button
            type="button"
            disabled={apiLoading}
            onClick={handleCompleteFlow}
            className="w-full sm:w-auto px-6 py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-semibold disabled:opacity-50"
          >
            Run complete flow (Entry → Send OTP)
          </button>
          <p className="text-xs text-slate-500">After OTP arrives on the phone, enter it above and click Verify OTP.</p>
          <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-100">
            <button type="button" disabled={apiLoading} onClick={handleEntry} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm disabled:opacity-50">
              1. Entry
            </button>
            <button type="button" disabled={apiLoading} onClick={handleSendOtp} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm disabled:opacity-50">
              2. Send OTP
            </button>
            <button type="button" disabled={apiLoading} onClick={handleVerifyOtp} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm disabled:opacity-50">
              3. Verify OTP
            </button>
            <button type="button" disabled={apiLoading} onClick={handleGetVerification} className="px-4 py-2 border border-slate-300 rounded-lg text-sm disabled:opacity-50">
              4. Get record
            </button>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <h2 className="font-semibold text-slate-900">Stored verifications</h2>
          <p className="text-sm text-slate-600">All Aadhaar verification records saved for your tenant.</p>
          <div className="flex flex-wrap gap-2 items-end">
            <div>
              <label className="text-xs text-slate-500">Status</label>
              <select
                value={listStatus}
                onChange={(e) => setListStatus(e.target.value)}
                className="block border border-slate-300 rounded-lg px-3 py-2 text-sm"
              >
                <option value="all">All</option>
                <option value="verified">Verified</option>
                <option value="invalid">Invalid</option>
                <option value="rejected">Rejected</option>
                <option value="pending">Pending</option>
                <option value="error">Error</option>
              </select>
            </div>
            <button
              type="button"
              disabled={apiLoading}
              onClick={() => handleListRecords(1)}
              className="px-4 py-2 bg-slate-800 text-white rounded-lg text-sm font-medium disabled:opacity-50"
            >
              Load records
            </button>
            {pagination && (
              <div className="flex items-center gap-2 text-sm text-slate-600">
                <button
                  type="button"
                  disabled={listPage <= 1 || apiLoading}
                  onClick={() => handleListRecords(listPage - 1)}
                  className="px-2 py-1 border rounded disabled:opacity-40"
                >
                  Prev
                </button>
                <span>Page {pagination.page} / {pagination.totalPages} ({pagination.total} total)</span>
                <button
                  type="button"
                  disabled={listPage >= pagination.totalPages || apiLoading}
                  onClick={() => handleListRecords(listPage + 1)}
                  className="px-2 py-1 border rounded disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            )}
          </div>
          {records.length > 0 && (
            <div className="overflow-x-auto border border-slate-200 rounded-lg">
              <table className="min-w-full text-sm">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-3 py-2 text-left">Masked Aadhaar</th>
                    <th className="px-3 py-2 text-left">Name</th>
                    <th className="px-3 py-2 text-left">Status</th>
                    <th className="px-3 py-2 text-left">Reference</th>
                    <th className="px-3 py-2 text-left">Verified</th>
                  </tr>
                </thead>
                <tbody>
                  {records.map((r) => (
                    <tr key={String(r.verificationId)} className="border-t border-slate-100 hover:bg-slate-50">
                      <td className="px-3 py-2 font-mono text-xs">{String(r.aadhaarMasked || '—')}</td>
                      <td className="px-3 py-2">{String(r.name || '—')}</td>
                      <td className="px-3 py-2">
                        <span className={`px-2 py-0.5 rounded text-xs ${r.status === 'verified' ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100'}`}>
                          {String(r.status)}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-xs">{String(r.externalReferenceId || '—')}</td>
                      <td className="px-3 py-2 text-xs">{r.verifiedAt ? new Date(String(r.verifiedAt)).toLocaleString() : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="bg-slate-900 rounded-xl p-5 text-slate-100">
          <div className="flex items-center justify-between mb-3 text-sm">
            <span className="font-medium">API response</span>
            {lastStatus != null && (
              <span className={lastStatus >= 200 && lastStatus < 300 ? 'text-emerald-400' : 'text-red-400'}>
                HTTP {lastStatus}
              </span>
            )}
          </div>
          <pre className="text-xs overflow-auto max-h-96 whitespace-pre-wrap break-words">
            {lastResponse ? JSON.stringify(lastResponse, null, 2) : 'Responses appear here after each step.'}
          </pre>
        </div>
      </main>
    </div>
  );
};

export default PartnerDashboard;

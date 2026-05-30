import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { usePartnerAuth } from '../../contexts/PartnerAuthContext';
import partnerApi from '../../services/partnerApi';
import { ArrowRightOnRectangleIcon } from '@heroicons/react/24/outline';

const PartnerDashboard: React.FC = () => {
  const { tenant, loading, isAuthenticated, logout } = usePartnerAuth();
  const [aadhaarNumber, setAadhaarNumber] = useState('');
  const [externalReferenceId, setExternalReferenceId] = useState('');
  const [consent, setConsent] = useState(true);
  const [transactionId, setTransactionId] = useState('');
  const [otp, setOtp] = useState('');
  const [verificationId, setVerificationId] = useState('');
  const [apiLoading, setApiLoading] = useState(false);
  const [lastResponse, setLastResponse] = useState<unknown>(null);
  const [lastStatus, setLastStatus] = useState<number | null>(null);
  const [stepHint, setStepHint] = useState('Start with Entry to check cache.');

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

      if (res.data?.cached) {
        setStepHint('Cache hit — Aadhaar already verified for your tenant.');
      } else if (res.data?.otpRequired === false && res.data?.cached) {
        setStepHint('Verified from cache.');
      } else if (res.data?.otpSent) {
        setStepHint('OTP sent. Enter OTP and click Verify OTP.');
      }

      return res.data;
    } catch (error: any) {
      setLastResponse(error.response?.data || { message: error.message });
      setLastStatus(error.response?.status || 0);
      throw error;
    } finally {
      setApiLoading(false);
    }
  };

  const handleEntry = () => runRequest('Entry check', 'post', '/v1/partner/aadhaar/entry', sharedBody());
  const handleSendOtp = () => runRequest('Send OTP', 'post', '/v1/partner/aadhaar/otp/send', {
    ...sharedBody(),
    reason: 'KYC Verification'
  });
  const handleVerifyOtp = () => runRequest('Verify OTP', 'post', '/v1/partner/aadhaar/otp/verify', {
    aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
    otp: otp.trim(),
    transactionId: transactionId.trim(),
    externalReferenceId: externalReferenceId.trim() || undefined
  });
  const handleGetVerification = () => {
    if (!verificationId.trim()) {
      setLastResponse({ success: false, message: 'Enter verificationId first' });
      setLastStatus(400);
      return;
    }
    return runRequest('Get verification', 'get', `/v1/partner/aadhaar/verification/${encodeURIComponent(verificationId.trim())}`);
  };

  const handleFullFlow = async () => {
    try {
      const entry = await runRequest('Full flow — entry', 'post', '/v1/partner/aadhaar/entry', sharedBody());
      if (entry.cached) return;

      const send = await runRequest('Full flow — send OTP', 'post', '/v1/partner/aadhaar/otp/send', {
        ...sharedBody(),
        reason: 'KYC Verification'
      });
      if (send.cached) return;

      setStepHint('OTP sent. Enter the code from the phone and click Verify OTP.');
    } catch {
      // response already shown
    }
  };

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-slate-900">Partner Aadhaar API</h1>
            <p className="text-sm text-slate-600">
              {tenant?.name} · <span className="font-mono text-xs">{tenant?.tenantId}</span>
            </p>
          </div>
          <button
            type="button"
            onClick={logout}
            className="inline-flex items-center text-sm text-slate-600 hover:text-slate-900 px-3 py-2 rounded-lg border border-slate-200"
          >
            <ArrowRightOnRectangleIcon className="h-4 w-4 mr-2" />
            Logout
          </button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8 space-y-6">
        <div className="bg-indigo-50 border border-indigo-100 rounded-xl p-4 text-sm text-indigo-900">
          {stepHint}
        </div>

        <div className="grid md:grid-cols-2 gap-6">
          <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
            <h2 className="font-semibold text-slate-900">Request fields</h2>
            <div>
              <label className="text-sm text-slate-600">Aadhaar number</label>
              <input
                value={aadhaarNumber}
                onChange={(e) => setAadhaarNumber(e.target.value)}
                maxLength={12}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2"
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
              <label className="text-sm text-slate-600">Transaction ID</label>
              <input
                value={transactionId}
                onChange={(e) => setTransactionId(e.target.value)}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 font-mono text-sm"
              />
            </div>
            <div>
              <label className="text-sm text-slate-600">OTP</label>
              <input
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                maxLength={6}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2"
              />
            </div>
            <div>
              <label className="text-sm text-slate-600">Verification ID (for GET)</label>
              <input
                value={verificationId}
                onChange={(e) => setVerificationId(e.target.value)}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 font-mono text-sm"
              />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h2 className="font-semibold text-slate-900 mb-4">API actions</h2>
          <div className="flex flex-wrap gap-2">
            <button type="button" disabled={apiLoading} onClick={handleEntry} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium disabled:opacity-50">
              1. Entry
            </button>
            <button type="button" disabled={apiLoading} onClick={handleSendOtp} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium disabled:opacity-50">
              2. Send OTP
            </button>
            <button type="button" disabled={apiLoading} onClick={handleVerifyOtp} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium disabled:opacity-50">
              3. Verify OTP
            </button>
            <button type="button" disabled={apiLoading} onClick={handleGetVerification} className="px-4 py-2 border border-slate-300 rounded-lg text-sm">
              Get record
            </button>
            <button type="button" disabled={apiLoading} onClick={handleFullFlow} className="px-4 py-2 bg-emerald-600 text-white rounded-lg text-sm font-medium disabled:opacity-50">
              Run entry → send
            </button>
          </div>
        </div>

        <div className="bg-slate-900 rounded-xl p-5 text-slate-100">
          <div className="flex items-center justify-between mb-3 text-sm">
            <span className="font-medium">Response</span>
            {lastStatus != null && (
              <span className={lastStatus >= 200 && lastStatus < 300 ? 'text-emerald-400' : 'text-red-400'}>
                HTTP {lastStatus}
              </span>
            )}
          </div>
          <pre className="text-xs overflow-auto max-h-96 whitespace-pre-wrap break-words">
            {lastResponse ? JSON.stringify(lastResponse, null, 2) : 'Run an API action to see JSON here.'}
          </pre>
        </div>
      </main>
    </div>
  );
};

export default PartnerDashboard;

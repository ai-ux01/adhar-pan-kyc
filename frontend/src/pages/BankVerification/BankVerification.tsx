import React, { useEffect, useState } from 'react';
import { useToast } from '../../contexts/ToastContext';
import { useVerificationCredits } from '../../hooks/useVerificationCredits';
import api from '../../services/api';
import {
  CreditCardIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline';

interface BankVerificationRecord {
  _id: string;
  ifsc: string;
  accountNumber: string;
  status: string;
  nameAtBank?: string;
  createdAt: string;
}

interface BankVerificationResult {
  recordId: string;
  ifsc: string;
  accountNumber: string;
  status: string;
  nameAtBank?: string;
  accountExists: boolean;
  processedAt: string;
  processingTime?: number;
}

const IFSC_PATTERN = /^[A-Z]{4}0[A-Z0-9]{6}$/;
const ACCOUNT_PATTERN = /^\d{8,20}$/;

const BankVerification: React.FC = () => {
  const { showToast } = useToast();
  const { guardBeforeVerify, syncCreditsAfterVerify } = useVerificationCredits();

  const [ifsc, setIfsc] = useState('');
  const [accountNumber, setAccountNumber] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<BankVerificationResult | null>(null);
  const [records, setRecords] = useState<BankVerificationRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState(true);

  const fetchRecords = async () => {
    try {
      setLoadingRecords(true);
      const response = await api.get('/bank-verification/records?limit=10');
      setRecords(response.data?.data?.records || []);
    } catch (error) {
      console.error('Failed to fetch Bank verification records:', error);
    } finally {
      setLoadingRecords(false);
    }
  };

  useEffect(() => {
    fetchRecords();
  }, []);

  const validateForm = () => {
    const cleanIfsc = ifsc.trim().toUpperCase();
    const cleanAccount = accountNumber.trim();

    if (!cleanIfsc) {
      showToast({ type: 'error', message: 'Please enter bank IFSC code' });
      return false;
    }
    if (!IFSC_PATTERN.test(cleanIfsc)) {
      showToast({
        type: 'error',
        message: 'Invalid IFSC format. Example: HDFC0001234 (11 characters starting with 4 alphabets, 5th character "0")',
      });
      return false;
    }

    if (!cleanAccount) {
      showToast({ type: 'error', message: 'Please enter bank Account Number' });
      return false;
    }
    if (!ACCOUNT_PATTERN.test(cleanAccount)) {
      showToast({
        type: 'error',
        message: 'Invalid Account Number. Must be digits only, length between 8 and 20.',
      });
      return false;
    }

    return true;
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;
    if (!guardBeforeVerify()) return;

    try {
      setVerifying(true);
      setResult(null);

      const response = await api.post('/bank-verification/verify-single', {
        ifsc: ifsc.trim().toUpperCase(),
        accountNumber: accountNumber.trim(),
      });

      await syncCreditsAfterVerify(response.data);
      setResult(response.data.data);
      setIfsc('');
      setAccountNumber('');

      showToast({
        type: response.data.data.status === 'verified' ? 'success' : 'error',
        message: response.data.message,
      });

      await fetchRecords();
    } catch (error: any) {
      await syncCreditsAfterVerify(error.response?.data);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to verify bank account',
      });
    } finally {
      setVerifying(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'verified':
        return <CheckCircleIcon className="h-5 w-5 text-emerald-500" />;
      case 'rejected':
      case 'error':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
      default:
        return <ClockIcon className="h-5 w-5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-8">
      {/* Premium Header */}
      <div className="rounded-3xl bg-gradient-to-r from-blue-600 via-indigo-600 to-violet-600 p-8 text-white shadow-xl">
        <div className="flex items-center gap-4">
          <div className="rounded-2xl bg-white/20 p-3">
            <CreditCardIcon className="h-8 w-8" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Bank Verification</h1>
            <p className="mt-1 text-blue-100 text-sm">
              Verify bank account presence and retrieve registered name instantly without transaction transfers.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        {/* Verification Form */}
        <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-4">Account details</h2>
          <form onSubmit={handleVerify} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                IFSC Code
              </label>
              <input
                type="text"
                value={ifsc}
                onChange={(e) => setIfsc(e.target.value.toUpperCase())}
                placeholder="HDFC0001234"
                className="w-full rounded-xl border border-slate-300 px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="mt-1 text-xs text-slate-500">
                11-digit alphanumeric code. 5th digit is always 0.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Account Number
              </label>
              <input
                type="text"
                value={accountNumber}
                onChange={(e) => setAccountNumber(e.target.value)}
                placeholder="1234567890"
                className="w-full rounded-xl border border-slate-300 px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="mt-1 text-xs text-slate-500">
                Bank account number (digits only).
              </p>
            </div>

            <button
              type="submit"
              disabled={verifying}
              className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-5 py-3 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-60 transition-colors"
            >
              <MagnifyingGlassIcon className="h-5 w-5" />
              {verifying ? 'Verifying…' : 'Verify Account'}
            </button>
          </form>
        </div>

        {/* Verification Result */}
        <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-4">Verification result</h2>
          {!result ? (
            <p className="text-sm text-slate-500">Enter IFSC and Account details to run verification.</p>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                {getStatusIcon(result.status)}
                <span className="text-sm font-medium capitalize text-slate-800">{result.status}</span>
              </div>
              
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm border-t border-slate-100 pt-4">
                <div>
                  <dt className="text-slate-500">Account Owner Name (At Bank)</dt>
                  <dd className="font-semibold text-slate-900 text-base">{result.nameAtBank || '—'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">IFSC Code</dt>
                  <dd className="font-medium text-slate-900">{result.ifsc}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Account Number</dt>
                  <dd className="font-medium text-slate-900">{result.accountNumber}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Account Exists</dt>
                  <dd className="font-medium text-slate-900">{result.accountExists ? 'Yes' : 'No'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Verification ID</dt>
                  <dd className="font-medium text-slate-900">{result.recordId || '—'}</dd>
                </div>
                {result.processingTime !== undefined && (
                  <div>
                    <dt className="text-slate-500">Processing Time</dt>
                    <dd className="font-medium text-slate-900">{result.processingTime} ms</dd>
                  </div>
                )}
              </dl>
            </div>
          )}
        </div>
      </div>

      {/* History log */}
      <div className="rounded-2xl bg-white border border-slate-200 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-100">
          <h2 className="text-lg font-semibold text-slate-900">Recent verifications</h2>
        </div>
        {loadingRecords ? (
          <div className="p-8 text-center text-sm text-slate-500">Loading records…</div>
        ) : records.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-500">No bank verifications yet.</div>
        ) : (
          <div className="divide-y divide-slate-100">
            {records.map((record) => (
              <div key={record._id} className="px-6 py-4 flex items-center justify-between gap-4">
                <div>
                  <p className="font-medium text-slate-900">
                    {record.accountNumber} · <span className="text-slate-500">{record.ifsc}</span>
                  </p>
                  <p className="text-sm text-slate-500">
                    Holder: <span className="font-medium text-slate-700">{record.nameAtBank || '—'}</span> ·{' '}
                    {new Date(record.createdAt).toLocaleString()}
                  </p>
                </div>
                <div className="flex items-center gap-2 capitalize text-sm text-slate-700">
                  {getStatusIcon(record.status)}
                  {record.status}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default BankVerification;

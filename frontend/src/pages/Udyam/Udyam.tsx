import React, { useEffect, useState } from 'react';
import { useToast } from '../../contexts/ToastContext';
import { useVerificationCredits } from '../../hooks/useVerificationCredits';
import api from '../../services/api';
import {
  BuildingOffice2Icon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline';

interface UdyamRecord {
  _id: string;
  udyamNumber: string;
  status: string;
  enterpriseName?: string;
  ownerName?: string;
  enterpriseType?: string;
  createdAt: string;
}

interface UdyamResult {
  recordId: string;
  udyamNumber: string;
  status: string;
  enterpriseName?: string;
  ownerName?: string;
  organizationType?: string;
  enterpriseType?: string;
  majorActivity?: string;
  dateOfUdyamRegistration?: string;
  dateOfIncorporation?: string;
  gender?: string;
  socialCategory?: string;
  splitAddress?: Record<string, string>;
  unitLocations?: Array<Record<string, string>>;
  nicCodes?: Array<Record<string, string>>;
  classificationHistory?: Array<Record<string, string>>;
  udyamCertificateUrl?: string;
  dic?: string;
  msmeDi?: string;
  referenceId?: number;
  processingTime?: number;
}

const UDYAM_PATTERN = /^UDYAM-[A-Z]{2}-\d{2}-\d{7}$/;

const Udyam: React.FC = () => {
  const { showToast } = useToast();
  const { guardBeforeVerify, syncCreditsAfterVerify } = useVerificationCredits();

  const [udyamNumber, setUdyamNumber] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<UdyamResult | null>(null);
  const [records, setRecords] = useState<UdyamRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState(true);

  const fetchRecords = async () => {
    try {
      setLoadingRecords(true);
      const response = await api.get('/udyam/records?limit=10');
      setRecords(response.data?.data?.records || []);
    } catch (error) {
      console.error('Failed to fetch Udyam records:', error);
    } finally {
      setLoadingRecords(false);
    }
  };

  useEffect(() => {
    fetchRecords();
  }, []);

  const normalizeUdyam = (value: string) =>
    value.trim().toUpperCase().replace(/\s+/g, '');

  const validateForm = () => {
    const normalized = normalizeUdyam(udyamNumber);
    if (!normalized) {
      showToast({ type: 'error', message: 'Please enter Udyam registration number' });
      return false;
    }
    if (!UDYAM_PATTERN.test(normalized)) {
      showToast({
        type: 'error',
        message: 'Invalid format. Example: UDYAM-UP-43-1234567',
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

      const response = await api.post('/udyam/verify-single', {
        udyamNumber: normalizeUdyam(udyamNumber),
      });

      await syncCreditsAfterVerify(response.data);
      setResult(response.data.data);
      setUdyamNumber('');

      showToast({
        type: response.data.data.status === 'verified' ? 'success' : 'error',
        message: response.data.message,
      });

      await fetchRecords();
    } catch (error: any) {
      await syncCreditsAfterVerify(error.response?.data);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to verify Udyam registration',
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
      <div className="rounded-3xl bg-gradient-to-r from-indigo-600 via-violet-600 to-purple-600 p-8 text-white shadow-xl">
        <div className="flex items-center gap-4">
          <div className="rounded-2xl bg-white/20 p-3">
            <BuildingOffice2Icon className="h-8 w-8" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Verify Udyam</h1>
            <p className="mt-1 text-indigo-100 text-sm">
              Verify MSME Udyam registration via Cashfree and view enterprise details.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-4">Udyam verification</h2>
          <form onSubmit={handleVerify} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Udyam registration number
              </label>
              <input
                type="text"
                value={udyamNumber}
                onChange={(e) => setUdyamNumber(e.target.value.toUpperCase())}
                placeholder="UDYAM-UP-43-1234567"
                className="w-full rounded-xl border border-slate-300 px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
              <p className="mt-1 text-xs text-slate-500">
                Format: UDYAM-{'{STATE}'}-{'{DISTRICT}'}-{'{NUMBER}'}
              </p>
            </div>
            <button
              type="submit"
              disabled={verifying}
              className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-3 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-60 transition-colors"
            >
              <MagnifyingGlassIcon className="h-5 w-5" />
              {verifying ? 'Verifying…' : 'Verify Udyam'}
            </button>
          </form>
        </div>

        <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-4">Verification result</h2>
          {!result ? (
            <p className="text-sm text-slate-500">Enter a Udyam number and run verification.</p>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                {getStatusIcon(result.status)}
                <span className="text-sm font-medium capitalize text-slate-800">{result.status}</span>
              </div>
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                <div>
                  <dt className="text-slate-500">Udyam number</dt>
                  <dd className="font-medium text-slate-900">{result.udyamNumber}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Enterprise</dt>
                  <dd className="font-medium text-slate-900">{result.enterpriseName || '—'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Owner</dt>
                  <dd className="font-medium text-slate-900">{result.ownerName || '—'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Enterprise type</dt>
                  <dd className="font-medium text-slate-900">{result.enterpriseType || '—'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Organization</dt>
                  <dd className="font-medium text-slate-900">{result.organizationType || '—'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Major activity</dt>
                  <dd className="font-medium text-slate-900">{result.majorActivity || '—'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Registration date</dt>
                  <dd className="font-medium text-slate-900">{result.dateOfUdyamRegistration || '—'}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Reference ID</dt>
                  <dd className="font-medium text-slate-900">{result.referenceId ?? '—'}</dd>
                </div>
              </dl>

              {result.splitAddress && (
                <div className="rounded-xl bg-slate-50 p-4 text-sm">
                  <p className="font-medium text-slate-800 mb-2">Registered address</p>
                  <p className="text-slate-600">
                    {[
                      result.splitAddress.flat,
                      result.splitAddress.building,
                      result.splitAddress.street,
                      result.splitAddress.city,
                      result.splitAddress.district,
                      result.splitAddress.state,
                      result.splitAddress.pincode,
                    ]
                      .filter(Boolean)
                      .join(', ')}
                  </p>
                </div>
              )}

              {result.nicCodes && result.nicCodes.length > 0 && (
                <div>
                  <p className="text-sm font-medium text-slate-800 mb-2">NIC classification</p>
                  <ul className="space-y-2 text-sm text-slate-600">
                    {result.nicCodes.map((nic, index) => (
                      <li key={index} className="rounded-lg bg-slate-50 px-3 py-2">
                        {nic.nic_5_description || nic.nic_4_description || nic.activity || 'NIC entry'}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="rounded-2xl bg-white border border-slate-200 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-100">
          <h2 className="text-lg font-semibold text-slate-900">Recent verifications</h2>
        </div>
        {loadingRecords ? (
          <div className="p-8 text-center text-sm text-slate-500">Loading records…</div>
        ) : records.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-500">No verifications yet.</div>
        ) : (
          <div className="divide-y divide-slate-100">
            {records.map((record) => (
              <div key={record._id} className="px-6 py-4 flex items-center justify-between gap-4">
                <div>
                  <p className="font-medium text-slate-900">{record.udyamNumber}</p>
                  <p className="text-sm text-slate-500">
                    {record.enterpriseName || record.ownerName || '—'} ·{' '}
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

export default Udyam;

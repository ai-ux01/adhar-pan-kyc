import React, { useEffect, useState, useRef } from 'react';
import { useToast } from '../../contexts/ToastContext';
import { useVerificationCredits } from '../../hooks/useVerificationCredits';
import api from '../../services/api';
import {
  CreditCardIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  MagnifyingGlassIcon,
  CloudArrowUpIcon,
  DocumentArrowDownIcon,
  TrashIcon,
  PlayIcon,
  DocumentTextIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';

interface BankVerificationRecord {
  _id: string;
  ifsc: string;
  accountNumber: string;
  status: string;
  nameAtBank?: string;
  createdAt: string;
  accountExists?: boolean;
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

interface Batch {
  _id: string;
  totalRecords: number;
  pendingRecords: number;
  verifiedRecords: number;
  rejectedRecords: number;
  errorRecords: number;
  createdAt: string;
  updatedAt: string;
}

interface BatchDetail {
  batchId: string;
  records: BankVerificationRecord[];
  stats: {
    total: number;
    pending: number;
    verified: number;
    rejected: number;
    error: number;
  };
}

const IFSC_PATTERN = /^[A-Z]{4}0[A-Z0-9]{6}$/;
const ACCOUNT_PATTERN = /^\d{8,20}$/;

const BankVerification: React.FC = () => {
  const { showToast } = useToast();
  const { guardBeforeVerify, syncCreditsAfterVerify } = useVerificationCredits();

  // Tab State
  const [activeTab, setActiveTab] = useState<'single' | 'upload'>('single');

  // Single Verification Form State
  const [ifsc, setIfsc] = useState('');
  const [accountNumber, setAccountNumber] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<BankVerificationResult | null>(null);

  // Bulk Upload / Batch State
  const [batches, setBatches] = useState<Batch[]>([]);
  const [selectedBatch, setSelectedBatch] = useState<BatchDetail | null>(null);
  const [loadingBatches, setLoadingBatches] = useState(false);
  const [loadingBatchDetails, setLoadingBatchDetails] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [processingBatch, setProcessingBatch] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchBatches = async () => {
    try {
      setLoadingBatches(true);
      const response = await api.get('/bank-verification/batches');
      setBatches(response.data?.data || []);
    } catch (error) {
      console.error('Failed to fetch Bank verification batches:', error);
    } finally {
      setLoadingBatches(false);
    }
  };

  const fetchBatchDetails = async (batchId: string) => {
    try {
      setLoadingBatchDetails(true);
      const response = await api.get(`/bank-verification/batch/${batchId}`);
      setSelectedBatch(response.data?.data || null);
    } catch (error) {
      console.error('Failed to fetch batch details:', error);
      showToast({ type: 'error', message: 'Failed to fetch batch details' });
    } finally {
      setLoadingBatchDetails(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'upload') {
      fetchBatches();
    }
  }, [activeTab]);

  const handleTabChange = (tab: 'single' | 'upload') => {
    setActiveTab(tab);
    setSelectedFile(null);
    setSelectedBatch(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // Single verification validation
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

  // Handle Single Verification submission
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

  // Handle File selection
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
    }
  };

  // Handle File Upload submission
  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      showToast({ type: 'error', message: 'Please select an Excel/CSV file to upload' });
      return;
    }

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      setUploading(true);
      const response = await api.post('/bank-verification/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      showToast({ type: 'success', message: response.data.message });
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      await fetchBatches();
      if (response.data.data?.batchId) {
        await fetchBatchDetails(response.data.data.batchId);
      }
    } catch (error: any) {
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to upload file'
      });
    } finally {
      setUploading(false);
    }
  };

  // Handle Batch Process triggering
  const handleProcessBatch = async (batchId: string) => {
    if (!guardBeforeVerify()) return;

    try {
      setProcessingBatch(true);
      const response = await api.post(`/bank-verification/batch/${batchId}/process`);
      
      await syncCreditsAfterVerify(response.data);
      showToast({ type: 'success', message: response.data.message });
      await fetchBatchDetails(batchId);
      await fetchBatches();
    } catch (error: any) {
      await syncCreditsAfterVerify(error.response?.data);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to process batch verification'
      });
    } finally {
      setProcessingBatch(false);
    }
  };

  // Handle Batch deletion
  const handleDeleteBatch = async (batchId: string) => {
    if (!window.confirm('Are you sure you want to delete this batch and all its records?')) return;

    try {
      const response = await api.delete(`/bank-verification/batch/${batchId}`);
      showToast({ type: 'success', message: response.data.message });
      setSelectedBatch(null);
      await fetchBatches();
    } catch (error: any) {
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to delete batch'
      });
    }
  };

  // Handle Sample Template download
  const handleDownloadTemplate = async () => {
    try {
      const response = await api.get('/bank-verification/sample-template', {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'sample_bank_verification.xlsx');
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      showToast({ type: 'error', message: 'Failed to download sample template' });
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

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'verified':
        return 'bg-emerald-100 text-emerald-800';
      case 'rejected':
        return 'bg-red-100 text-red-800';
      case 'error':
        return 'bg-amber-100 text-amber-800';
      default:
        return 'bg-slate-100 text-slate-800';
    }
  };

  return (
    <div className="space-y-8">
      {/* Premium Header */}
      <div className="rounded-3xl bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 p-8 text-white shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="rounded-2xl bg-white/20 p-3">
            <CreditCardIcon className="h-8 w-8" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Bank Verification</h1>
            <p className="mt-1 text-blue-100 text-sm font-medium">
              Verify bank account presence and retrieve registered name instantly in single or bulk batches.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => window.location.href = '/bank-verification-records'}
          className="inline-flex items-center px-5 py-2.5 bg-white/20 backdrop-blur-sm hover:bg-white/30 text-white font-semibold rounded-2xl transition-all duration-300 border border-white/30 hover:border-white/50 hover:scale-105 transform self-start md:self-auto shadow-md"
        >
          <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          View All Records
        </button>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white/80 backdrop-blur-sm rounded-3xl p-2 shadow-sm border border-slate-200">
        <nav className="flex space-x-2">
          <button
            onClick={() => handleTabChange('single')}
            className={`py-2 px-6 rounded-2xl font-semibold text-sm transition-all duration-300 ${
              activeTab === 'single'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-600 hover:text-slate-800 hover:bg-slate-50'
            }`}
          >
            <div className="flex items-center space-x-2">
              <DocumentTextIcon className="h-5 w-5" />
              <span>Single Account</span>
            </div>
          </button>
          <button
            onClick={() => handleTabChange('upload')}
            className={`py-2 px-6 rounded-2xl font-semibold text-sm transition-all duration-300 ${
              activeTab === 'upload'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-600 hover:text-slate-800 hover:bg-slate-50'
            }`}
          >
            <div className="flex items-center space-x-2">
              <CloudArrowUpIcon className="h-5 w-5" />
              <span>Bulk verification</span>
            </div>
          </button>
        </nav>
      </div>

      {/* SINGLE VERIFICATION TAB */}
      {activeTab === 'single' && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
          {/* Form */}
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

          {/* Result */}
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
      )}

      {/* BULK UPLOAD TAB CONTENT */}
      {activeTab === 'upload' && (
        <div className="space-y-8">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Upload form card */}
            <div className="lg:col-span-1 bg-white border border-slate-200 rounded-2xl shadow-sm p-6 space-y-6 h-fit">
              <div>
                <h2 className="text-lg font-semibold text-slate-900">Upload bulk data</h2>
                <p className="text-xs text-slate-500 mt-1">
                  Upload an Excel or CSV file (.xlsx, .xls, .csv) to verify bank accounts in bulk.
                </p>
              </div>

              <form onSubmit={handleUpload} className="space-y-4">
                <div className="border-2 border-dashed border-slate-300 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer hover:border-blue-500 transition-colors"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <CloudArrowUpIcon className="h-10 w-10 text-slate-400 mb-2" />
                  <span className="text-sm font-semibold text-slate-700">
                    {selectedFile ? selectedFile.name : 'Select file'}
                  </span>
                  <span className="text-xs text-slate-400 mt-1">
                    {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB` : 'Supports .xlsx, .xls, .csv'}
                  </span>
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    accept=".xlsx,.xls,.csv"
                    className="hidden"
                  />
                </div>

                <div className="flex gap-3">
                  <button
                    type="submit"
                    disabled={!selectedFile || uploading}
                    className="flex-1 inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-60 transition-colors"
                  >
                    {uploading ? 'Uploading…' : 'Upload file'}
                  </button>

                  <button
                    type="button"
                    onClick={handleDownloadTemplate}
                    className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-300 px-4 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
                    title="Download template file"
                  >
                    <DocumentArrowDownIcon className="h-5 w-5" />
                    Template
                  </button>
                </div>
              </form>
            </div>

            {/* Batches Table List */}
            <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden flex flex-col">
              <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-slate-900">Verification batches</h2>
                <button 
                  onClick={fetchBatches}
                  className="rounded-lg p-1.5 hover:bg-slate-100 text-slate-500 hover:text-slate-800 transition-colors"
                >
                  <ArrowPathIcon className="h-5 w-5" />
                </button>
              </div>

              {loadingBatches ? (
                <div className="p-8 text-center text-sm text-slate-500">Loading batches…</div>
              ) : batches.length === 0 ? (
                <div className="p-8 text-center text-sm text-slate-500">No batches uploaded yet.</div>
              ) : (
                <div className="overflow-x-auto flex-1">
                  <table className="w-full text-sm text-left text-slate-600">
                    <thead className="bg-slate-50 text-slate-700 uppercase font-semibold text-xs border-b border-slate-100">
                      <tr>
                        <th className="px-6 py-3">Batch Name/ID</th>
                        <th className="px-6 py-3">Total</th>
                        <th className="px-6 py-3">Status</th>
                        <th className="px-6 py-3">Uploaded</th>
                        <th className="px-6 py-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {batches.map((batch) => {
                        const isSelected = selectedBatch?.batchId === batch._id;
                        return (
                          <tr key={batch._id} 
                            className={`hover:bg-slate-50/50 cursor-pointer ${isSelected ? 'bg-blue-50/30' : ''}`}
                            onClick={() => fetchBatchDetails(batch._id)}
                          >
                            <td className="px-6 py-4 font-semibold text-slate-900 truncate max-w-[200px]" title={batch._id}>
                              {batch._id}
                            </td>
                            <td className="px-6 py-4 font-medium">{batch.totalRecords}</td>
                            <td className="px-6 py-4">
                              <span className="flex items-center gap-1.5">
                                {batch.pendingRecords > 0 ? (
                                  <>
                                    <ClockIcon className="h-4 w-4 text-amber-500" />
                                    <span className="text-xs text-amber-700 font-medium">
                                      {batch.pendingRecords} pending
                                    </span>
                                  </>
                                ) : (
                                  <>
                                    <CheckCircleIcon className="h-4 w-4 text-emerald-500" />
                                    <span className="text-xs text-emerald-700 font-medium">Done</span>
                                  </>
                                )}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-xs text-slate-500">
                              {new Date(batch.createdAt).toLocaleDateString()}
                            </td>
                            <td className="px-6 py-4 text-right" onClick={(e) => e.stopPropagation()}>
                              <div className="flex items-center justify-end gap-2">
                                {batch.pendingRecords > 0 && (
                                  <button
                                    onClick={() => handleProcessBatch(batch._id)}
                                    disabled={processingBatch}
                                    className="p-1 rounded bg-blue-100 hover:bg-blue-200 text-blue-800 disabled:opacity-50 transition-colors"
                                    title="Process Batch verification"
                                  >
                                    <PlayIcon className="h-4 w-4" />
                                  </button>
                                )}
                                <button
                                  onClick={() => handleDeleteBatch(batch._id)}
                                  className="p-1 rounded bg-red-100 hover:bg-red-200 text-red-800 transition-colors"
                                  title="Delete batch"
                                >
                                  <TrashIcon className="h-4 w-4" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* Selected Batch Record Details */}
          {selectedBatch && (
            <div className="bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden space-y-4 p-6">
              <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                <div>
                  <h3 className="text-lg font-semibold text-slate-900">Batch details</h3>
                  <p className="text-xs text-slate-500 mt-0.5">ID: {selectedBatch.batchId}</p>
                </div>

                <div className="flex items-center gap-2">
                  {selectedBatch.stats.pending > 0 && (
                    <button
                      onClick={() => handleProcessBatch(selectedBatch.batchId)}
                      disabled={processingBatch}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-50 transition-colors"
                    >
                      <PlayIcon className="h-4 w-4" />
                      {processingBatch ? 'Processing…' : 'Process batch'}
                    </button>
                  )}
                  <button
                    onClick={() => handleDeleteBatch(selectedBatch.batchId)}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-red-300 text-red-600 hover:bg-red-50 px-4 py-2 text-sm font-semibold transition-colors"
                  >
                    <TrashIcon className="h-4 w-4" />
                    Delete
                  </button>
                </div>
              </div>

              {/* Progress Summary Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
                <div className="rounded-xl border border-slate-100 bg-slate-50/50 p-3 text-center">
                  <div className="text-xs font-semibold text-slate-500 uppercase">Total</div>
                  <div className="text-xl font-bold text-slate-800 mt-1">{selectedBatch.stats.total}</div>
                </div>
                <div className="rounded-xl border border-amber-100 bg-amber-50/20 p-3 text-center">
                  <div className="text-xs font-semibold text-amber-500 uppercase">Pending</div>
                  <div className="text-xl font-bold text-amber-600 mt-1">{selectedBatch.stats.pending}</div>
                </div>
                <div className="rounded-xl border border-emerald-100 bg-emerald-50/20 p-3 text-center">
                  <div className="text-xs font-semibold text-emerald-500 uppercase">Verified</div>
                  <div className="text-xl font-bold text-emerald-600 mt-1">{selectedBatch.stats.verified}</div>
                </div>
                <div className="rounded-xl border border-red-100 bg-red-50/20 p-3 text-center">
                  <div className="text-xs font-semibold text-red-500 uppercase">Rejected</div>
                  <div className="text-xl font-bold text-red-600 mt-1">{selectedBatch.stats.rejected}</div>
                </div>
                <div className="rounded-xl border border-amber-100 bg-amber-50/20 p-3 text-center">
                  <div className="text-xs font-semibold text-amber-650 uppercase">Error</div>
                  <div className="text-xl font-bold text-amber-600 mt-1">{selectedBatch.stats.error}</div>
                </div>
              </div>

              {/* Detailed record rows */}
              {loadingBatchDetails ? (
                <div className="p-8 text-center text-sm text-slate-500">Loading batch details…</div>
              ) : (
                <div className="overflow-x-auto border border-slate-150 rounded-xl mt-4">
                  <table className="w-full text-sm text-left text-slate-600">
                    <thead className="bg-slate-50 text-slate-700 uppercase font-semibold text-xs border-b border-slate-100">
                      <tr>
                        <th className="px-6 py-3">Account Number</th>
                        <th className="px-6 py-3">IFSC Code</th>
                        <th className="px-6 py-3">Holder Name</th>
                        <th className="px-6 py-3">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {selectedBatch.records.map((record) => (
                        <tr key={record._id} className="hover:bg-slate-50/50">
                          <td className="px-6 py-4 font-semibold text-slate-900">{record.accountNumber}</td>
                          <td className="px-6 py-4 text-slate-700 font-medium">{record.ifsc}</td>
                          <td className="px-6 py-4 font-medium text-slate-900">{record.nameAtBank || '—'}</td>
                          <td className="px-6 py-4">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold uppercase ${getStatusBadgeClass(record.status)}`}>
                              {record.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default BankVerification;

import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../contexts/ToastContext';
import api, { HEAVY_REQUEST_TIMEOUT_MS } from '../../services/api';
import { downloadReport, type ReportExportFormat } from '../../utils/exportReport';
import ExportReportButtons from '../../components/ExportReportButtons';
import RecordDateRangeFilters, { type DateFilterPreset } from '../../components/RecordDateRangeFilters';
import { 
  MagnifyingGlassIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  DocumentTextIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';

interface BankVerificationRecord {
  _id: string;
  batchId: string;
  ifsc: string;
  accountNumber: string;
  status: 'pending' | 'verified' | 'rejected' | 'error';
  nameAtBank?: string;
  accountExists?: boolean;
  processingTime?: number;
  createdAt: string;
  updatedAt: string;
  errorMessage?: string;
}

interface RecordsStats {
  total: number;
  pending: number;
  verified: number;
  rejected: number;
  error: number;
}

interface RecordsPagination {
  currentPage: number;
  totalPages: number;
  totalRecords: number;
  limit: number;
}

const BankVerificationRecords: React.FC = () => {
  const { user, isAuthenticated } = useAuth();
  const { showToast } = useToast();

  const [records, setRecords] = useState<BankVerificationRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [stats, setStats] = useState<RecordsStats>({
    total: 0,
    pending: 0,
    verified: 0,
    rejected: 0,
    error: 0
  });
  const [pagination, setPagination] = useState<RecordsPagination>({
    currentPage: 1,
    totalPages: 1,
    totalRecords: 0,
    limit: 20
  });

  const recordsPerPage = 20;
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [dateFilter, setDateFilter] = useState<DateFilterPreset>('all');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  const fetchRecords = async (page: number = pagination.currentPage) => {
    if (!isAuthenticated || !user) {
      showToast({ message: 'Please log in to view records', type: 'error' });
      return;
    }
    if (loading) return;
    try {
      setLoading(true);
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('limit', String(recordsPerPage));
      if (statusFilter !== 'all') params.set('status', statusFilter);
      if (dateFilter !== 'all') params.set('dateFilter', dateFilter);
      if (dateFrom) params.set('dateFrom', dateFrom);
      if (dateTo) params.set('dateTo', dateTo);
      const response = await api.get(`/bank-verification/records?${params.toString()}`);
      const res = response.data;
      if (res.success) {
        const data = res.data?.records || [];
        setRecords(data);

        if (res.data?.pagination) {
          setPagination({
            currentPage: res.data.pagination.page,
            totalPages: res.data.pagination.pages,
            totalRecords: res.data.pagination.total,
            limit: res.data.pagination.limit
          });
        } else {
          setPagination({
            currentPage: 1,
            totalPages: 1,
            totalRecords: data.length,
            limit: recordsPerPage
          });
        }

        // Calculate stats client-side since API returns full total in pagination
        const total = res.data?.pagination?.total || data.length;
        setStats({
          total: total,
          pending: data.filter((r: BankVerificationRecord) => r.status === 'pending').length,
          verified: data.filter((r: BankVerificationRecord) => r.status === 'verified').length,
          rejected: data.filter((r: BankVerificationRecord) => r.status === 'rejected').length,
          error: data.filter((r: BankVerificationRecord) => r.status === 'error').length
        });
      }
    } catch (error: any) {
      showToast({ message: 'Failed to fetch records', type: 'error' });
      console.error('Error fetching records:', error);
    } finally {
      setLoading(false);
    }
  };

  const refreshRecords = () => fetchRecords(pagination.currentPage);

  useEffect(() => {
    if (!isAuthenticated || !user) return;
    fetchRecords(1);
  }, [isAuthenticated, user, statusFilter, dateFilter, dateFrom, dateTo]);

  const handlePageChange = (page: number) => {
    if (page < 1 || page > pagination.totalPages) return;
    fetchRecords(page);
  };

  const filteredRecords = records.filter(record => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    return (
      record.accountNumber?.toLowerCase().includes(term) ||
      record.ifsc?.toLowerCase().includes(term) ||
      record.nameAtBank?.toLowerCase().includes(term) ||
      record.batchId?.toLowerCase().includes(term)
    );
  });

  const EXPORT_CAP = 200;

  const handleExport = async (format: ReportExportFormat) => {
    if (!isAuthenticated || !user) {
      showToast({ message: 'Please log in to export', type: 'error' });
      return;
    }
    try {
      setExporting(true);
      const params = new URLSearchParams();
      params.set('export', '1');
      params.set('limit', String(EXPORT_CAP));
      if (statusFilter !== 'all') params.set('status', statusFilter);
      if (dateFilter !== 'all') params.set('dateFilter', dateFilter);
      if (dateFrom) params.set('dateFrom', dateFrom);
      if (dateTo) params.set('dateTo', dateTo);
      const response = await api.get(`/bank-verification/records?${params.toString()}`, {
        timeout: HEAVY_REQUEST_TIMEOUT_MS
      });
      const res = response.data;
      if (!res.success || !res.data?.records) {
        showToast({ message: 'Failed to load records for export', type: 'error' });
        return;
      }
      let rows: BankVerificationRecord[] = res.data.records;
      const totalMatching = res.data.pagination?.total ?? rows.length;
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        rows = rows.filter(
          (record) =>
            record.accountNumber?.toLowerCase().includes(term) ||
            record.ifsc?.toLowerCase().includes(term) ||
            record.nameAtBank?.toLowerCase().includes(term) ||
            record.batchId?.toLowerCase().includes(term)
        );
      }
      if (rows.length === 0) {
        showToast({ message: 'No records to export', type: 'error' });
        return;
      }
      const headers = [
        'Batch ID',
        'Account Number',
        'IFSC Code',
        'Holder Name',
        'Account Exists',
        'Status',
        'Processing Time (ms)',
        'Created At',
        'ErrorMessage'
      ];
      const matrix: string[][] = rows.map((record) => [
        record.batchId,
        record.accountNumber,
        record.ifsc,
        record.nameAtBank || '',
        record.accountExists ? 'Yes' : 'No',
        record.status,
        String(record.processingTime ?? ''),
        new Date(record.createdAt).toLocaleString(),
        record.errorMessage || ''
      ]);
      const jsonPayload = rows.map((r) => ({
        batchId: r.batchId,
        accountNumber: r.accountNumber,
        ifsc: r.ifsc,
        nameAtBank: r.nameAtBank || '',
        accountExists: r.accountExists,
        status: r.status,
        processingTime: r.processingTime,
        createdAt: r.createdAt,
        errorMessage: r.errorMessage || ''
      }));
      downloadReport('bank-verification-records', format, headers, matrix, 'Bank Verification', jsonPayload);
      const hitExportCap = !searchTerm.trim() && totalMatching > EXPORT_CAP;
      const fmt = format === 'xls' ? 'Excel' : format.toUpperCase();
      showToast({
        message: hitExportCap
          ? `${fmt}: first ${rows.length} of ${totalMatching} records (export limit ${EXPORT_CAP})`
          : `${fmt} downloaded (${rows.length} record${rows.length === 1 ? '' : 's'})`,
        type: 'success'
      });
    } catch (error: any) {
      console.error('Export failed:', error);
      showToast({ message: 'Failed to export records', type: 'error' });
    } finally {
      setExporting(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'verified':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'rejected':
      case 'error':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
      default:
        return <ClockIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'verified':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'rejected':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'error':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="container mx-auto px-4 py-8 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <DocumentTextIcon className="h-7 w-7 text-purple-600" />
            Bank Verification Log
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            View, filter, and export historical bank account check logs.
          </p>
        </div>
        <div className="flex items-center gap-2 self-start md:self-auto">
          <ExportReportButtons exporting={exporting} onExport={handleExport} />
          <button
            onClick={refreshRecords}
            disabled={loading}
            className="p-2 rounded-lg border border-gray-300 hover:bg-gray-50 text-gray-600 disabled:opacity-50 transition-colors"
            title="Refresh records"
          >
            <ArrowPathIcon className={`h-5 w-5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-semibold text-gray-500 uppercase">Total Hits</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{stats.total}</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-semibold text-green-600 uppercase">Verified</div>
          <div className="text-2xl font-bold text-green-600 mt-1">{stats.verified}</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-semibold text-red-600 uppercase">Rejected</div>
          <div className="text-xl font-bold text-red-600 mt-1">{stats.rejected}</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-semibold text-yellow-600 uppercase">Errors</div>
          <div className="text-xl font-bold text-yellow-600 mt-1">{stats.error}</div>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-4 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center gap-4 justify-between">
          <div className="flex-1 max-w-md relative">
            <MagnifyingGlassIcon className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search account, IFSC, name or batch..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
            />
          </div>
          <div className="flex items-center gap-3">
            <label className="text-sm font-medium text-gray-700">Status</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
            >
              <option value="all">All</option>
              <option value="verified">Verified</option>
              <option value="rejected">Rejected</option>
              <option value="error">Error</option>
              <option value="pending">Pending</option>
            </select>
          </div>
        </div>

        <RecordDateRangeFilters
          accent="indigo"
          dateFilter={dateFilter}
          dateFrom={dateFrom}
          dateTo={dateTo}
          onChange={(vals) => {
            setDateFilter(vals.dateFilter);
            setDateFrom(vals.dateFrom);
            setDateTo(vals.dateTo);
          }}
          onClear={() => {
            setDateFilter('all');
            setDateFrom('');
            setDateTo('');
          }}
        />
      </div>

      {/* Main Table */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-sm text-gray-500">
            <ArrowPathIcon className="h-8 w-8 animate-spin mx-auto text-purple-600 mb-2" />
            Loading verification logs...
          </div>
        ) : filteredRecords.length === 0 ? (
          <div className="p-12 text-center text-sm text-gray-500">
            No records found matching filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left text-gray-600">
              <thead className="bg-gray-50 text-gray-700 uppercase font-semibold text-xs border-b border-gray-200">
                <tr>
                  <th className="px-6 py-3">Account Number</th>
                  <th className="px-6 py-3">IFSC Code</th>
                  <th className="px-6 py-3">Holder Name</th>
                  <th className="px-6 py-3">Exists</th>
                  <th className="px-6 py-3">Status</th>
                  <th className="px-6 py-3">Processed</th>
                  <th className="px-6 py-3">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-150">
                {filteredRecords.map((record) => (
                  <tr key={record._id} className="hover:bg-gray-50/50">
                    <td className="px-6 py-4 font-semibold text-gray-900">{record.accountNumber}</td>
                    <td className="px-6 py-4 font-mono text-xs">{record.ifsc}</td>
                    <td className="px-6 py-4 font-medium text-gray-800">{record.nameAtBank || '—'}</td>
                    <td className="px-6 py-4 text-xs font-semibold">
                      {record.accountExists !== undefined ? (record.accountExists ? 'Yes' : 'No') : '—'}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getStatusColor(record.status)}`}>
                        {getStatusIcon(record.status)}
                        {record.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs text-gray-500">
                      {new Date(record.createdAt).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-xs text-gray-500">
                      {record.processingTime ? `${record.processingTime} ms` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        {pagination.totalPages > 1 && (
          <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between">
            <span className="text-xs text-gray-500">
              Showing page {pagination.currentPage} of {pagination.totalPages} ({pagination.totalRecords} total records)
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => handlePageChange(pagination.currentPage - 1)}
                disabled={pagination.currentPage === 1}
                className="px-3 py-1.5 border border-gray-300 rounded-lg text-xs font-medium hover:bg-gray-50 disabled:opacity-50 transition-colors"
              >
                Previous
              </button>
              <button
                onClick={() => handlePageChange(pagination.currentPage + 1)}
                disabled={pagination.currentPage === pagination.totalPages}
                className="px-3 py-1.5 border border-gray-300 rounded-lg text-xs font-medium hover:bg-gray-50 disabled:opacity-50 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default BankVerificationRecords;

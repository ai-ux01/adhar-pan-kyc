import React, { useState, useEffect, useRef } from 'react';
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
  ExclamationTriangleIcon,
  ClockIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

interface AadhaarPanRecord {
  _id: string;
  batchId: string;
  aadhaarNumber: string;
  panNumber: string;
  name: string;
  fatherName?: string;
  dateOfBirth?: string;
  gender?: string;
  status: 'linked' | 'not-linked' | 'pending' | 'invalid' | 'error';
  linkingDetails?: {
    apiResponse?: any;
    linkingDate?: string;
    linkingStatus?: string;
    remarks?: string;
    lastChecked?: string;
  };
  apiAttempts?: Array<{
    timestamp: string;
    status: 'success' | 'failed' | 'timeout';
    response?: any;
    error?: string;
  }>;
  fileUpload?: {
    originalName: string;
    fileName: string;
    fileSize: number;
    uploadDate: string;
  };
  processingTime?: number;
  retryCount?: number;
  lastRetryAt?: string;
  isProcessed: boolean;
  processedAt?: string;
  errorMessage?: string;
  createdAt: string;
  updatedAt: string;
}

interface RecordsStats {
  total: number;
  linked: number;
  'not-linked': number;
  pending?: number;
  invalid?: number;
  error?: number;
}

const AadhaarPanRecords: React.FC = () => {
  const { user, isAuthenticated } = useAuth();
  const { showToast } = useToast();
  const [records, setRecords] = useState<AadhaarPanRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [stats, setStats] = useState<RecordsStats>({
    total: 0,
    linked: 0,
    'not-linked': 0
  });
  
  const [pagination, setPagination] = useState({
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

  const fetchRecords = async (
    page: number = pagination.currentPage,
    searchOverride?: string
  ) => {
    if (!isAuthenticated || !user) {
      showToast({ message: 'Please log in to view records', type: 'error' });
      return;
    }
    if (loading) return;

    const searchQuery = searchOverride !== undefined ? searchOverride : searchTerm;

    try {
      setLoading(true);
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('limit', String(recordsPerPage));
      if (statusFilter !== 'all') params.set('status', statusFilter);
      if (dateFilter !== 'all') params.set('dateFilter', dateFilter);
      if (dateFrom) params.set('dateFrom', dateFrom);
      if (dateTo) params.set('dateTo', dateTo);
      if (searchQuery.trim()) params.set('search', searchQuery.trim());

      const response = await api.get(`/aadhaar-pan/records?${params.toString()}`);
      const res = response.data;
      if (res.success) {
        setRecords(res.data || []);
        if (res.pagination) {
          setPagination({
            currentPage: res.pagination.currentPage,
            totalPages: res.pagination.totalPages,
            totalRecords: res.pagination.totalRecords,
            limit: res.pagination.limit
          });
        }
        if (res.stats) {
          setStats({
            total: res.stats.total ?? 0,
            linked: res.stats.linked ?? 0,
            'not-linked': res.stats['not-linked'] ?? 0,
            pending: res.stats.pending ?? 0,
            invalid: res.stats.invalid ?? 0,
            error: res.stats.error ?? 0
          });
        }
      }
    } catch (error: any) {
      if (error.response?.status === 401) {
        showToast({ message: 'Authentication failed. Please log in again.', type: 'error' });
      } else {
        showToast({ message: 'Failed to fetch records', type: 'error' });
      }
      console.error('Error fetching records:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!isAuthenticated || !user) return;
    fetchRecords(1);
  }, [isAuthenticated, user, statusFilter, dateFilter, dateFrom, dateTo]);

  const searchDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleSearchChange = (value: string) => {
    setSearchTerm(value);
    if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current);
    searchDebounceRef.current = setTimeout(() => {
      fetchRecords(1, value);
    }, 400);
  };

  const handlePageChange = (page: number) => {
    if (page < 1 || page > pagination.totalPages) return;
    fetchRecords(page);
  };

  const paginatedRecords = records;
  const totalPages = pagination.totalPages;

  const EXPORT_CAP = 200;

  const handleExport = async (format: ReportExportFormat) => {
    if (!isAuthenticated || !user) {
      showToast({ message: 'Please log in to export', type: 'error' });
      return;
    }
    setExporting(true);
    try {
      const params = new URLSearchParams();
      params.set('export', '1');
      params.set('limit', String(EXPORT_CAP));
      if (statusFilter !== 'all') params.set('status', statusFilter);
      if (dateFilter !== 'all') params.set('dateFilter', dateFilter);
      if (dateFrom) params.set('dateFrom', dateFrom);
      if (dateTo) params.set('dateTo', dateTo);
      if (searchTerm.trim()) params.set('search', searchTerm.trim());

      const response = await api.get(`/aadhaar-pan/records?${params.toString()}`, {
        timeout: HEAVY_REQUEST_TIMEOUT_MS
      });
      const res = response.data;
      if (!res.success || !Array.isArray(res.data) || res.data.length === 0) {
        showToast({ message: 'No records to export', type: 'error' });
        return;
      }
      const rows: AadhaarPanRecord[] = res.data;
      const headers = [
        'Batch ID',
        'Aadhaar Number',
        'PAN Number',
        'Name',
        'Father Name',
        'Date of Birth',
        'Gender',
        'Status',
        'Processing Time (ms)',
        'Retry Count',
        'Created At',
        'Processed At',
        'Error Message'
      ];
      const matrix: string[][] = rows.map((record) => [
        record.batchId,
        record.aadhaarNumber,
        record.panNumber,
        record.name,
        record.fatherName || '',
        record.dateOfBirth || '',
        record.gender || '',
        record.status,
        String(record.processingTime ?? ''),
        String(record.retryCount ?? 0),
        new Date(record.createdAt).toLocaleString(),
        record.processedAt ? new Date(record.processedAt).toLocaleString() : '',
        record.errorMessage || ''
      ]);
      const jsonPayload = rows.map((r) => ({
        batchId: r.batchId,
        aadhaarNumber: r.aadhaarNumber,
        panNumber: r.panNumber,
        name: r.name,
        fatherName: r.fatherName || '',
        dateOfBirth: r.dateOfBirth || '',
        gender: r.gender || '',
        status: r.status,
        processingTime: r.processingTime,
        retryCount: r.retryCount,
        createdAt: r.createdAt,
        processedAt: r.processedAt || '',
        errorMessage: r.errorMessage || ''
      }));
      downloadReport('aadhaar-pan-records', format, headers, matrix, 'Aadhaar PAN', jsonPayload);
      const fmt = format === 'xls' ? 'Excel' : format.toUpperCase();
      const totalMatching = res.pagination?.totalRecords ?? rows.length;
      const hitExportCap = totalMatching > EXPORT_CAP;
      showToast({
        message: hitExportCap
          ? `${fmt}: first ${rows.length} of ${totalMatching} records (export limit ${EXPORT_CAP})`
          : `${fmt} downloaded (${rows.length} record${rows.length === 1 ? '' : 's'})`,
        type: 'success'
      });
    } catch (error: any) {
      console.error('Export failed:', error);
      showToast({ message: 'Failed to export', type: 'error' });
    } finally {
      setExporting(false);
    }
  };

  // Get status icon and color
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'linked':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'not-linked':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
      case 'invalid':
      case 'error':
        return <ExclamationTriangleIcon className="h-5 w-5 text-amber-500" />;
      case 'pending':
        return <ClockIcon className="h-5 w-5 text-gray-500" />;
      default:
        return <ClockIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'linked':
        return 'bg-green-100 text-green-800';
      case 'not-linked':
        return 'bg-red-100 text-red-800';
      case 'invalid':
      case 'error':
        return 'bg-amber-100 text-amber-800';
      case 'pending':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  // Format date
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="space-y-6">
      {/* Enhanced Header */}
      <div className="bg-gradient-to-br from-emerald-500 via-teal-600 to-cyan-700 rounded-3xl p-8 text-white shadow-2xl relative overflow-hidden">
        {/* Background Pattern */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-white/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-0 left-0 w-40 h-40 bg-white/5 rounded-full blur-3xl"></div>
        
        <div className="relative z-10">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center mb-3">
                <div className="w-12 h-12 bg-white/20 rounded-2xl flex items-center justify-center mr-4">
                  <DocumentTextIcon className="h-7 w-7 text-white" />
                </div>
                <h1 className="text-3xl font-bold">Aadhaar-PAN Linking Records</h1>
              </div>
              <p className="text-emerald-100 text-lg">
                View and manage all Aadhaar-PAN linking verification records
              </p>
            </div>
            <div className="flex space-x-3">
              <button
                onClick={() => fetchRecords(pagination.currentPage)}
                disabled={loading}
                className="inline-flex items-center px-6 py-3 bg-white/20 backdrop-blur-sm hover:bg-white/30 text-white font-semibold rounded-2xl transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-white/50 hover:scale-105 transform border border-white/30 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
              >
                {loading ? (
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2"></div>
                ) : (
                  <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                )}
                Refresh
              </button>
              <ExportReportButtons
                exporting={exporting}
                onExport={handleExport}
                variant="light"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Enhanced Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-all duration-300 transform hover:scale-105">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl flex items-center justify-center mr-4">
              <DocumentTextIcon className="h-6 w-6 text-white" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Total Records</p>
              <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-all duration-300 transform hover:scale-105">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl flex items-center justify-center mr-4">
              <CheckCircleIcon className="h-6 w-6 text-white" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Operative</p>
              <p className="text-2xl font-bold text-emerald-600">{stats.linked}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-all duration-300 transform hover:scale-105">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-gradient-to-br from-red-500 to-pink-600 rounded-xl flex items-center justify-center mr-4">
              <XCircleIcon className="h-6 w-6 text-white" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Inoperative</p>
              <p className="text-2xl font-bold text-red-600">{stats['not-linked']}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100">
        <div className="flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1 min-w-0">
              <MagnifyingGlassIcon className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search by Aadhaar, PAN, Name, or Batch ID..."
                value={searchTerm}
                onChange={(e) => handleSearchChange(e.target.value)}
                className="w-full pl-12 pr-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all duration-200"
              />
            </div>
            <div className="w-full sm:w-44 shrink-0">
              <label className="block text-xs font-medium text-gray-600 mb-1 sm:sr-only">
                Status
              </label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all duration-200"
              >
                <option value="all">All Statuses</option>
                <option value="linked">Operative</option>
                <option value="not-linked">Inoperative</option>
                <option value="pending">Pending</option>
                <option value="invalid">Invalid</option>
                <option value="error">Error</option>
              </select>
            </div>
          </div>
          <RecordDateRangeFilters
            accent="emerald"
            dateFilter={dateFilter}
            onDateFilterChange={setDateFilter}
            dateFrom={dateFrom}
            dateTo={dateTo}
            onDateFromChange={setDateFrom}
            onDateToChange={setDateTo}
            onClear={() => {
              setDateFilter('all');
              setDateFrom('');
              setDateTo('');
            }}
          />
        </div>
      </div>

      {/* Enhanced Records Table */}
      <div className="bg-white rounded-2xl shadow-lg overflow-hidden border border-gray-100">
        <div className="px-6 py-6 border-b border-gray-100 bg-gradient-to-r from-emerald-50 to-teal-50">
          <h3 className="text-xl font-semibold text-emerald-800">
            Records ({pagination.totalRecords})
          </h3>
        </div>

        {loading ? (
          <div className="p-12 text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-emerald-600 mx-auto mb-4"></div>
            <p className="text-lg text-emerald-700">Loading records...</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-gradient-to-r from-emerald-50 to-teal-50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-emerald-700 uppercase tracking-wider">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-emerald-500 rounded-full"></div>
                        <span>Basic Info</span>
                      </div>
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-emerald-700 uppercase tracking-wider">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-emerald-500 rounded-full"></div>
                        <span>Status</span>
                      </div>
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-emerald-700 uppercase tracking-wider">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-emerald-500 rounded-full"></div>
                        <span>Timestamps</span>
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {paginatedRecords.map((record) => (
                    <tr key={record._id} className="hover:bg-gradient-to-r hover:from-emerald-50/50 hover:to-teal-50/50 transition-all duration-200">
                      {/* Basic Info */}
                      <td className="px-6 py-4">
                        <div className="space-y-1">
                          <div className="text-sm font-medium text-gray-900">
                            {record.name}
                          </div>
                          <div className="text-sm text-gray-500">
                            Aadhaar: {record.aadhaarNumber}
                          </div>
                          <div className="text-sm text-gray-500">
                            PAN: {record.panNumber}
                          </div>
                          {record.fatherName && (
                            <div className="text-sm text-gray-500">
                              Father: {record.fatherName}
                            </div>
                          )}
                          {record.dateOfBirth && (
                            <div className="text-sm text-gray-500">
                              DOB: {record.dateOfBirth}
                            </div>
                          )}
                          {record.gender && (
                            <div className="text-sm text-gray-500">
                              Gender: {record.gender}
                            </div>
                          )}
                        </div>
                      </td>

                      {/* Status */}
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          {getStatusIcon(record.status)}
                          <span className={`ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(record.status)}`}>
                            {record.status === 'linked' ? 'Operative' : 'Inoperative'}
                          </span>
                        </div>
                        {record.errorMessage && (
                          <div className="mt-1 text-xs text-red-600 max-w-xs truncate" title={record.errorMessage}>
                            {record.errorMessage}
                          </div>
                        )}
                      </td>

                      {/* Timestamps */}
                      <td className="px-6 py-4">
                        <div className="space-y-1">
                          <div className="text-sm text-gray-500">
                            Created: {formatDate(record.createdAt)}
                          </div>
                          {record.processedAt && (
                            <div className="text-sm text-gray-500">
                              Processed: {formatDate(record.processedAt)}
                            </div>
                          )}
                          {record.linkingDetails?.lastChecked && (
                            <div className="text-sm text-gray-500">
                              Last checked: {formatDate(record.linkingDetails.lastChecked)}
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Enhanced Pagination */}
            {totalPages > 1 && (
              <div className="px-6 py-6 border-t border-gray-100 bg-gradient-to-r from-emerald-50 to-teal-50">
                <div className="flex items-center justify-between">
                  <div className="text-sm text-emerald-700">
                    Showing <span className="font-semibold">{((pagination.currentPage - 1) * recordsPerPage) + 1}</span> to{' '}
                    <span className="font-semibold">{Math.min(pagination.currentPage * recordsPerPage, pagination.totalRecords)}</span> of{' '}
                    <span className="font-semibold">{pagination.totalRecords}</span> records
                  </div>
                  <div className="flex items-center space-x-3">
                    <button
                      onClick={() => handlePageChange(pagination.currentPage - 1)}
                      disabled={pagination.currentPage === 1}
                      className="px-4 py-2 text-sm font-medium border border-emerald-300 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed hover:bg-emerald-50 transition-colors duration-200"
                    >
                      Previous
                    </button>
                    <span className="px-4 py-2 text-sm font-medium text-emerald-700 bg-white rounded-xl border border-emerald-200">
                      {pagination.currentPage} of {totalPages}
                    </span>
                    <button
                      onClick={() => handlePageChange(pagination.currentPage + 1)}
                      disabled={pagination.currentPage === totalPages}
                      className="px-4 py-2 text-sm font-medium border border-emerald-300 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed hover:bg-emerald-50 transition-colors duration-200"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default AadhaarPanRecords;

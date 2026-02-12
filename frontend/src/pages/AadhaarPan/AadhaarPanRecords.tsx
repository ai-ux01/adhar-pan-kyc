import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../contexts/ToastContext';
import api from '../../services/api';
import { 
  MagnifyingGlassIcon,
  ArrowDownTrayIcon,
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
  status: 'linked' | 'not-linked';
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
}

const AadhaarPanRecords: React.FC = () => {
  const { user, isAuthenticated } = useAuth();
  const { showToast } = useToast();
  const [records, setRecords] = useState<AadhaarPanRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<RecordsStats>({
    total: 0,
    linked: 0,
    'not-linked': 0
  });
  
  // Ref to track if we've already fetched records to prevent multiple API calls
  const hasFetchedRecords = useRef(false);

  // Pagination and search
  const [currentPage, setCurrentPage] = useState(1);
  const [recordsPerPage] = useState(20);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [dateFilter, setDateFilter] = useState<string>('all');

  // Fetch all records
  const fetchRecords = async () => {
    // Check if user is authenticated
    if (!isAuthenticated || !user) {
      showToast({
        message: 'Please log in to view records',
        type: 'error'
      });
      return;
    }

    // Prevent multiple API calls
    if (hasFetchedRecords.current || loading) {
      return;
    }

    try {
      setLoading(true);
      hasFetchedRecords.current = true;
      const response = await api.get('/aadhaar-pan/records');
      if (response.data.success) {
        setRecords(response.data.data);
        calculateStats(response.data.data);
      }
    } catch (error: any) {
      hasFetchedRecords.current = false; // Reset on error so we can retry
      if (error.response?.status === 401) {
        showToast({
          message: 'Authentication failed. Please log in again.',
          type: 'error'
        });
        console.error('Authentication error:', error);
      } else {
        showToast({
          message: 'Failed to fetch records',
          type: 'error'
        });
        console.error('Error fetching records:', error);
      }
    } finally {
      setLoading(false);
    }
  };

  // Calculate statistics
  const calculateStats = (data: AadhaarPanRecord[]) => {
    const linked = data.filter(r => r.status === 'linked').length;
    const notLinked = data.filter(r => r.status === 'not-linked').length;
    const stats = {
      total: linked + notLinked,
      linked: linked,
      'not-linked': notLinked
    };
    setStats(stats);
  };

  // Filter records based on search and filters
  const filteredRecords = records.filter(record => {
    // Only show records with valid statuses (linked or not-linked)
    const hasValidStatus = record.status === 'linked' || record.status === 'not-linked';
    
    const matchesSearch = 
      record.aadhaarNumber?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      record.panNumber?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      record.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      record.batchId?.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesStatus = statusFilter === 'all' || record.status === statusFilter;
    
    let matchesDate = true;
    if (dateFilter !== 'all') {
      const recordDate = new Date(record.createdAt);
      const now = new Date();
      const diffDays = Math.floor((now.getTime() - recordDate.getTime()) / (1000 * 60 * 60 * 24));
      
      switch (dateFilter) {
        case 'today':
          matchesDate = diffDays === 0;
          break;
        case 'week':
          matchesDate = diffDays <= 7;
          break;
        case 'month':
          matchesDate = diffDays <= 30;
          break;
      }
    }
    
    return hasValidStatus && matchesSearch && matchesStatus && matchesDate;
  });

  // Pagination
  const totalPages = Math.ceil(filteredRecords.length / recordsPerPage);
  const paginatedRecords = filteredRecords.slice(
    (currentPage - 1) * recordsPerPage,
    currentPage * recordsPerPage
  );

  // Download CSV
  const downloadCSV = () => {
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

    const csvContent = [
      headers.join(','),
      ...filteredRecords.map(record => [
        record.batchId,
        record.aadhaarNumber,
        record.panNumber,
        record.name,
        record.fatherName || '',
        record.dateOfBirth || '',
        record.gender || '',
        record.status,
        record.processingTime || '',
        record.retryCount || 0,
        new Date(record.createdAt).toLocaleString(),
        record.processedAt ? new Date(record.processedAt).toLocaleString() : '',
        record.errorMessage || ''
      ].join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aadhaar-pan-records-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
    showToast({
      message: 'CSV downloaded successfully',
      type: 'success'
    });
  };

  // Get status icon and color
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'linked':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'not-linked':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
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

  // Reset fetch flag when user changes
  useEffect(() => {
    hasFetchedRecords.current = false;
  }, [user?._id]);

  useEffect(() => {
    if (isAuthenticated && user && !hasFetchedRecords.current) {
      fetchRecords();
    }
  }, [isAuthenticated, user]);

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
                onClick={() => {
                  hasFetchedRecords.current = false;
                  fetchRecords();
                }}
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
              <button
                onClick={downloadCSV}
                className="inline-flex items-center px-6 py-3 bg-white/20 backdrop-blur-sm hover:bg-white/30 text-white font-semibold rounded-2xl transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-white/50 hover:scale-105 transform border border-white/30"
              >
                <ArrowDownTrayIcon className="h-5 w-5 mr-2" />
                Download CSV
              </button>
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

      {/* Enhanced Filters and Search */}
      <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100">
        <div className="flex flex-col lg:flex-row gap-6">
          {/* Search */}
          <div className="flex-1">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search by Aadhaar, PAN, Name, or Batch ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-12 pr-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all duration-200"
              />
            </div>
          </div>

          {/* Status Filter */}
          <div className="lg:w-48">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all duration-200"
            >
              <option value="all">All Statuses</option>
              <option value="linked">Operative</option>
              <option value="not-linked">Inoperative</option>
            </select>
          </div>

          {/* Date Filter */}
          <div className="lg:w-48">
            <select
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all duration-200"
            >
              <option value="all">All Time</option>
              <option value="today">Today</option>
              <option value="week">This Week</option>
              <option value="month">This Month</option>
            </select>
          </div>
        </div>
      </div>

      {/* Enhanced Records Table */}
      <div className="bg-white rounded-2xl shadow-lg overflow-hidden border border-gray-100">
        <div className="px-6 py-6 border-b border-gray-100 bg-gradient-to-r from-emerald-50 to-teal-50">
          <h3 className="text-xl font-semibold text-emerald-800">
            Records ({filteredRecords.length})
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
                    Showing <span className="font-semibold">{((currentPage - 1) * recordsPerPage) + 1}</span> to{' '}
                    <span className="font-semibold">{Math.min(currentPage * recordsPerPage, filteredRecords.length)}</span> of{' '}
                    <span className="font-semibold">{filteredRecords.length}</span> records
                  </div>
                  <div className="flex items-center space-x-3">
                    <button
                      onClick={() => setCurrentPage(currentPage - 1)}
                      disabled={currentPage === 1}
                      className="px-4 py-2 text-sm font-medium border border-emerald-300 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed hover:bg-emerald-50 transition-colors duration-200"
                    >
                      Previous
                    </button>
                    <span className="px-4 py-2 text-sm font-medium text-emerald-700 bg-white rounded-xl border border-emerald-200">
                      {currentPage} of {totalPages}
                    </span>
                    <button
                      onClick={() => setCurrentPage(currentPage + 1)}
                      disabled={currentPage === totalPages}
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

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
  EyeIcon,
  DocumentTextIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';

interface PanKycRecord {
  _id: string;
  batchId: string;
  panNumber: string;
  name: string;
  fatherName?: string;
  dateOfBirth?: string;
  status: 'pending' | 'verified' | 'rejected' | 'error';
  verificationResult?: any;
  processedAt?: string;
  processingTime?: number;
  fileUpload?: {
    originalName: string;
    fileName: string;
    fileSize: number;
    uploadDate: string;
  };
  createdAt: string;
  updatedAt: string;
}

interface RecordsStats {
  total: number;
  pending: number;
  verified: number;
  rejected: number;
  error: number;
}

const PanKycRecords: React.FC = () => {
  const { user, isAuthenticated } = useAuth();
  const { showToast } = useToast();

  // Add shimmer animation styles
  React.useEffect(() => {
    const style = document.createElement('style');
    style.textContent = `
      @keyframes shimmer {
        0% { background-position: -200% 0; }
        100% { background-position: 200% 0; }
      }
    `;
    document.head.appendChild(style);
    return () => {
      if (document.head.contains(style)) {
        document.head.removeChild(style);
      }
    };
  }, []);
  const [records, setRecords] = useState<PanKycRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const hasFetchedRecords = useRef(false);
  const [stats, setStats] = useState<RecordsStats>({
    total: 0,
    pending: 0,
    verified: 0,
    rejected: 0,
    error: 0
  });

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

    // Prevent multiple simultaneous calls
    if (hasFetchedRecords.current || loading) {
      return;
    }

    try {
      setLoading(true);
      
      // Use pagination to reduce load time
      const response = await api.get('/pan-kyc/records', {
        params: {
          page: 1,
          limit: 50 // Start with smaller page size
        },
        timeout: 45000 // 45 second timeout (less than 60s axios default)
      });
      
      if (response.data.success) {
        setRecords(response.data.data);
        calculateStats(response.data.data);
        hasFetchedRecords.current = true;
        
        // Show success message if processing took time
        if (response.data.processingTime > 5000) {
          showToast({
            message: `Records loaded (took ${(response.data.processingTime / 1000).toFixed(1)}s). Consider using pagination for faster loading.`,
            type: 'success',
            duration: 3000
          });
        }
      }
    } catch (error: any) {
      // Handle cancelled requests
      if (error.code === 'ECONNABORTED' || error.message?.includes('timeout') || error.message?.includes('canceled')) {
        showToast({
          message: 'Request timed out. The server may be starting up (Render free tier). Please try again in a few seconds.',
          type: 'error',
          duration: 5000
        });
        console.error('Request timeout/cancelled:', error);
      } else if (error.response?.status === 401) {
        showToast({
          message: 'Authentication failed. Please log in again.',
          type: 'error'
        });
        console.error('Authentication error:', error);
      } else if (error.response?.status === 504) {
        showToast({
          message: 'Server timeout. Try using pagination (smaller page size) or try again later.',
          type: 'error',
          duration: 5000
        });
        console.error('Server timeout:', error);
      } else if (!error.response) {
        // Network error - likely Render service sleeping
        showToast({
          message: 'Connection failed. The server may be starting up. Please wait a moment and try again.',
          type: 'error',
          duration: 5000
        });
        console.error('Network error (Render may be sleeping):', error);
      } else {
        showToast({
          message: error.response?.data?.message || 'Failed to fetch records',
          type: 'error'
        });
        console.error('Error fetching records:', error);
      }
      hasFetchedRecords.current = false; // Reset on error to allow retry
    } finally {
      setLoading(false);
    }
  };

  const refreshRecords = async () => {
    hasFetchedRecords.current = false;
    await fetchRecords();
  };

  // Calculate statistics
  const calculateStats = (data: PanKycRecord[]) => {
    const verified = data.filter(r => r.status === 'verified').length;
    const rejected = data.filter(r => r.status === 'rejected').length;
    
    const stats = {
      total: verified + rejected, // Only count verified + rejected
      pending: 0, // Removed pending count
      verified: verified,
      rejected: rejected,
      error: 0 // Removed error count
    };
    setStats(stats);
  };

  // Filter records based on search and filters - only show verified and rejected records
  const filteredRecords = records.filter(record => {
    // Only show verified and rejected records
    const isProcessed = record.status === 'verified' || record.status === 'rejected';
    
    const matchesSearch = 
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
    
    return isProcessed && matchesSearch && matchesStatus && matchesDate;
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
      'PAN Number',
      'Name',
      'Father Name',
      'Date of Birth',
      'Status',
      'Processing Time (ms)',
      'Created At',
      'Processed At'
    ];

    const csvContent = [
      headers.join(','),
      ...filteredRecords.map(record => [
        record.batchId,
        record.panNumber,
        record.name,
        record.fatherName || '',
        record.dateOfBirth || '',
        record.status,
        record.processingTime || '',
        new Date(record.createdAt).toLocaleString(),
        record.processedAt ? new Date(record.processedAt).toLocaleString() : ''
      ].join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pan-kyc-records-${new Date().toISOString().split('T')[0]}.csv`;
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
      case 'verified':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'rejected':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
      default:
        return <ClockIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'verified':
        return 'bg-green-100 text-green-800';
      case 'rejected':
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

  useEffect(() => {
    if (isAuthenticated && user && !hasFetchedRecords.current) {
      fetchRecords();
    }
  }, [isAuthenticated, user]);

  // Reset fetch flag when user changes
  useEffect(() => {
    hasFetchedRecords.current = false;
  }, [user?._id]);

  return (
    <div className="space-y-6">
      {/* Enhanced Header */}
      <div className="bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-3xl p-8 text-white shadow-2xl relative overflow-hidden">
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
                <h1 className="text-3xl font-bold">PAN KYC Verification Records</h1>
              </div>
              <p className="text-blue-100 text-lg">
                View and manage all PAN KYC verification records
              </p>
            </div>
            <div className="flex items-center space-x-3">
              <button
                onClick={refreshRecords}
                disabled={loading}
                className="inline-flex items-center px-4 py-2 bg-white/20 backdrop-blur-sm hover:bg-white/30 text-white font-semibold rounded-xl transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-white/50 hover:scale-105 transform border border-white/30 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ArrowPathIcon className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
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
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
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
              <p className="text-sm font-medium text-gray-600">Verified</p>
              <p className="text-2xl font-bold text-emerald-600">{stats.verified}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-all duration-300 transform hover:scale-105">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-gradient-to-br from-red-500 to-pink-600 rounded-xl flex items-center justify-center mr-4">
              <XCircleIcon className="h-6 w-6 text-white" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-600">Rejected</p>
              <p className="text-2xl font-bold text-red-600">{stats.rejected}</p>
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
                placeholder="Search by PAN, Name, or Batch ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-12 pr-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
              />
            </div>
          </div>

          {/* Status Filter */}
          <div className="lg:w-48">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
            >
              <option value="all">All Statuses</option>
              <option value="verified">Verified</option>
              <option value="rejected">Rejected</option>
            </select>
          </div>

          {/* Date Filter */}
          <div className="lg:w-48">
            <select
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
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
        <div className="px-6 py-6 border-b border-gray-100 bg-gradient-to-r from-blue-50 to-purple-50">
          <h3 className="text-xl font-semibold text-blue-800">
            Records ({filteredRecords.length})
          </h3>
        </div>

        {loading ? (
          <div className="fixed inset-0 bg-gradient-to-br from-slate-900/95 via-blue-900/95 to-purple-900/95 backdrop-blur-lg flex items-center justify-center z-50">
            <div className="text-center">
              {/* Beautiful morphing loader */}
              <div className="relative mb-8">
                <div className="w-24 h-24 mx-auto relative">
                  {/* Outer pulsing ring */}
                  <div className="absolute inset-0 rounded-full border-2 border-blue-400/30 animate-ping"></div>
                  
                  {/* Main morphing shape */}
                  <div className="absolute inset-2 rounded-full bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 animate-spin" style={{ animationDuration: '3s' }}>
                    <div className="absolute inset-1 rounded-full bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 animate-pulse"></div>
                  </div>
                  
                  {/* Inner rotating dots */}
                  <div className="absolute inset-4 rounded-full border-2 border-white/20 animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}>
                    <div className="absolute top-0 left-1/2 transform -translate-x-1/2 -translate-y-1 w-2 h-2 bg-white rounded-full"></div>
                    <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 translate-y-1 w-2 h-2 bg-white rounded-full"></div>
                    <div className="absolute left-0 top-1/2 transform -translate-y-1/2 -translate-x-1 w-2 h-2 bg-white rounded-full"></div>
                    <div className="absolute right-0 top-1/2 transform -translate-y-1/2 translate-x-1 w-2 h-2 bg-white rounded-full"></div>
                  </div>
                  
                  {/* Center pulsing dot */}
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="w-3 h-3 bg-white rounded-full animate-pulse"></div>
                  </div>
                </div>
                
                {/* Floating particles */}
                <div className="absolute -top-4 -right-4 w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0s', animationDuration: '2s' }}></div>
                <div className="absolute -bottom-4 -left-4 w-3 h-3 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0.7s', animationDuration: '2.5s' }}></div>
                <div className="absolute -top-2 -left-6 w-2 h-2 bg-pink-400 rounded-full animate-bounce" style={{ animationDelay: '1.4s', animationDuration: '1.8s' }}></div>
                <div className="absolute -bottom-2 -right-6 w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '2.1s', animationDuration: '2.2s' }}></div>
              </div>
              
              <h3 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-pink-400 bg-clip-text text-transparent mb-4 animate-pulse">
                Loading Records
              </h3>
              <p className="text-gray-300 text-lg mb-8">Please wait while we fetch your PAN KYC records...</p>
              
              {/* Animated progress dots */}
              <div className="flex justify-center space-x-2">
                <div className="w-3 h-3 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0s' }}></div>
                <div className="w-3 h-3 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                <div className="w-3 h-3 bg-pink-400 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                <div className="w-3 h-3 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '0.6s' }}></div>
                <div className="w-3 h-3 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0.8s' }}></div>
              </div>
            </div>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-gradient-to-r from-blue-50 to-purple-50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-blue-700 uppercase tracking-wider">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                        <span>Basic Info</span>
                      </div>
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-blue-700 uppercase tracking-wider">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                        <span>Status</span>
                      </div>
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-blue-700 uppercase tracking-wider">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                        <span>Processing</span>
                      </div>
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-blue-700 uppercase tracking-wider">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                        <span>Timestamps</span>
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {paginatedRecords.map((record) => (
                    <tr key={record._id} className="hover:bg-gradient-to-r hover:from-blue-50/50 hover:to-purple-50/50 transition-all duration-200">
                      {/* Basic Info */}
                      <td className="px-6 py-4">
                        <div className="space-y-1">
                          <div className="text-sm font-medium text-gray-900">
                            {record.name}
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
                        </div>
                      </td>

                      {/* Status */}
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          {getStatusIcon(record.status)}
                          <span className={`ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(record.status)}`}>
                            {record.status}
                          </span>
                        </div>
                      </td>

                      {/* Processing */}
                      <td className="px-6 py-4">
                        <div className="space-y-1">
                          {record.processingTime && (
                            <div className="text-sm text-gray-900">
                              {record.processingTime}ms
                            </div>
                          )}
                        </div>
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
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Enhanced Pagination */}
            {totalPages > 1 && (
              <div className="px-6 py-6 border-t border-gray-100 bg-gradient-to-r from-blue-50 to-purple-50">
                <div className="flex items-center justify-between">
                  <div className="text-sm text-blue-700">
                    Showing <span className="font-semibold">{((currentPage - 1) * recordsPerPage) + 1}</span> to{' '}
                    <span className="font-semibold">{Math.min(currentPage * recordsPerPage, filteredRecords.length)}</span> of{' '}
                    <span className="font-semibold">{filteredRecords.length}</span> records
                  </div>
                  <div className="flex items-center space-x-3">
                    <button
                      onClick={() => setCurrentPage(currentPage - 1)}
                      disabled={currentPage === 1}
                      className="px-4 py-2 text-sm font-medium border border-blue-300 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed hover:bg-blue-50 transition-colors duration-200"
                    >
                      Previous
                    </button>
                    <span className="px-4 py-2 text-sm font-medium text-blue-700 bg-white rounded-xl border border-blue-200">
                      {currentPage} of {totalPages}
                    </span>
                    <button
                      onClick={() => setCurrentPage(currentPage + 1)}
                      disabled={currentPage === totalPages}
                      className="px-4 py-2 text-sm font-medium border border-blue-300 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed hover:bg-blue-50 transition-colors duration-200"
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

export default PanKycRecords;

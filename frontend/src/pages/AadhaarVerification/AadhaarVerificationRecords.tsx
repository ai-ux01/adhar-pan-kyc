import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import api from '../../services/api';
import { 
  IdentificationIcon, 
  CheckCircleIcon, 
  XCircleIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  EyeIcon,
  CalendarIcon,
  ArrowLeftIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
  FunnelIcon,
  ChevronUpIcon,
  ChevronDownIcon
} from '@heroicons/react/24/outline';

// Component to load authenticated images
const AuthenticatedImage: React.FC<{ 
  recordId: string; 
  className?: string;
  alt?: string;
  fallback?: React.ReactNode;
}> = ({ recordId, className, alt = 'Selfie', fallback }) => {
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let currentImageUrl: string | null = null;
    let isMounted = true;
    
    const loadImage = async () => {
      try {
        setLoading(true);
        setError(false);
        
        // Revoke previous URL if it exists
        if (currentImageUrl) {
          URL.revokeObjectURL(currentImageUrl);
          currentImageUrl = null;
        }
        
        const response = await api.get(`/aadhaar-verification/records/${recordId}/selfie`, {
          responseType: 'blob'
        });
        
        // Check if component is still mounted
        if (!isMounted) {
          // If unmounted, revoke the URL and return
          if (response.data instanceof Blob) {
            URL.revokeObjectURL(URL.createObjectURL(response.data));
          }
          return;
        }
        
        // Check if response is actually an image blob
        const contentType = response.headers['content-type'] || '';
        if (contentType.startsWith('image/')) {
          // Clone the blob to ensure it's not consumed
          const blob = response.data as Blob;
          const clonedBlob = blob.slice(0, blob.size, blob.type);
          const url = URL.createObjectURL(clonedBlob);
          currentImageUrl = url;
          setImageUrl(url);
        } else {
          // If not an image, it might be a JSON error response
          // Clone the blob to read it without consuming the original
          const blob = response.data as Blob;
          const text = await blob.text();
          try {
            const jsonError = JSON.parse(text);
            console.error('Error loading selfie:', jsonError.message || 'Unknown error');
          } catch {
            console.error('Error loading selfie: Invalid response format');
          }
          if (isMounted) {
            setError(true);
          }
        }
      } catch (err: any) {
        // Only update state if component is still mounted
        if (!isMounted) return;
        
        // Handle errors gracefully - 404 is expected if selfie doesn't exist
        const status = err.response?.status;
        if (status === 404) {
          // Selfie not found - this is expected for records without selfies
          setError(true);
        } else if (status === 403) {
          // Permission denied
          console.warn('Permission denied to view selfie for record:', recordId);
          setError(true);
        } else {
          // Other errors - log for debugging but don't spam console
          if (err.response && err.response.data instanceof Blob) {
            try {
              const text = await err.response.data.text();
              const jsonError = JSON.parse(text);
              console.warn('Error loading selfie:', jsonError.message || 'Unknown error');
            } catch {
              // Ignore parsing errors
            }
          } else {
            console.warn('Error loading selfie:', err.message || 'Network error');
          }
          setError(true);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    loadImage();

    // Cleanup function
    return () => {
      isMounted = false;
      if (currentImageUrl) {
        URL.revokeObjectURL(currentImageUrl);
        currentImageUrl = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recordId]);

  if (loading) {
    return (
      <div className={`w-12 h-16 bg-gray-200 rounded border-2 border-gray-300 flex items-center justify-center ${className || ''}`}>
        <ArrowPathIcon className="w-4 h-4 text-gray-400 animate-spin" />
      </div>
    );
  }

  if (error || !imageUrl) {
    if (fallback) {
      return <>{fallback}</>;
    }
    return (
      <div className={`w-12 h-16 bg-gray-200 rounded border-2 border-gray-300 flex items-center justify-center ${className || ''}`}>
        <span className="text-xs text-gray-500">-</span>
      </div>
    );
  }

  return (
    <img 
      src={imageUrl} 
      alt={alt}
      className={className}
      onError={() => setError(true)}
    />
  );
};

interface VerificationRecord {
  _id: string;
  batchId: string;
  status: string;
  createdAt: string;
  processedAt?: string;
    aadhaarNumber: string;
    name: string;
  dateOfBirth: string;
    gender: string;
  address?: string;
  pinCode?: string;
  state?: string;
    district?: string;
  careOf?: string;
  photo?: string;
  selfie?: {
    filename: string;
    originalName: string;
    path: string;
    mimetype: string;
    size: number;
    uploadedAt: string;
  };
  dynamicFields?: Array<{
    label: string;
    value: string;
  }>;
  verificationDetails?: {
    apiResponse?: any;
    verificationDate?: string;
    remarks?: string;
    source?: string;
    confidence?: number;
    dataMatch?: boolean;
    nameMatch?: boolean;
    dobMatch?: boolean;
    genderMatch?: boolean;
    addressMatch?: boolean;
    transactionId?: string;
    fullAddress?: string;
    careOf?: string;
    photo?: string;
    emailHash?: string;
    mobileHash?: string;
    yearOfBirth?: string;
    shareCode?: string;
  };
  processingTime?: number;
  errorMessage?: string;
}

interface PaginationInfo {
  currentPage: number;
  totalPages: number;
  totalRecords: number;
  hasNext: boolean;
  hasPrev: boolean;
}

const AadhaarVerificationRecords: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  
  const [records, setRecords] = useState<VerificationRecord[]>([]);
  const [pagination, setPagination] = useState<PaginationInfo>({
    currentPage: 1,
    totalPages: 1,
    totalRecords: 0,
    hasNext: false,
    hasPrev: false
  });
  const [isLoading, setIsLoading] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState<VerificationRecord | null>(null);
  const [showDetails, setShowDetails] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [filters, setFilters] = useState({
    status: '',
    dateFrom: '',
    dateTo: '',
    sortBy: 'createdAt',
    sortOrder: 'desc'
  });
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [dynamicFieldLabels, setDynamicFieldLabels] = useState<string[]>([]);

  // Extract unique dynamic field labels from records
  const extractDynamicFieldLabels = (records: VerificationRecord[]) => {
    const labels = new Set<string>();
    records.forEach(record => {
      if (record.dynamicFields && record.dynamicFields.length > 0) {
        record.dynamicFields.forEach(field => {
          if (field.label) {
            labels.add(field.label);
          }
        });
      }
    });
    return Array.from(labels).sort();
  };

  // Load verification records
  const loadRecords = async (page: number = 1, search: string = '', currentFilters = filters) => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: '10'
      });
      
      if (search) params.append('search', search);
      if (currentFilters.status) params.append('status', currentFilters.status);
      if (currentFilters.dateFrom) params.append('dateFrom', currentFilters.dateFrom);
      if (currentFilters.dateTo) params.append('dateTo', currentFilters.dateTo);
      if (currentFilters.sortBy) params.append('sortBy', currentFilters.sortBy);
      if (currentFilters.sortOrder) params.append('sortOrder', currentFilters.sortOrder);
      
      // Determine API base URL
      const getApiBaseURL = () => {
        if (process.env.REACT_APP_API_URL) return process.env.REACT_APP_API_URL;
        const isProduction = window.location.hostname !== 'localhost' && 
                             window.location.hostname !== '127.0.0.1' &&
                             !window.location.hostname.startsWith('192.168.');
        return isProduction ? 'https://adhar-pan-kyc-1.onrender.com/api' : 'http://localhost:3002/api';
      };
      const response = await fetch(`${getApiBaseURL()}/aadhaar-verification/records?${params.toString()}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token') || sessionStorage.getItem('token')}`
        }
      });

      const data = await response.json();
      if (data.success) {
        console.log('Pagination data received:', data.pagination);
        setRecords(data.data);
        setPagination({
          currentPage: data.pagination.currentPage,
          totalPages: data.pagination.totalPages,
          totalRecords: data.pagination.totalRecords,
          hasNext: data.pagination.hasNext,
          hasPrev: data.pagination.hasPrev
        });
        // Extract and set dynamic field labels
        const labels = extractDynamicFieldLabels(data.data);
        setDynamicFieldLabels(labels);
      } else {
        toast.error(data.message || 'Failed to load verification records');
      }
    } catch (error) {
      console.error('Error loading verification records:', error);
      toast.error('Failed to load verification records');
    } finally {
      setIsLoading(false);
    }
  };

  // Load records on component mount
  useEffect(() => {
    loadRecords();
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'verified':
        return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case 'failed':
        return <XCircleIcon className="w-5 h-5 text-red-500" />;
      case 'expired':
        return <ClockIcon className="w-5 h-5 text-yellow-500" />;
      case 'otp_sent':
        return <ExclamationTriangleIcon className="w-5 h-5 text-blue-500" />;
      default:
        return <ExclamationTriangleIcon className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'verified':
        return 'bg-green-100 text-green-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      case 'expired':
        return 'bg-yellow-100 text-yellow-800';
      case 'otp_sent':
        return 'bg-blue-100 text-blue-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'verified':
        return 'Verified';
      case 'failed':
        return 'Failed';
      case 'expired':
        return 'Expired';
      case 'otp_sent':
        return 'OTP Sent';
      case 'pending':
        return 'Pending';
      default:
        return status;
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-IN', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };


  const handlePageChange = (page: number) => {
    loadRecords(page, searchTerm, filters);
  };

  // Handle search
  const handleSearch = async (search: string) => {
    setSearchTerm(search);
    setIsSearching(true);
    await loadRecords(1, search, filters);
    setIsSearching(false);
  };

  // Handle filter changes
  const handleFilterChange = async (newFilters: typeof filters) => {
    setFilters(newFilters);
    setIsSearching(true);
    await loadRecords(1, searchTerm, newFilters);
    setIsSearching(false);
  };

  // Handle sort change
  const handleSortChange = (sortBy: string) => {
    const newSortOrder = filters.sortBy === sortBy && filters.sortOrder === 'desc' ? 'asc' : 'desc';
    const newFilters = { ...filters, sortBy, sortOrder: newSortOrder };
    handleFilterChange(newFilters);
  };

  // Handle search input change with debounce
  const handleSearchInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setSearchTerm(value);
    
    // Clear existing timeout
    if ((window as any).searchTimeout) {
      clearTimeout((window as any).searchTimeout);
    }
    
    // Set new timeout for debounced search
    (window as any).searchTimeout = setTimeout(() => {
      handleSearch(value);
    }, 500);
  };

  // Clear search
  const clearSearch = () => {
    setSearchTerm('');
    handleSearch('');
  };

  // Clear all filters
  const clearAllFilters = () => {
    const defaultFilters = {
      status: '',
      dateFrom: '',
      dateTo: '',
      sortBy: 'createdAt',
      sortOrder: 'desc'
    };
    setFilters(defaultFilters);
    handleFilterChange(defaultFilters);
  };

  const handleViewDetails = (record: VerificationRecord) => {
    setSelectedRecord(record);
    setShowDetails(true);
  };

  const handleCloseDetails = () => {
    setSelectedRecord(null);
    setShowDetails(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 relative overflow-hidden">
      {/* Subtle Animated Background Elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-200 rounded-full mix-blend-multiply filter blur-xl opacity-30 animate-pulse"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-purple-200 rounded-full mix-blend-multiply filter blur-xl opacity-30 animate-pulse"></div>
        <div className="absolute top-40 left-1/2 w-80 h-80 bg-indigo-200 rounded-full mix-blend-multiply filter blur-xl opacity-30 animate-pulse"></div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex justify-center mb-8">
            <div className="relative group">
              <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full blur-lg opacity-60 group-hover:opacity-80 transition-opacity duration-300"></div>
              <div className="relative p-6 bg-white rounded-full shadow-2xl border-4 border-white/50 transform group-hover:scale-110 transition-transform duration-300">
                <IdentificationIcon className="w-16 h-16 text-blue-600" />
              </div>
            </div>
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-600 bg-clip-text text-transparent mb-4 animate-pulse">
            📋 Verification Records
          </h1>
          <p className="text-lg text-gray-600 mb-8 max-w-3xl mx-auto leading-relaxed">
            🔍 View your complete Aadhaar verification history with detailed information and status tracking
          </p>
          
          {/* Back to Verification Button */}
          <button
            onClick={() => navigate('/aadhaar-verification')}
            className="group relative inline-flex items-center px-10 py-5 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold rounded-2xl shadow-2xl hover:shadow-3xl transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
          >
            <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-500 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
            <ArrowLeftIcon className="w-6 h-6 mr-3 relative z-10" />
            <span className="relative z-10 text-base">Back to Verification</span>
          </button>
        </div>

        {/* Enhanced Search Section */}
        <div className="bg-white/95 backdrop-blur-lg border border-white/50 rounded-3xl shadow-2xl p-8 transform hover:scale-[1.01] transition-transform duration-300">
          {/* Main Search Bar */}
          <div className="flex flex-col lg:flex-row gap-4 items-center mb-6">
            <div className="flex-1 relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <MagnifyingGlassIcon className="h-6 w-6 text-gray-400" />
              </div>
              <input
                type="text"
                placeholder="Search by Aadhaar Number, Name, Address, District, State, PIN Code, or Care Of..."
                value={searchTerm}
                onChange={handleSearchInputChange}
                className="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-xl text-base font-medium text-gray-900 placeholder-gray-500 focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/80 backdrop-blur-sm"
              />
              {searchTerm && (
                <button
                  onClick={clearSearch}
                  className="absolute inset-y-0 right-0 pr-4 flex items-center text-gray-400 hover:text-gray-600 transition-colors duration-200"
                >
                  <XMarkIcon className="h-6 w-6" />
                </button>
              )}
            </div>
            
            {/* Advanced Filters Toggle */}
            <button
              onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
              className={`group relative inline-flex items-center px-6 py-4 font-bold rounded-2xl shadow-lg hover:shadow-xl focus:outline-none focus:ring-4 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1 ${
                showAdvancedFilters 
                  ? 'bg-gradient-to-r from-purple-600 to-blue-600 text-white' 
                  : 'bg-gradient-to-r from-blue-500 to-purple-600 text-white hover:from-purple-600 hover:to-blue-600'
              }`}
            >
              <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-500 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              <FunnelIcon className="w-5 h-5 mr-2 relative z-10" />
              <span className="relative z-10">Filters</span>
            </button>

            {isSearching && (
              <div className="flex items-center space-x-2 text-blue-600">
                <ArrowPathIcon className="w-5 h-5 animate-spin" />
                <span className="text-xs font-medium">Searching...</span>
              </div>
            )}
          </div>

          {/* Advanced Filters Panel */}
          {showAdvancedFilters && (
            <div className="border-t border-gray-200 pt-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                {/* Status Filter */}
                <div>
                  <label className="block text-xs font-semibold text-gray-700 mb-2">Status</label>
                  <select
                    value={filters.status}
                    onChange={(e) => handleFilterChange({ ...filters, status: e.target.value })}
                    className="block w-full px-3 py-2 border border-gray-300 rounded-lg text-xs font-medium text-gray-900 focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/80 backdrop-blur-sm"
                  >
                    <option value="">All Status</option>
                    <option value="verified">Verified</option>
                    <option value="failed">Failed</option>
                    <option value="expired">Expired</option>
                    <option value="pending">Pending</option>
                  </select>
                </div>

                {/* Date From Filter */}
                <div>
                  <label className="block text-xs font-semibold text-gray-700 mb-2">Date From</label>
                  <input
                    type="date"
                    value={filters.dateFrom}
                    onChange={(e) => handleFilterChange({ ...filters, dateFrom: e.target.value })}
                    className="block w-full px-3 py-2 border border-gray-300 rounded-lg text-xs font-medium text-gray-900 focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/80 backdrop-blur-sm"
                  />
                </div>

                {/* Date To Filter */}
                <div>
                  <label className="block text-xs font-semibold text-gray-700 mb-2">Date To</label>
                  <input
                    type="date"
                    value={filters.dateTo}
                    onChange={(e) => handleFilterChange({ ...filters, dateTo: e.target.value })}
                    className="block w-full px-3 py-2 border border-gray-300 rounded-lg text-xs font-medium text-gray-900 focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/80 backdrop-blur-sm"
                  />
                </div>

                {/* Sort By Filter */}
                <div>
                  <label className="block text-xs font-semibold text-gray-700 mb-2">Sort By</label>
                  <select
                    value={filters.sortBy}
                    onChange={(e) => handleFilterChange({ ...filters, sortBy: e.target.value })}
                    className="block w-full px-3 py-2 border border-gray-300 rounded-lg text-xs font-medium text-gray-900 focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/80 backdrop-blur-sm"
                  >
                    <option value="createdAt">Date Created</option>
                    <option value="name">Name</option>
                    <option value="aadhaarNumber">Aadhaar Number</option>
                    <option value="status">Status</option>
                    <option value="district">District</option>
                    <option value="state">State</option>
                  </select>
                </div>
              </div>

              {/* Filter Actions */}
              <div className="flex flex-wrap gap-3 justify-center">
                <button
                  onClick={() => handleFilterChange({ ...filters, sortOrder: filters.sortOrder === 'desc' ? 'asc' : 'desc' })}
                  className="group relative inline-flex items-center px-6 py-3 bg-gradient-to-r from-green-500 to-blue-600 text-white font-bold rounded-xl shadow-lg hover:shadow-xl focus:outline-none focus:ring-4 focus:ring-green-500/20 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-green-500 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  {filters.sortOrder === 'desc' ? (
                    <ChevronDownIcon className="w-5 h-5 mr-2 relative z-10" />
                  ) : (
                    <ChevronUpIcon className="w-5 h-5 mr-2 relative z-10" />
                  )}
                  <span className="relative z-10">Sort {filters.sortOrder === 'desc' ? 'Descending' : 'Ascending'}</span>
                </button>

                <button
                  onClick={clearAllFilters}
                  className="group relative inline-flex items-center px-6 py-3 bg-gradient-to-r from-red-500 to-pink-600 text-white font-bold rounded-xl shadow-lg hover:shadow-xl focus:outline-none focus:ring-4 focus:ring-red-500/20 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-pink-600 to-red-500 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  <XMarkIcon className="w-5 h-5 mr-2 relative z-10" />
                  <span className="relative z-10">Clear All Filters</span>
                </button>
              </div>
            </div>
          )}

          {/* Active Filters Display */}
          {(searchTerm || filters.status || filters.dateFrom || filters.dateTo) && (
            <div className="mt-4 flex flex-wrap gap-2 justify-center">
              {searchTerm && (
                <span className="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                  🔍 Search: "{searchTerm}"
                </span>
              )}
              {filters.status && (
                <span className="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  📊 Status: {filters.status}
                </span>
              )}
              {filters.dateFrom && (
                <span className="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                  📅 From: {filters.dateFrom}
                </span>
              )}
              {filters.dateTo && (
                <span className="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                  📅 To: {filters.dateTo}
                </span>
              )}
            </div>
          )}
        </div>

        {/* Records Table */}
        <div className="bg-white/95 backdrop-blur-lg border border-white/50 rounded-3xl shadow-2xl overflow-hidden transform hover:scale-[1.01] transition-transform duration-300">
          {isLoading ? (
            <div className="flex items-center justify-center py-20">
              <div className="flex items-center space-x-4">
                <div className="relative">
                  <div className="absolute inset-0 bg-blue-400 rounded-full blur-lg opacity-60 animate-pulse"></div>
                  <div className="relative p-4 bg-white rounded-full shadow-xl">
                    <ArrowPathIcon className="w-8 h-8 animate-spin text-blue-600" />
                  </div>
                </div>
                <span className="text-xl font-semibold text-gray-600">Loading verification records...</span>
              </div>
            </div>
          ) : records.length === 0 ? (
            <div className="text-center py-20">
              <div className="relative mb-8">
                <div className="absolute inset-0 bg-gray-300 rounded-full blur-lg opacity-60 animate-pulse"></div>
                <div className="relative p-8 bg-white rounded-full shadow-xl mx-auto w-32 h-32 flex items-center justify-center">
                  {searchTerm ? (
                    <MagnifyingGlassIcon className="w-16 h-16 text-gray-400" />
                  ) : (
                    <IdentificationIcon className="w-16 h-16 text-gray-400" />
                  )}
                </div>
              </div>
              {searchTerm ? (
                <>
                  <h3 className="text-xl font-bold text-gray-900 mb-3">No records found for "{searchTerm}"</h3>
                  <p className="text-base text-gray-500 mb-6">Try searching with different keywords or clear the search to see all records.</p>
                  <button
                    onClick={clearSearch}
                    className="group relative inline-flex items-center px-8 py-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-bold rounded-2xl shadow-2xl hover:shadow-3xl transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                  >
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-600 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                    <span className="relative z-10 flex items-center">
                      <span className="mr-2">🔍</span>
                      Clear Search
                    </span>
                  </button>
                </>
              ) : (
                <>
                  <h3 className="text-xl font-bold text-gray-900 mb-3">No verification records found</h3>
                  <p className="text-base text-gray-500 mb-6">You haven't performed any Aadhaar verifications yet.</p>
                  <button
                    onClick={() => navigate('/aadhaar-verification')}
                    className="group relative inline-flex items-center px-8 py-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-bold rounded-2xl shadow-2xl hover:shadow-3xl transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                  >
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-600 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                    <span className="relative z-10 flex items-center">
                      <span className="mr-2">🚀</span>
                      Start Verification
                    </span>
                  </button>
                </>
              )}
            </div>
          ) : (
            <>
              {/* Desktop Table */}
              <div className="hidden lg:block overflow-x-auto">
                <table className="min-w-max divide-y divide-gray-200" id="aadhaarTable" style={{ minWidth: '1200px' }}>
                  <thead className="bg-gradient-to-r from-blue-50 to-purple-50">
                    <tr>
                      <th 
                        className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider sticky left-0 bg-gradient-to-r from-blue-50 to-purple-50 z-10 cursor-pointer hover:bg-gradient-to-r hover:from-indigo-100 hover:to-purple-100 transition-all duration-300"
                        onClick={() => handleSortChange('aadhaarNumber')}
                      >
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                          Aadhaar Number
                          {filters.sortBy === 'aadhaarNumber' && (
                            filters.sortOrder === 'desc' ? 
                              <ChevronDownIcon className="w-4 h-4 ml-1 text-indigo-600" /> : 
                              <ChevronUpIcon className="w-4 h-4 ml-1 text-indigo-600" />
                          )}
                        </span>
                      </th>
                      <th 
                        className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider sticky left-32 bg-gradient-to-r from-blue-50 to-purple-50 z-10 cursor-pointer hover:bg-gradient-to-r hover:from-pink-100 hover:to-purple-100 transition-all duration-300"
                        onClick={() => handleSortChange('name')}
                      >
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-pink-500 rounded-full mr-2"></span>
                          Name
                          {filters.sortBy === 'name' && (
                            filters.sortOrder === 'desc' ? 
                              <ChevronDownIcon className="w-4 h-4 ml-1 text-pink-600" /> : 
                              <ChevronUpIcon className="w-4 h-4 ml-1 text-pink-600" />
                          )}
                        </span>
                      </th>
                      <th 
                        className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider cursor-pointer hover:bg-gradient-to-r hover:from-green-100 hover:to-purple-100 transition-all duration-300"
                        onClick={() => handleSortChange('status')}
                      >
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                          Status
                          {filters.sortBy === 'status' && (
                            filters.sortOrder === 'desc' ? 
                              <ChevronDownIcon className="w-4 h-4 ml-1 text-green-600" /> : 
                              <ChevronUpIcon className="w-4 h-4 ml-1 text-green-600" />
                          )}
                        </span>
                      </th>
                      <th 
                        className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider cursor-pointer hover:bg-gradient-to-r hover:from-purple-100 hover:to-blue-100 transition-all duration-300"
                        onClick={() => handleSortChange('createdAt')}
                      >
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-purple-500 rounded-full mr-2"></span>
                          Date
                          {filters.sortBy === 'createdAt' && (
                            filters.sortOrder === 'desc' ? 
                              <ChevronDownIcon className="w-4 h-4 ml-1 text-purple-600" /> : 
                              <ChevronUpIcon className="w-4 h-4 ml-1 text-purple-600" />
                          )}
                        </span>
                      </th>
                      <th className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-orange-500 rounded-full mr-2"></span>
                          Gender
                        </span>
                      </th>
                      <th className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-teal-500 rounded-full mr-2"></span>
                          Date Of Birth
                        </span>
                      </th>
                      <th className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-red-500 rounded-full mr-2"></span>
                          District
                        </span>
                      </th>
                      <th className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></span>
                          State
                        </span>
                      </th>
                      <th className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-cyan-500 rounded-full mr-2"></span>
                          Address
                        </span>
                      </th>
                      <th className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-emerald-500 rounded-full mr-2"></span>
                          Care Of
                        </span>
                      </th>
                      <th className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-violet-500 rounded-full mr-2"></span>
                          Photo
                        </span>
                      </th>
                      <th className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-pink-500 rounded-full mr-2"></span>
                          Selfie
                        </span>
                      </th>
                      {/* Dynamic Field Headers */}
                      {dynamicFieldLabels.map((label, index) => (
                        <th key={label} className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                          <span className="flex items-center">
                            <span className={`w-2 h-2 rounded-full mr-2 ${
                              index % 6 === 0 ? 'bg-orange-500' :
                              index % 6 === 1 ? 'bg-pink-500' :
                              index % 6 === 2 ? 'bg-blue-500' :
                              index % 6 === 3 ? 'bg-green-500' :
                              index % 6 === 4 ? 'bg-purple-500' :
                              'bg-indigo-500'
                            }`}></span>
                            {label}
                          </span>
                        </th>
                      ))}
                      <th className="px-4 py-6 text-left text-sm font-bold text-gray-700 uppercase tracking-wider">
                        <span className="flex items-center">
                          <span className="w-2 h-2 bg-rose-500 rounded-full mr-2"></span>
                          Actions
                        </span>
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-100">
                    {records.map((record, index) => (
                      <tr key={record._id} className="hover:bg-gradient-to-r hover:from-blue-50 hover:to-purple-50 transition-all duration-300 transform hover:scale-[1.01]">
                        <td className="px-4 py-6 whitespace-nowrap text-sm font-bold text-gray-900 font-mono sticky left-0 bg-white z-10">
                          <span className="inline-flex items-center px-3 py-1 rounded-full bg-indigo-100 text-indigo-800">
                            {record.aadhaarNumber ? 
                              record.aadhaarNumber.replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3') : 
                              '-'
                            }
                          </span>
                        </td>
                        <td className="px-4 py-6 whitespace-nowrap text-sm font-semibold text-gray-900 sticky left-32 bg-white z-10">
                          <span className="inline-flex items-center px-3 py-1 rounded-full bg-pink-100 text-pink-800">
                            {record.name || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-6 whitespace-nowrap">
                          <div className="flex items-center">
                            {getStatusIcon(record.status)}
                            <span className={`ml-2 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(record.status)}`}>
                              {getStatusText(record.status)}
                            </span>
                            </div>
                        </td>
                        <td className="px-4 py-6 whitespace-nowrap text-sm font-semibold text-gray-900">
                          <span className="inline-flex items-center px-3 py-1 rounded-full bg-purple-100 text-purple-800">
                          {formatDate(record.createdAt)}
                          </span>
                        </td>
                        <td className="px-4 py-6 whitespace-nowrap text-sm font-semibold text-gray-900">
                          <span className="inline-flex items-center px-3 py-1 rounded-full bg-orange-100 text-orange-800">
                            {record.gender === 'M' ? 'Male' : record.gender === 'F' ? 'Female' : 'Other'}
                          </span>
                        </td>
                        <td className="px-4 py-6 whitespace-nowrap text-sm font-semibold text-gray-900">
                          <span className="inline-flex items-center px-3 py-1 rounded-full bg-teal-100 text-teal-800">
                            {record.dateOfBirth || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-6 whitespace-nowrap text-sm font-semibold text-gray-900">
                          <span className="inline-flex items-center px-3 py-1 rounded-full bg-red-100 text-red-800">
                            {record.district || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-6 whitespace-nowrap text-sm font-semibold text-gray-900">
                          <span className="inline-flex items-center px-3 py-1 rounded-full bg-yellow-100 text-yellow-800">
                            {record.state || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-6 text-sm font-semibold text-gray-900 max-w-xs">
                          <span className="inline-flex items-center px-3 py-1 rounded-full bg-cyan-100 text-cyan-800">
                            {record.address ? 
                              (record.address.length > 30 ? record.address.substring(0, 30) + '...' : record.address) 
                              : '-'
                            }
                          </span>
                        </td>
                        <td className="px-4 py-6 text-sm font-semibold text-gray-900 max-w-xs truncate">
                          <span className="inline-flex items-center px-3 py-1 rounded-full bg-emerald-100 text-emerald-800">
                            {record.careOf || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-6 whitespace-nowrap text-sm text-gray-900">
                          {record.photo ? (
                            <img 
                              src={`data:image/jpeg;base64,${record.photo}`} 
                              alt="Photo" 
                              className="w-12 h-16 object-cover rounded border-2 border-green-200 shadow-sm"
                            />
                          ) : (
                            <span className="w-12 h-16 bg-gray-200 rounded border-2 border-gray-300 flex items-center justify-center">
                              <span className="text-xs text-gray-500">-</span>
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-6 whitespace-nowrap text-sm text-gray-900">
                          {record.selfie ? (
                            <AuthenticatedImage 
                              recordId={record._id}
                              className="w-12 h-16 object-cover rounded border-2 border-pink-200 shadow-sm cursor-pointer hover:scale-110 transition-transform"
                              alt="Selfie"
                              fallback={
                                <span className="w-12 h-16 bg-gray-200 rounded border-2 border-gray-300 flex items-center justify-center">
                                  <span className="text-xs text-gray-500">-</span>
                                </span>
                              }
                            />
                          ) : (
                            <span className="w-12 h-16 bg-gray-200 rounded border-2 border-gray-300 flex items-center justify-center">
                              <span className="text-xs text-gray-500">-</span>
                            </span>
                          )}
                        </td>
                        {/* Dynamic Field Columns */}
                        {dynamicFieldLabels.map((label, index) => {
                          const field = record.dynamicFields?.find(f => f.label === label);
                          return (
                            <td key={label} className="px-4 py-6 whitespace-nowrap text-sm text-gray-900">
                              <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${
                                index % 6 === 0 ? 'bg-orange-100 text-orange-800' :
                                index % 6 === 1 ? 'bg-pink-100 text-pink-800' :
                                index % 6 === 2 ? 'bg-blue-100 text-blue-800' :
                                index % 6 === 3 ? 'bg-green-100 text-green-800' :
                                index % 6 === 4 ? 'bg-purple-100 text-purple-800' :
                                'bg-indigo-100 text-indigo-800'
                              }`}>
                                {field?.value || '-'}
                              </span>
                            </td>
                          );
                        })}
                        <td className="px-4 py-6 whitespace-nowrap text-sm text-gray-900">
                          <button
                            onClick={() => handleViewDetails(record)}
                            className="group relative inline-flex items-center px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold rounded-xl shadow-lg hover:shadow-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                          >
                            <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-500 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                            <EyeIcon className="w-4 h-4 mr-2 relative z-10" />
                            <span className="relative z-10">View Details</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile Cards */}
              <div className="lg:hidden">
                {records.map((record, index) => (
                  <div key={record._id} className="border-b border-gray-200 p-4">
                    <div className="flex items-center justify-end mb-3">
                      <div className="flex items-center">
                        {getStatusIcon(record.status)}
                        <span className={`ml-2 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(record.status)}`}>
                          {getStatusText(record.status)}
                        </span>
                      </div>
                    </div>
                    
                    <div className="mb-4">
                      <div className="mb-2">
                        <span className="text-gray-500 font-semibold">Aadhaar Number:</span>
                        <span className="ml-2 font-bold text-indigo-600 font-mono">
                          {record.aadhaarNumber ? 
                            record.aadhaarNumber.replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3') : 
                            '-'
                          }
                      </span>
                      </div>
                      <div className="mb-2">
                        <span className="text-gray-500 font-semibold">Name:</span>
                        <span className="ml-2 font-bold text-pink-600">{record.name || '-'}</span>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-2 text-sm mb-3">
                      <div>
                        <span className="text-gray-500">Gender:</span>
                        <span className="ml-1 font-medium">{record.gender === 'M' ? 'Male' : record.gender === 'F' ? 'Female' : 'Other'}</span>
                      </div>
                      <div>
                        <span className="text-gray-500">DOB:</span>
                        <span className="ml-1 font-medium">{record.dateOfBirth || '-'}</span>
                      </div>
                      <div>
                        <span className="text-gray-500">State:</span>
                        <span className="ml-1 font-medium">{record.state || '-'}</span>
                      </div>
                      <div>
                        <span className="text-gray-500">Care Of:</span>
                        <span className="ml-1 font-medium">{record.careOf || '-'}</span>
                      </div>
                      <div>
                        <span className="text-gray-500">Photo:</span>
                        <span className="ml-1 font-medium">
                          {record.photo ? (
                            <img 
                              src={`data:image/jpeg;base64,${record.photo}`} 
                              alt="Photo" 
                              className="w-8 h-12 object-cover rounded border border-gray-300"
                            />
                          ) : (
                            <span className="w-8 h-12 bg-gray-200 rounded border border-gray-300 flex items-center justify-center">
                              <span className="text-xs text-gray-500">-</span>
                            </span>
                          )}
                        </span>
                      </div>
                      {record.dynamicFields && record.dynamicFields.length > 0 && (
                        <div>
                          <span className="text-gray-500">Dynamic Fields:</span>
                          <div className="mt-1 space-y-1">
                            {record.dynamicFields.map((field: any, idx: number) => (
                              <div key={idx} className="flex items-center space-x-2">
                                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                                  {field.label}: {field.value}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                    
                    {/* Address Section */}
                    {record.address && (
                      <div className="mb-3 p-3 bg-gray-50 rounded-lg">
                        <span className="text-gray-500 font-semibold block mb-1">Address:</span>
                        <div className="text-sm text-gray-700 font-medium">
                          {record.address.length > 50 ? record.address.substring(0, 50) + '...' : record.address}
                        </div>
                      </div>
                    )}
                    
                    <div className="space-y-1 text-sm text-gray-600">
                      <div className="flex items-center">
                        <CalendarIcon className="w-4 h-4 mr-2" />
                        <span>Date: {formatDate(record.createdAt)}</span>
                      </div>
                      {record.aadhaarNumber && (
                        <div>
                          <span className="text-gray-500">Aadhaar:</span>
                          <span className="ml-1 font-mono">
                            {record.aadhaarNumber.replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3')}
                          </span>
                        </div>
                      )}
                      <div className="pt-2">
                        <button
                          onClick={() => handleViewDetails(record)}
                          className="text-blue-600 hover:text-blue-800 underline text-sm"
                        >
                          View Details
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination */}
              {pagination.totalRecords > 0 && (
                <div className="bg-gradient-to-r from-blue-50 to-purple-50 px-6 py-6 flex items-center justify-between border-t border-gray-200">
                  <div className="flex-1 flex justify-between sm:hidden">
                    <button
                      onClick={() => handlePageChange(pagination.currentPage - 1)}
                      disabled={!pagination.hasPrev}
                      className="group relative inline-flex items-center px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold rounded-xl shadow-lg hover:shadow-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-500 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                      <span className="relative z-10">← Previous</span>
                    </button>
                    <button
                      onClick={() => handlePageChange(pagination.currentPage + 1)}
                      disabled={!pagination.hasNext}
                      className="group relative inline-flex items-center px-6 py-3 bg-gradient-to-r from-purple-500 to-blue-600 text-white font-bold rounded-xl shadow-lg hover:shadow-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-purple-500 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                      <span className="relative z-10">Next →</span>
                    </button>
                  </div>
                  <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                    <div>
                      <p className="text-lg font-bold text-gray-700">
                        📄 Showing page <span className="font-bold text-blue-600">{pagination.currentPage}</span> of{' '}
                        <span className="font-bold text-purple-600">{pagination.totalPages}</span> 
                        <span className="ml-2 text-sm font-semibold text-gray-600">({pagination.totalRecords} total records)</span>
                      </p>
                    </div>
                    <div>
                      <nav className="relative z-0 inline-flex rounded-xl shadow-lg space-x-2">
                        <button
                          onClick={() => handlePageChange(pagination.currentPage - 1)}
                          disabled={!pagination.hasPrev}
                          className="group relative inline-flex items-center px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold rounded-lg shadow-lg hover:shadow-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                        >
                          <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-500 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                          <span className="relative z-10">←</span>
                        </button>
                        
                        {/* Page Numbers */}
                        {Array.from({ length: Math.min(5, pagination.totalPages) }, (_, i) => {
                          let pageNum: number;
                          if (pagination.totalPages <= 5) {
                            pageNum = i + 1;
                          } else if (pagination.currentPage <= 3) {
                            pageNum = i + 1;
                          } else if (pagination.currentPage >= pagination.totalPages - 2) {
                            pageNum = pagination.totalPages - 4 + i;
                          } else {
                            pageNum = pagination.currentPage - 2 + i;
                          }
                          
                          return (
                            <button
                              key={pageNum}
                              onClick={() => handlePageChange(pageNum)}
                              className={`group relative inline-flex items-center px-4 py-2 font-bold rounded-lg shadow-lg hover:shadow-xl focus:outline-none focus:ring-4 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1 ${
                                pageNum === pagination.currentPage
                                  ? 'bg-gradient-to-r from-purple-600 to-blue-600 text-white'
                                  : 'bg-white text-gray-700 hover:bg-gradient-to-r hover:from-blue-500 hover:to-purple-600 hover:text-white'
                              }`}
                            >
                              <div className={`absolute inset-0 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300 ${
                                pageNum === pagination.currentPage
                                  ? 'bg-gradient-to-r from-blue-600 to-purple-500'
                                  : 'bg-gradient-to-r from-purple-600 to-blue-500'
                              }`}></div>
                              <span className="relative z-10">{pageNum}</span>
                            </button>
                          );
                        })}
                        
                        <button
                          onClick={() => handlePageChange(pagination.currentPage + 1)}
                          disabled={!pagination.hasNext}
                          className="group relative inline-flex items-center px-4 py-2 bg-gradient-to-r from-purple-500 to-blue-600 text-white font-bold rounded-lg shadow-lg hover:shadow-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                        >
                          <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-purple-500 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                          <span className="relative z-10">→</span>
                        </button>
                      </nav>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Record Details Modal */}
        {showDetails && selectedRecord && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
              <div className="mt-3">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-medium text-gray-900">Verification Details</h3>
                  <button
                    onClick={handleCloseDetails}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <XCircleIcon className="w-6 h-6" />
                  </button>
                </div>
                
                <div className="space-y-6">
                  {/* Status and Basic Info */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Status</label>
                      <div className="mt-1 flex items-center">
                        {getStatusIcon(selectedRecord.status)}
                        <span className={`ml-2 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(selectedRecord.status)}`}>
                          {getStatusText(selectedRecord.status)}
                        </span>
                      </div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Created At</label>
                      <p className="mt-1 text-sm text-gray-900">{formatDate(selectedRecord.createdAt)}</p>
                    </div>
                    
                    {selectedRecord.processedAt && (
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Processed At</label>
                        <p className="mt-1 text-sm text-gray-900">{formatDate(selectedRecord.processedAt)}</p>
                      </div>
                    )}
                    
                    {selectedRecord.processingTime && (
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Processing Time</label>
                        <p className="mt-1 text-sm text-gray-900">{selectedRecord.processingTime}ms</p>
                      </div>
                    )}
                    
                  </div>

                  {/* Aadhaar Information */}
                    <div className="border-t pt-4">
                      <h4 className="text-lg font-medium text-gray-900 mb-3">Aadhaar Information</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700">Aadhaar Number</label>
                          <p className="mt-1 text-sm text-gray-900 font-mono">
                          {selectedRecord.aadhaarNumber ? 
                            selectedRecord.aadhaarNumber.replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3') : 
                              '-'
                            }
                          </p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700">Name</label>
                        <p className="mt-1 text-sm text-gray-900">{selectedRecord.name || '-'}</p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700">Gender</label>
                        <p className="mt-1 text-sm text-gray-900">{selectedRecord.gender === 'M' ? 'Male' : selectedRecord.gender === 'F' ? 'Female' : 'Other'}</p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700">Date of Birth</label>
                        <p className="mt-1 text-sm text-gray-900">{selectedRecord.dateOfBirth || '-'}</p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700">District</label>
                        <p className="mt-1 text-sm text-gray-900">{selectedRecord.district || '-'}</p>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700">State</label>
                        <p className="mt-1 text-sm text-gray-900">{selectedRecord.state || '-'}</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Pin Code</label>
                        <p className="mt-1 text-sm text-gray-900">{selectedRecord.pinCode || '-'}</p>
                      </div>
                      <div className="md:col-span-2">
                        <label className="block text-sm font-medium text-gray-700">Address</label>
                        <p className="mt-1 text-sm text-gray-900">{selectedRecord.address || '-'}</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Care Of</label>
                        <p className="mt-1 text-sm text-gray-900">{selectedRecord.careOf || '-'}</p>
                        </div>
                      {selectedRecord.photo && (
                        <div className="md:col-span-2">
                          <label className="block text-sm font-medium text-gray-700">Photo</label>
                          <div className="mt-1">
                            <img 
                              src={`data:image/jpeg;base64,${selectedRecord.photo}`} 
                              alt="Aadhaar Photo" 
                              className="w-24 h-32 object-cover border rounded"
                            />
                          </div>
                        </div>
                      )}
                      {selectedRecord.selfie && (
                        <div className="md:col-span-2">
                          <label className="block text-sm font-medium text-gray-700">Selfie</label>
                          <div className="mt-1">
                            <AuthenticatedImage 
                              recordId={selectedRecord._id}
                              className="w-24 h-32 object-cover border rounded border-pink-300"
                              alt="Selfie"
                              fallback={
                                <div className="w-24 h-32 bg-gray-200 border border-gray-300 rounded flex items-center justify-center">
                                  <span className="text-xs text-gray-500">Error loading</span>
                                </div>
                              }
                            />
                          </div>
                        </div>
                      )}
                      {selectedRecord.dynamicFields && selectedRecord.dynamicFields.length > 0 && (
                        <div className="md:col-span-2">
                          <label className="block text-sm font-medium text-gray-700">Dynamic Fields</label>
                          <div className="mt-1 space-y-2">
                            {selectedRecord.dynamicFields.map((field: any, idx: number) => (
                              <div key={idx} className="flex items-center space-x-2">
                                <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-orange-100 text-orange-800">
                                  <span className="font-semibold">{field.label}:</span>
                                  <span className="ml-1">{field.value}</span>
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Verification Details */}
                  {selectedRecord.verificationDetails && (
                    <div className="border-t pt-4">
                      <h4 className="text-lg font-medium text-gray-900 mb-3">Verification Details</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {selectedRecord.verificationDetails.confidence && (
                          <div>
                            <label className="block text-sm font-medium text-gray-700">Confidence</label>
                            <p className="mt-1 text-sm text-gray-900">{selectedRecord.verificationDetails.confidence}%</p>
                          </div>
                        )}
                        {selectedRecord.verificationDetails.dataMatch !== undefined && (
                          <div>
                            <label className="block text-sm font-medium text-gray-700">Data Match</label>
                            <div className="mt-1 flex items-center">
                              {selectedRecord.verificationDetails.dataMatch ? (
                                <CheckCircleIcon className="w-4 h-4 text-green-500" />
                              ) : (
                                <XCircleIcon className="w-4 h-4 text-red-500" />
                              )}
                              <span className="ml-1 text-sm text-gray-900">
                                {selectedRecord.verificationDetails.dataMatch ? 'Yes' : 'No'}
                              </span>
                            </div>
                          </div>
                        )}
                        {selectedRecord.verificationDetails.remarks && (
                          <div className="md:col-span-2">
                            <label className="block text-sm font-medium text-gray-700">Remarks</label>
                            <p className="mt-1 text-sm text-gray-900">{selectedRecord.verificationDetails.remarks}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
                
                <div className="mt-6 flex justify-end">
                  <button
                    onClick={handleCloseDetails}
                    className="bg-gray-300 text-gray-700 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-500"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AadhaarVerificationRecords;

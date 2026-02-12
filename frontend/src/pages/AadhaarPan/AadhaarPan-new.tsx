import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../contexts/ToastContext';
import api from '../../services/api';
import { 
  DocumentTextIcon, 
  DocumentArrowDownIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  LinkIcon,
  TrashIcon,
  MagnifyingGlassIcon,
  ArrowDownTrayIcon,
  CheckIcon
} from '@heroicons/react/24/outline';
import { validateAadhaar, validatePAN, filterAadhaarInput, filterPANInput } from '../../utils/validation';

interface Batch {
  _id: string;
  totalRecords: number;
  pendingRecords: number;
  linkedRecords: number;
  notLinkedRecords: number;
  invalidRecords: number;
  errorRecords: number;
  createdAt: string;
  updatedAt: string;
}

interface BatchDetail {
  batchId: string;
  records: Record[];
  stats: {
    total: number;
    linked: number;
    'not-linked': number;
    invalid: number;
    error: number;
    pending: number;
  };
}

interface Record {
  _id: string;
  aadhaarNumber: string;
  panNumber: string;
  name: string;
  status: string;
  processedAt?: string;
  processingTime?: number;
}

const AadhaarPan: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [batches, setBatches] = useState<Batch[]>([]);
  const [selectedBatch, setSelectedBatch] = useState<BatchDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const documentsPerPage = 5;
  const batchDetailsRef = useRef<HTMLDivElement>(null);
  
  // Enhanced features from PAN KYC
  const [selectedRecords, setSelectedRecords] = useState<Set<string>>(new Set());
  const [verifying, setVerifying] = useState(false);
  const [verifyingRecords, setVerifyingRecords] = useState<Set<string>>(new Set());
  const [searchTerm, setSearchTerm] = useState('');
  const [currentTablePage, setCurrentTablePage] = useState(1);
  const recordsPerPage = 10;
  
  // Single verification form state
  const [singleVerificationForm, setSingleVerificationForm] = useState({
    aadhaarNumber: '',
    panNumber: '',
    name: ''
  });
  const [singleVerificationVerifying, setSingleVerificationVerifying] = useState(false);
  const [singleVerificationResult, setSingleVerificationResult] = useState<any>(null);

  useEffect(() => {
    fetchBatches();
  }, []);

  // Reset to first page when batches change
  useEffect(() => {
    setCurrentPage(1);
  }, [batches.length]);

  const fetchBatches = async () => {
    try {
      setLoading(true);
      const response = await api.get('/aadhaar-pan/batches');
      setBatches(response.data.data);
    } catch (error: any) {
      console.error('Error fetching batches:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to fetch batches'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteBatch = async (batchId: string) => {
    if (!window.confirm('Are you sure you want to delete this batch? This action cannot be undone.')) {
      return;
    }

    try {
      setLoading(true);
      await api.delete(`/aadhaar-pan/batch/${batchId}`);
      
      showToast({
        type: 'success',
        message: 'Batch deleted successfully'
      });
      
      // Refresh batches list
      await fetchBatches();
      
      // Clear selected batch if it was deleted
      if (selectedBatch && selectedBatch.batchId === batchId) {
        setSelectedBatch(null);
      }
    } catch (error: any) {
      console.error('Error deleting batch:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to delete batch'
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchBatchDetails = async (batchId: string) => {
    try {
      setLoading(true);
      const response = await api.get(`/aadhaar-pan/batch/${batchId}`);
      setSelectedBatch(response.data.data);
      
      // Scroll to batch details
      if (batchDetailsRef.current) {
        batchDetailsRef.current.scrollIntoView({ behavior: 'smooth' });
      }
    } catch (error: any) {
      console.error('Error fetching batch details:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to fetch batch details'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSingleVerificationFormChange = (field: string, value: string) => {
    let filteredValue = value;
    
    if (field === 'aadhaarNumber') {
      filteredValue = filterAadhaarInput(value);
    } else if (field === 'panNumber') {
      filteredValue = filterPANInput(value);
    }
    
    setSingleVerificationForm(prev => ({
      ...prev,
      [field]: filteredValue
    }));
  };

  const validateSingleVerificationForm = () => {
    const { aadhaarNumber, panNumber, name } = singleVerificationForm;
    
    // Validate Aadhaar
    const aadhaarValidation = validateAadhaar(aadhaarNumber);
    if (!aadhaarValidation.isValid) {
      showToast({
        type: 'error',
        message: aadhaarValidation.message || 'Invalid Aadhaar number'
      });
      return false;
    }
    
    // Validate PAN
    const panValidation = validatePAN(panNumber);
    if (!panValidation.isValid) {
      showToast({
        type: 'error',
        message: panValidation.message || 'Invalid PAN number'
      });
      return false;
    }
    
    if (!name.trim()) {
      showToast({
        type: 'error',
        message: 'Name is required'
      });
      return false;
    }
    
    return true;
  };

  const handleSingleVerificationSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateSingleVerificationForm()) {
      return;
    }
    
    try {
      setSingleVerificationVerifying(true);
      
      const response = await api.post('/aadhaar-pan/verify-single', {
        aadhaarNumber: singleVerificationForm.aadhaarNumber.replace(/\s/g, ''),
        panNumber: singleVerificationForm.panNumber.toUpperCase(),
        name: singleVerificationForm.name.trim()
      });
      
      setSingleVerificationResult(response.data.data);
      showToast({
        type: 'success',
        message: 'Aadhaar-PAN linking verification completed'
      });
      
    } catch (error: any) {
      console.error('Error in single verification:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to verify Aadhaar-PAN linking'
      });
    } finally {
      setSingleVerificationVerifying(false);
    }
  };

  const resetSingleVerificationForm = () => {
    setSingleVerificationForm({
      aadhaarNumber: '',
      panNumber: '',
      name: ''
    });
    setSingleVerificationResult(null);
  };

  // Utility functions
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'linked':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'not-linked':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
      case 'invalid':
        return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500" />;
      case 'error':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />;
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
        return 'bg-yellow-100 text-yellow-800';
      case 'error':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-emerald-50 via-teal-50 to-cyan-50 p-6">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header */}
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-r from-emerald-500 to-teal-600 rounded-2xl mb-4 shadow-lg">
            <LinkIcon className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Aadhaar-PAN Linking</h1>
          <p className="text-gray-600 max-w-2xl mx-auto">
            Verify Aadhaar-PAN linking status for individual records. Enter the details below to check if an Aadhaar number is linked to a PAN number.
          </p>
        </div>

        {/* Single Aadhaar-PAN Linking Verification */}
        <div className="bg-white/90 backdrop-blur-sm rounded-2xl p-4 shadow-xl border border-white/30">
          <div className="max-w-xl mx-auto">
            <h2 className="text-xl font-bold text-gray-900 mb-4 text-center">Single Aadhaar-PAN Linking Verification</h2>
            
            <form onSubmit={handleSingleVerificationSubmit} className="space-y-4">
              <div>
                <label htmlFor="aadhaarNumber" className="block text-sm font-medium text-gray-700 mb-1">
                  Aadhaar Number *
                </label>
                <input
                  type="text"
                  id="aadhaarNumber"
                  value={singleVerificationForm.aadhaarNumber}
                  onChange={(e) => handleSingleVerificationFormChange('aadhaarNumber', e.target.value)}
                  placeholder="e.g., 123456789012"
                  className="block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500"
                  maxLength={12}
                />
                <p className="mt-1 text-sm text-gray-500">
                  Enter 12-digit Aadhaar number
                </p>
              </div>

              <div>
                <label htmlFor="panNumber" className="block text-sm font-medium text-gray-700 mb-1">
                  PAN Number *
                </label>
                <input
                  type="text"
                  id="panNumber"
                  value={singleVerificationForm.panNumber}
                  onChange={(e) => handleSingleVerificationFormChange('panNumber', e.target.value)}
                  placeholder="e.g., ABCDE1234F"
                  className="block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500"
                  maxLength={10}
                />
                <p className="mt-1 text-sm text-gray-500">
                  Enter PAN number in format: ABCDE1234F
                </p>
              </div>

              <div>
                <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-2">
                  Full Name *
                </label>
                <input
                  type="text"
                  id="name"
                  value={singleVerificationForm.name}
                  onChange={(e) => handleSingleVerificationFormChange('name', e.target.value)}
                  placeholder="Enter full name as per Aadhaar"
                  className="block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500"
                />
              </div>

              <div className="flex space-x-4">
                <button
                  type="submit"
                  disabled={singleVerificationVerifying}
                  className="flex-1 bg-gradient-to-r from-emerald-500 to-teal-600 text-white py-3 px-6 rounded-xl font-semibold hover:from-emerald-600 hover:to-teal-700 transition-all duration-300 transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                >
                  {singleVerificationVerifying ? (
                    <div className="flex items-center justify-center space-x-2">
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                      <span>Verifying...</span>
                    </div>
                  ) : (
                    'Verify Linking'
                  )}
                </button>
                
                <button
                  type="button"
                  onClick={resetSingleVerificationForm}
                  className="px-6 py-3 border border-gray-300 text-gray-700 rounded-xl font-semibold hover:bg-gray-50 transition-colors"
                >
                  Reset
                </button>
              </div>
            </form>

            {/* Verification Result */}
            {singleVerificationResult && (
              <div className="mt-8 p-6 bg-gray-50 rounded-xl border border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Verification Result</h3>
                <div className="space-y-4">
                  <div className="flex items-center space-x-3">
                    {getStatusIcon(singleVerificationResult.status)}
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(singleVerificationResult.status)}`}>
                      {singleVerificationResult.status}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium text-gray-700">Aadhaar Number:</span>
                      <span className="ml-2 text-gray-600">{singleVerificationResult.aadhaarNumber}</span>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">PAN Number:</span>
                      <span className="ml-2 text-gray-600">{singleVerificationResult.panNumber}</span>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Name:</span>
                      <span className="ml-2 text-gray-600">{singleVerificationResult.name}</span>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Processed At:</span>
                      <span className="ml-2 text-gray-600">
                        {new Date(singleVerificationResult.processedAt).toLocaleString()}
                      </span>
                    </div>
                  </div>
                  
                  {singleVerificationResult.verificationDetails && (
                    <div>
                      <span className="font-medium text-gray-700">Details:</span>
                      <pre className="mt-1 text-sm text-gray-600 bg-white p-3 rounded border overflow-auto">
                        {JSON.stringify(singleVerificationResult.verificationDetails, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AadhaarPan;

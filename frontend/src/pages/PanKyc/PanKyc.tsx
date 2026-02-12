import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../contexts/ToastContext';
import api from '../../services/api';
import { 
  DocumentTextIcon, 
  CloudArrowUpIcon, 
  DocumentArrowDownIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  TrashIcon,
  MagnifyingGlassIcon
} from '@heroicons/react/24/outline';
import { validatePAN, validateDateOfBirth, validateName, filterPANInput, filterNameInput } from '../../utils/validation';

// Auto-format date input function (DD/MM/YYYY format)
const autoFormatDateInput = (inputValue: string): string => {
  // Remove any non-digit characters
  const digitsOnly = inputValue.replace(/[^0-9]/g, '');
  
  let formattedValue = '';
  
  if (digitsOnly.length >= 2) {
    formattedValue = digitsOnly.substring(0, 2);
    if (digitsOnly.length >= 4) {
      formattedValue += '/' + digitsOnly.substring(2, 4);
      if (digitsOnly.length >= 8) {
        formattedValue += '/' + digitsOnly.substring(4, 8);
      } else if (digitsOnly.length > 4) {
        // Handle partial year input
        formattedValue += '/' + digitsOnly.substring(4);
      }
    } else if (digitsOnly.length > 2) {
      // Handle partial month input
      formattedValue += '/' + digitsOnly.substring(2);
    }
  } else {
    formattedValue = digitsOnly;
  }
  
  return formattedValue;
};

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
  records: any[];
  stats: {
    total: number;
    pending: number;
    verified: number;
    rejected: number;
    error: number;
  };
}


const PanKyc: React.FC = () => {
  const { user } = useAuth();
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
  const [batches, setBatches] = useState<Batch[]>([]);
  const [selectedBatch, setSelectedBatch] = useState<BatchDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [selectedRecords, setSelectedRecords] = useState<string[]>([]);
  const [verifying, setVerifying] = useState(false);
  const [verifyingRecords, setVerifyingRecords] = useState<Set<string>>(new Set());
  const [currentPage, setCurrentPage] = useState(1);
  const documentsPerPage = 3;
  const [newlyUploadedBatchId, setNewlyUploadedBatchId] = useState<string | null>(null);
  const batchDetailsRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const hasFetchedBatches = useRef(false);
  
  // Table pagination and search
  const [tableCurrentPage, setTableCurrentPage] = useState(1);
  const [tableRecordsPerPage, setTableRecordsPerPage] = useState(10);
  const [searchTerm, setSearchTerm] = useState('');
  const [filteredRecords, setFilteredRecords] = useState<any[]>([]);

  // Tab state
  const [activeTab, setActiveTab] = useState<'upload' | 'single'>('upload');
  
  // Reset file input when switching tabs
  const handleTabChange = (tab: 'upload' | 'single') => {
    setActiveTab(tab);
    if (tab === 'upload') {
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  // Single KYC form state
  const [singleKycForm, setSingleKycForm] = useState({
    panNumber: '',
    name: '',
    dateOfBirth: ''
  });
  const [singleKycVerifying, setSingleKycVerifying] = useState(false);
  const [singleKycResult, setSingleKycResult] = useState<any>(null);

  // Calendar state
  const [isCalendarOpen, setIsCalendarOpen] = useState(false);
  const [selectedDate, setSelectedDate] = useState<Date | null>(null);
  const [currentMonth, setCurrentMonth] = useState(new Date());
  const calendarRef = useRef<HTMLDivElement>(null);

  // Calendar helper functions
  const formatDateForInput = (date: Date): string => {
    const day = date.getDate().toString().padStart(2, '0');
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const year = date.getFullYear();
    return `${day}/${month}/${year}`;
  };

  const parseDateFromInput = (dateString: string): Date | null => {
    if (!dateString || dateString.length !== 10) return null;
    const [day, month, year] = dateString.split('/').map(Number);
    if (isNaN(day) || isNaN(month) || isNaN(year)) return null;
    return new Date(year, month - 1, day);
  };

  const generateCalendarDays = () => {
    const year = currentMonth.getFullYear();
    const month = currentMonth.getMonth();
    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const startDate = new Date(firstDay);
    startDate.setDate(startDate.getDate() - firstDay.getDay());
    
    const days = [];
    const today = new Date();
    
    for (let i = 0; i < 42; i++) {
      const date = new Date(startDate);
      date.setDate(startDate.getDate() + i);
      
      const isCurrentMonth = date.getMonth() === month;
      const isToday = date.toDateString() === today.toDateString();
      const isSelected = selectedDate && date.toDateString() === selectedDate.toDateString();
      const isFuture = date > today;
      
      days.push({
        date,
        isCurrentMonth,
        isToday,
        isSelected,
        isFuture
      });
    }
    
    return days;
  };

  // Close calendar when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (calendarRef.current && !calendarRef.current.contains(event.target as Node)) {
        setIsCalendarOpen(false);
      }
    };

    if (isCalendarOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isCalendarOpen]);

  // Update selectedDate when dateOfBirth changes
  useEffect(() => {
    if (singleKycForm.dateOfBirth) {
      const parsedDate = parseDateFromInput(singleKycForm.dateOfBirth);
      setSelectedDate(parsedDate);
    } else {
      setSelectedDate(null);
    }
  }, [singleKycForm.dateOfBirth]);

  // Handle calendar date selection
  const handleCalendarDateSelect = (date: Date) => {
    if (date > new Date()) return; // Don't allow future dates
    
    setSelectedDate(date);
    const formattedDate = formatDateForInput(date);
    setSingleKycForm(prev => ({
      ...prev,
      dateOfBirth: formattedDate
    }));
    setIsCalendarOpen(false);
  };

  // Navigation functions
  const navigateMonth = (direction: 'prev' | 'next') => {
    setCurrentMonth(prev => {
      const newMonth = new Date(prev);
      if (direction === 'prev') {
        newMonth.setMonth(prev.getMonth() - 1);
      } else {
        newMonth.setMonth(prev.getMonth() + 1);
      }
      return newMonth;
    });
  };

  // Verification popup state
  const [showVerifyPopup, setShowVerifyPopup] = useState(false);
  const [selectedRecordForVerification, setSelectedRecordForVerification] = useState<any>(null);
  
  // Verify selected popup state
  const [showVerifySelectedPopup, setShowVerifySelectedPopup] = useState(false);

  const fetchBatches = useCallback(async () => {
    // Prevent multiple simultaneous calls
    if (hasFetchedBatches.current || loading) {
      return;
    }

    try {
      setLoading(true);
      const response = await api.get('/pan-kyc/batches');
      setBatches(response.data.data);
      hasFetchedBatches.current = true;
    } catch (error) {
      console.error('Error fetching batches:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch batches'
      });
      hasFetchedBatches.current = false; // Reset on error to allow retry
    } finally {
      setLoading(false);
    }
  }, [loading, showToast]);

  useEffect(() => {
    if (!hasFetchedBatches.current) {
      fetchBatches();
    }
  }, [fetchBatches]);

  // Reset fetch flag when user changes
  useEffect(() => {
    hasFetchedBatches.current = false;
  }, [user?._id]);

  // Reset to first page when batches change
  useEffect(() => {
    setCurrentPage(1);
  }, [batches.length]);



  // Filter and paginate records when selectedBatch or search changes
  useEffect(() => {
    if (selectedBatch) {
      const filtered = selectedBatch.records.filter(record => {
        const searchLower = searchTerm.toLowerCase();
        return (
          record.panNumber?.toLowerCase().includes(searchLower) ||
          record.name?.toLowerCase().includes(searchLower) ||
          record.dateOfBirth?.toLowerCase().includes(searchLower) ||
          record.status?.toLowerCase().includes(searchLower)
        );
      });
      setFilteredRecords(filtered);
      setTableCurrentPage(1); // Reset to first page when search changes
    }
  }, [selectedBatch, searchTerm]);

  const refreshBatches = async () => {
    hasFetchedBatches.current = false;
    await fetchBatches();
  };

  const fetchBatchDetails = async (batchId: string) => {
    try {
      setLoading(true);
      const response = await api.get(`/pan-kyc/batch/${batchId}`);
      setSelectedBatch(response.data.data);
      
      // Scroll to the top of the batch details section
      setTimeout(() => {
        if (batchDetailsRef.current) {
          batchDetailsRef.current.scrollIntoView({ 
            behavior: 'smooth', 
            block: 'start' 
          });
        }
        
        // Also scroll the table to the top if it exists
        const tableElement = document.querySelector('.overflow-x-auto');
        if (tableElement) {
          tableElement.scrollTop = 0;
        }
      }, 100);
          } catch (error) {
        console.error('Error fetching batch details:', error);
        showToast({
          type: 'error',
          message: 'Failed to fetch batch details'
        });
      } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    console.log('File selected:', file);
    console.log('File name:', file?.name);
    console.log('File size:', file?.size);
    console.log('File type:', file?.type);
    
    if (file) {
      const allowedTypes = ['.xlsx', '.xls'];
      const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
      console.log('File extension:', fileExtension);
      
      if (!allowedTypes.includes(fileExtension)) {
        showToast({
          type: 'error',
          message: 'Please select an Excel file (.xlsx or .xls)'
        });
        return;
      }
      
      if (file.size > 10 * 1024 * 1024) { // 10MB
        showToast({
          type: 'error',
          message: 'File size must be less than 10MB'
        });
        return;
      }
      
      setSelectedFile(file);
      console.log('File set successfully:', file);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      showToast({
        type: 'error',
        message: 'Please select a file to upload'
      });
      return;
    }

    try {
      setUploading(true);

      const formData = new FormData();
      console.log('Selected file before FormData:', selectedFile);
      console.log('Selected file name:', selectedFile?.name);
      console.log('Selected file size:', selectedFile?.size);
      formData.append('file', selectedFile);
      console.log('FormData created');
      console.log('FormData entries:');
      formData.forEach((value, key) => {
        console.log(key, value);
      });
      const response = await api.post('/pan-kyc/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent: any) => {
          if (progressEvent.total) {
            const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            setUploadProgress(progress);
          }
        },
      });

      showToast({
        type: 'success',
        message: `Successfully uploaded ${response.data.data.recordCount} records`
      });
      setSelectedFile(null);
      setUploadProgress(0);
      
      // Reset the file input element
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      
      // Fetch updated batches list
      await refreshBatches();
      
      // Automatically fetch and display the newly uploaded batch
      if (response.data.data.batchId) {
        setNewlyUploadedBatchId(response.data.data.batchId);
        await fetchBatchDetails(response.data.data.batchId);
        
        // Scroll to the top of the batch details section
        setTimeout(() => {
          if (batchDetailsRef.current) {
            batchDetailsRef.current.scrollIntoView({ 
              behavior: 'smooth', 
              block: 'start' 
            });
          }
          
          // Also scroll the table to the top if it exists
          const tableElement = document.querySelector('.overflow-x-auto');
          if (tableElement) {
            tableElement.scrollTop = 0;
          }
        }, 100);
        
        // Clear the "new upload" indicator after 5 seconds
        setTimeout(() => {
          setNewlyUploadedBatchId(null);
        }, 5000);
      }
    } catch (error: any) {
      console.error('Error uploading file:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to upload file'
      });
    } finally {
      setUploading(false);
    }
  };

  const handleDownloadReport = async (batchId: string) => {
    try {
      const response = await api.get(`/pan-kyc/batch/${batchId}/download`, {
        responseType: 'blob',
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${batchId}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error downloading report:', error);
      showToast({
        type: 'error',
        message: 'Failed to download report'
      });
    }
  };

  const handleRecordSelection = (recordId: string) => {
    setSelectedRecords(prev => 
      prev.includes(recordId) 
        ? prev.filter(id => id !== recordId)
        : [...prev, recordId]
    );
  };

  const handleSelectAll = () => {
    if (selectedBatch) {
      const pendingRecordIds = filteredRecords
        .filter(record => record.status === 'pending')
        .map(record => record._id);
      
      setSelectedRecords(prev => 
        prev.length === pendingRecordIds.length ? [] : pendingRecordIds
      );
    }
  };

  const handleVerifySelected = () => {
    if (selectedRecords.length === 0) {
      showToast({
        type: 'error',
        message: 'Please select records to verify'
      });
      return;
    }

    // Open the verify selected popup
    setShowVerifySelectedPopup(true);
  };

  const handleVerifySelectedFromPopup = async () => {
    if (selectedRecords.length === 0) return;

    try {
      setVerifying(true);
      setVerifyingRecords(new Set(selectedRecords));
      const response = await api.post('/pan-kyc/verify', {
        recordIds: selectedRecords
      });
      
      // Show dynamic toast message based on verification results
      if (response.data.success && response.data.data && response.data.data.results) {
        const results = response.data.data.results;
        const verifiedCount = results.filter((r: any) => r.status === 'verified').length;
        const rejectedCount = results.filter((r: any) => r.status === 'rejected').length;
        
        if (verifiedCount === results.length) {
      showToast({
        type: 'success',
            message: `Successfully verified all ${results.length} records`
          });
        } else if (rejectedCount === results.length) {
          showToast({
            type: 'error',
            message: `All ${results.length} records failed verification - data mismatch detected`
          });
        } else {
          showToast({
            type: 'warning',
            message: `Verification completed: ${verifiedCount} verified, ${rejectedCount} rejected`
          });
        }
      } else {
        showToast({
          type: 'error',
          message: 'Batch verification failed'
        });
      }
      setSelectedRecords([]);
      
      // Close popup
      setShowVerifySelectedPopup(false);
      
      // Refresh batch details
      if (selectedBatch) {
        await fetchBatchDetails(selectedBatch.batchId);
      }
      
      // Refresh batches list
      await refreshBatches();
    } catch (error) {
      console.error('Error verifying records:', error);
      showToast({
        type: 'error',
        message: 'Failed to verify selected records'
      });
    } finally {
      setVerifying(false);
      setVerifyingRecords(new Set());
    }
  };

  const handleVerifySingle = (recordId: string) => {
    // Find the record to show in popup
    const record = selectedBatch?.records.find(r => r._id === recordId);
    if (!record) return;

    // Set the selected record and open popup
    setSelectedRecordForVerification(record);
    setShowVerifyPopup(true);
  };

  const handleVerifyFromPopup = async () => {
    if (!selectedRecordForVerification) return;

    try {
      setVerifyingRecords(new Set([selectedRecordForVerification._id]));
      const response = await api.post('/pan-kyc/verify', {
        recordIds: [selectedRecordForVerification._id]
      });
      
      // Show dynamic toast message based on verification results
      if (response.data.success && response.data.data && response.data.data.results && response.data.data.results.length > 0) {
        const result = response.data.data.results[0];
        const isSuccess = result.status === 'verified';
      showToast({
          type: isSuccess ? 'success' : 'error',
          message: isSuccess ? 'Record verified successfully' : 'Record verification failed - data mismatch detected'
        });
      } else {
        showToast({
          type: 'error',
          message: 'Verification failed'
        });
      }
      
      // Close popup
      setShowVerifyPopup(false);
      setSelectedRecordForVerification(null);
      
      // Refresh batch details
      if (selectedBatch) {
        await fetchBatchDetails(selectedBatch.batchId);
      }
      
      // Refresh batches list
      await refreshBatches();
    } catch (error) {
      console.error('Error verifying record:', error);
      showToast({
        type: 'error',
        message: 'Failed to verify record'
      });
    } finally {
      setVerifyingRecords(new Set());
    }
  };

  const handleDeleteBatch = async (batchId: string) => {
    if (!window.confirm('Are you sure you want to delete this batch? This action cannot be undone.')) {
      return;
    }

    try {
      setLoading(true);
      const response = await api.delete(`/pan-kyc/batch/${batchId}`);
      
      showToast({
        type: 'success',
        message: `Successfully deleted batch with ${response.data.data.deletedRecords} records`
      });
      
      // Clear selected batch if it was the one deleted
      if (selectedBatch && selectedBatch.batchId === batchId) {
        setSelectedBatch(null);
        setSelectedRecords([]); // Clear selected records
      }
      
      // Refresh batches list
      await refreshBatches();
    } catch (error) {
      console.error('Error deleting batch:', error);
      showToast({
        type: 'error',
        message: 'Failed to delete batch'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadTableData = () => {
    if (!selectedBatch || filteredRecords.length === 0) {
      showToast({
        type: 'error',
        message: 'No data to download'
      });
      return;
    }

    try {
      // Create CSV content
      const headers = ['PAN Number', 'Name', 'Date of Birth', 'Processed At'];
      const csvContent = [
        headers.join(','),
        ...filteredRecords.map(record => [
          record.panNumber || '',
          record.name || '',
          record.dateOfBirth || '',
          record.processedAt ? new Date(record.processedAt).toLocaleString() : ''
        ].join(','))
      ].join('\n');

      // Create and download file
      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${selectedBatch.batchId}_table_data.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      showToast({
        type: 'success',
        message: 'Table data downloaded successfully'
      });
    } catch (error) {
      console.error('Error downloading table data:', error);
      showToast({
        type: 'error',
        message: 'Failed to download table data'
      });
    }
  };

  // Single KYC form functions
  const handleSingleKycFormChange = (field: string, value: string) => {
    if (field === 'panNumber') {
      const filteredValue = filterPANInput(value);
      setSingleKycForm(prev => ({
        ...prev,
        [field]: filteredValue
      }));
    } else if (field === 'dateOfBirth') {
      // Auto-format date input to DD/MM/YYYY
      const formattedValue = autoFormatDateInput(value);
      setSingleKycForm(prev => ({
        ...prev,
        [field]: formattedValue
      }));
    } else if (field === 'name') {
      const filteredValue = filterNameInput(value);
      setSingleKycForm(prev => ({
        ...prev,
        [field]: filteredValue
      }));
    } else {
      setSingleKycForm(prev => ({
        ...prev,
        [field]: value
      }));
    }
  };


  // Function to validate PAN format
  const isValidPANFormat = (pan: string) => {
    const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
    return panRegex.test(pan);
  };

  const validateSingleKycForm = () => {
    // Validate PAN
    const panValidation = validatePAN(singleKycForm.panNumber);
    if (!panValidation.isValid) {
      showToast({
        type: 'error',
        message: panValidation.message || 'Invalid PAN number'
      });
      return false;
    }
    
    // Validate Name
    const nameValidation = validateName(singleKycForm.name);
    if (!nameValidation.isValid) {
      showToast({
        type: 'error',
        message: nameValidation.message || 'Invalid name'
      });
      return false;
    }
    
    // Validate Date of Birth
    const dobValidation = validateDateOfBirth(singleKycForm.dateOfBirth);
    if (!dobValidation.isValid) {
      showToast({
        type: 'error',
        message: dobValidation.message || 'Invalid date of birth'
      });
      return false;
    }

    return true;
  };

  const handleSingleKycSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateSingleKycForm()) {
      return;
    }

    try {
      setSingleKycVerifying(true);
      setSingleKycResult(null);

      // Create a temporary record for verification
      const tempRecord = {
        panNumber: singleKycForm.panNumber.toUpperCase(),
        name: singleKycForm.name.trim(),
        dateOfBirth: singleKycForm.dateOfBirth.trim()
      };

      // Call the verification API
      const response = await api.post('/pan-kyc/verify-single', tempRecord);
      
      setSingleKycResult(response.data.data);
      
      // Show dynamic toast message based on verification status
      const isSuccess = response.data.data.status === 'verified';
      showToast({
        type: isSuccess ? 'success' : 'error',
        message: response.data.message || (isSuccess ? 'KYC verification completed successfully' : 'KYC verification failed')
      });
      
      // Reset form
      setSingleKycForm({
        panNumber: '',
        name: '',
        dateOfBirth: ''
      });
    } catch (error: any) {
      console.error('Error verifying single KYC:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to verify KYC'
      });
    } finally {
      setSingleKycVerifying(false);
    }
  };

  const resetSingleKycForm = () => {
    setSingleKycForm({
      panNumber: '',
      name: '',
      dateOfBirth: ''
    });
    setSingleKycResult(null);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'verified':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'rejected':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
      case 'error':
        return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500" />;
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
      case 'error':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50 relative overflow-hidden">
      {/* Full Page Loader for Verify Selected */}
      {verifying && (
        <div className="fixed inset-0 bg-gradient-to-br from-indigo-900/95 via-purple-900/95 to-pink-900/95 backdrop-blur-xl flex items-center justify-center z-50">
          <div className="text-center">
            {/* Stunning wave loader */}
            <div className="relative mb-8">
              <div className="w-32 h-32 mx-auto relative">
                {/* Outer wave rings */}
                <div className="absolute inset-0 rounded-full border-4 border-cyan-400/20 animate-ping"></div>
                <div className="absolute inset-2 rounded-full border-4 border-blue-400/30 animate-ping" style={{ animationDelay: '0.5s' }}></div>
                <div className="absolute inset-4 rounded-full border-4 border-purple-400/40 animate-ping" style={{ animationDelay: '1s' }}></div>
                
                {/* Main verification icon */}
                <div className="absolute inset-6 rounded-full bg-gradient-to-r from-green-400 via-emerald-500 to-teal-500 flex items-center justify-center animate-pulse">
                  <svg className="w-8 h-8 text-white animate-bounce" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                </div>
                
                {/* Rotating verification dots */}
                <div className="absolute inset-0 animate-spin" style={{ animationDuration: '4s' }}>
                  <div className="absolute top-0 left-1/2 transform -translate-x-1/2 -translate-y-2 w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
                  <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 translate-y-2 w-3 h-3 bg-blue-400 rounded-full animate-pulse"></div>
                  <div className="absolute left-0 top-1/2 transform -translate-y-1/2 -translate-x-2 w-3 h-3 bg-purple-400 rounded-full animate-pulse"></div>
                  <div className="absolute right-0 top-1/2 transform -translate-y-1/2 translate-x-2 w-3 h-3 bg-pink-400 rounded-full animate-pulse"></div>
                </div>
              </div>
              
              {/* Floating verification badges */}
              <div className="absolute -top-6 -right-6 w-6 h-6 bg-green-400 rounded-full animate-bounce flex items-center justify-center" style={{ animationDelay: '0s' }}>
                <span className="text-white text-xs font-bold">✓</span>
              </div>
              <div className="absolute -bottom-6 -left-6 w-5 h-5 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0.8s' }}>
                <div className="w-full h-full rounded-full bg-white/30 animate-ping"></div>
              </div>
              <div className="absolute -top-4 -left-8 w-4 h-4 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '1.6s' }}>
                <div className="w-full h-full rounded-full bg-white/40 animate-pulse"></div>
              </div>
            </div>
            
            <h3 className="text-3xl font-bold bg-gradient-to-r from-green-400 via-blue-400 to-purple-400 bg-clip-text text-transparent mb-3 animate-pulse">
              Verifying Records
            </h3>
            <p className="text-gray-300 text-lg mb-6">Please wait while we verify {selectedRecords.length} selected records...</p>
            
            {/* Beautiful wave progress */}
            <div className="w-80 mx-auto mb-6">
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm text-gray-400">Progress</span>
                <span className="text-sm text-gray-400">75%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2 overflow-hidden">
                <div className="h-full bg-gradient-to-r from-green-400 via-blue-500 to-purple-500 rounded-full relative" style={{ width: '75%' }}>
                  <div className="absolute inset-0 bg-white/20 rounded-full animate-pulse"></div>
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent rounded-full animate-pulse" style={{ animationDuration: '2s' }}></div>
                </div>
              </div>
            </div>
            
            {/* Animated status steps */}
            <div className="flex justify-center space-x-8">
              <div className="flex flex-col items-center">
                <div className="w-4 h-4 bg-green-400 rounded-full animate-pulse mb-2"></div>
                <span className="text-sm text-green-400 font-medium">Processing</span>
              </div>
              <div className="flex flex-col items-center">
                <div className="w-4 h-4 bg-blue-400 rounded-full animate-pulse mb-2" style={{ animationDelay: '0.5s' }}></div>
                <span className="text-sm text-blue-400 font-medium">Verifying</span>
              </div>
              <div className="flex flex-col items-center">
                <div className="w-4 h-4 bg-purple-400 rounded-full animate-pulse mb-2" style={{ animationDelay: '1s' }}></div>
                <span className="text-sm text-purple-400 font-medium">Finalizing</span>
              </div>
            </div>
          </div>
        </div>
      )}
      {/* Animated Background Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-10 w-72 h-72 bg-blue-400/10 rounded-full blur-3xl animate-float"></div>
        <div className="absolute top-40 right-20 w-96 h-96 bg-purple-400/10 rounded-full blur-3xl animate-float" style={{ animationDelay: '2s' }}></div>
        <div className="absolute bottom-20 left-1/4 w-80 h-80 bg-indigo-400/10 rounded-full blur-3xl animate-float" style={{ animationDelay: '4s' }}></div>
      </div>
      
      <div className="relative z-10 space-y-8 p-6">
              <div className="bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-700 rounded-3xl p-8 text-white shadow-2xl border border-white/20 backdrop-blur-xl relative overflow-hidden">
          {/* Header Background Pattern */}
          <div className="absolute inset-0 bg-gradient-to-br from-white/10 to-transparent"></div>
          <div className="absolute top-0 right-0 w-32 h-32 bg-white/5 rounded-full blur-2xl"></div>
          <div className="relative z-10 flex items-center justify-between">
                      <div>
              <h1 className="text-3xl font-bold tracking-tight drop-shadow-lg">PAN KYC Verification</h1>
              <p className="text-blue-100 mt-2 text-base font-medium">
                Upload Excel files and verify PAN details in bulk with advanced verification
              </p>
            </div>
                      <div className="flex items-center space-x-3">
            <button
              onClick={refreshBatches}
              disabled={loading}
              className="inline-flex items-center px-4 py-2 bg-white/20 backdrop-blur-sm hover:bg-white/30 text-white font-semibold rounded-xl transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-white/50 focus:ring-offset-2 focus:ring-offset-transparent border border-white/30 hover:border-white/50 hover:scale-105 transform disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ArrowPathIcon className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button
              onClick={() => window.location.href = '/pan-kyc-records'}
              className="inline-flex items-center px-6 py-3 bg-white/20 backdrop-blur-sm hover:bg-white/30 text-white font-semibold rounded-2xl transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-white/50 focus:ring-offset-2 focus:ring-offset-transparent border border-white/30 hover:border-white/50 hover:scale-105 transform"
            >
            <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            View All Records
          </button>
          </div>
        </div>
      </div>



      {/* Tab Navigation */}
      <div className="bg-white/80 backdrop-blur-sm rounded-3xl p-2 shadow-xl border border-white/20">
        <nav className="flex space-x-2">
          <button
            onClick={() => handleTabChange('upload')}
            className={`py-2 px-4 rounded-xl font-semibold text-xs transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'upload'
                ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white shadow-lg border border-white/30'
                : 'text-slate-600 hover:text-slate-800 hover:bg-slate-50/80'
            }`}
          >
            <div className="flex items-center space-x-2">
              <CloudArrowUpIcon className="h-5 w-5" />
              <span>Upload File</span>
            </div>
          </button>
          <button
            onClick={() => handleTabChange('single')}
            className={`py-2 px-4 rounded-xl font-semibold text-xs transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'single'
                ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white shadow-lg border border-white/30'
                : 'text-slate-600 hover:text-slate-800 hover:bg-slate-50/80'
            }`}
          >
            <div className="flex items-center space-x-2">
              <DocumentTextIcon className="h-5 w-5" />
              <span>Single KYC</span>
            </div>
          </button>
        </nav>
      </div>

      {/* Upload Tab Content */}
      {activeTab === 'upload' && (
        <>
          {/* Enhanced File Upload Section */}
          <div className="bg-gradient-to-br from-blue-50 via-purple-50 to-indigo-50 rounded-3xl p-8 shadow-2xl border border-blue-100/50 relative overflow-hidden">
            {/* Background Pattern */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-blue-200/20 rounded-full blur-3xl"></div>
            <div className="absolute bottom-0 left-0 w-40 h-40 bg-purple-200/20 rounded-full blur-3xl"></div>
            
            <div className="relative z-10">

              {/* File Input Area */}
              <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-6 border-2 border-dashed border-blue-300/50 hover:border-blue-400/70 transition-all duration-300 mb-6">
                <div className="text-center">
                  <h3 className="text-base font-semibold text-blue-800 mb-2 flex items-center justify-center">
                    <DocumentTextIcon className="h-5 w-5 mr-2 text-blue-600" />
                    Select Excel File
                  </h3>
                  <p className="text-blue-600/70 mb-4">
                    Supports .xlsx and .xls formats
                  </p>
                  
                  {/* Centered File Input */}
                  <div className="flex justify-center mb-4">
                    <div className="relative">
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept=".xlsx,.xls"
                        onChange={handleFileSelect}
                        className="hidden"
                        id="file-input"
                      />
                      <label
                        htmlFor="file-input"
                        className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold text-base rounded-xl shadow-xl hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-300 cursor-pointer border-2 border-transparent hover:border-blue-400/30"
                      >
                        <DocumentTextIcon className="h-6 w-6 mr-3" />
                        Choose File
                      </label>
                    </div>
                  </div>
                  
                  <div className="mt-4 flex flex-col sm:flex-row items-center justify-center gap-3">
                    <p className="text-xs text-blue-500/70">
                      Required columns: <span className="font-semibold">panNumber</span>, <span className="font-semibold">name</span>, <span className="font-semibold">dateOfBirth</span>
                    </p>
                    <button
                      type="button"
                      onClick={() => {
                        // Import xlsx dynamically
                        import('xlsx').then((XLSX) => {
                          // Create sample data
                          const sampleData = [
                            ['panNumber', 'name', 'dateOfBirth'],
                            ['ABCDE1234F', 'John Doe', '15/03/1990'],
                            ['FGHIJ5678K', 'Jane Smith', '22/11/1985'],
                            ['LMNOP9012Q', 'Bob Johnson', '08/07/1992']
                          ];
                          
                          // Create workbook and worksheet
                          const wb = XLSX.utils.book_new();
                          const ws = XLSX.utils.aoa_to_sheet(sampleData);
                          
                          // Set column widths for better readability
                          ws['!cols'] = [
                            { wch: 15 }, // panNumber
                            { wch: 20 }, // name
                            { wch: 15 }  // dateOfBirth
                          ];
                          
                          // Add worksheet to workbook
                          XLSX.utils.book_append_sheet(wb, ws, 'PAN KYC Data');
                          
                          // Generate Excel file buffer
                          const excelBuffer = XLSX.write(wb, { 
                            type: 'array', 
                            bookType: 'xlsx',
                            cellStyles: true
                          });
                          
                          // Create blob and download
                          const blob = new Blob([excelBuffer], { 
                            type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' 
                          });
                          const url = window.URL.createObjectURL(blob);
                          const link = document.createElement('a');
                          link.href = url;
                          link.setAttribute('download', 'sample_pan_kyc.xlsx');
                          document.body.appendChild(link);
                          link.click();
                          link.remove();
                          window.URL.revokeObjectURL(url);
                        }).catch((error) => {
                          console.error('Error generating Excel file:', error);
                          alert('Failed to generate sample file. Please try again.');
                        });
                      }}
                      className="inline-flex items-center px-3 py-1.5 bg-green-500 text-white text-xs font-medium rounded-lg hover:bg-green-600 transition-colors"
                    >
                      <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      Download Sample
                    </button>
                  </div>
                </div>
              </div>


              {/* Selected File Display */}
              {selectedFile && (
                <div className="bg-gradient-to-r from-blue-500/20 to-purple-500/20 rounded-2xl p-6 border border-blue-200/50 mb-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center">
                      <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center mr-4">
                        <DocumentTextIcon className="h-6 w-6 text-white" />
                      </div>
                      <div>
                        <p className="text-base font-semibold text-blue-900">{selectedFile.name}</p>
                        <p className="text-blue-700">
                          {(selectedFile.size / 1024).toFixed(2)} KB
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => {
                        setSelectedFile(null);
                        if (fileInputRef.current) {
                          fileInputRef.current.value = '';
                        }
                      }}
                      className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-xl transition-all duration-300 hover:scale-105"
                    >
                      Clear
                    </button>
                  </div>
                </div>
              )}

              {/* Upload Progress */}
              {uploading && (
                <div className="bg-white/80 rounded-2xl p-6 border border-blue-200/50 mb-6">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-base font-semibold text-blue-800">Uploading...</span>
                    <span className="text-base font-bold text-blue-600">{uploadProgress}%</span>
                  </div>
                  <div className="w-full bg-blue-100 rounded-full h-3 overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-blue-500 to-purple-600 h-3 rounded-full transition-all duration-300 shadow-lg"
                      style={{ width: `${uploadProgress}%` }}
                    ></div>
                  </div>
                </div>
              )}

              {/* Upload Button */}
              <div className="text-center">
                <button
                  onClick={handleUpload}
                  disabled={!selectedFile || uploading}
                  className="inline-flex items-center px-8 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold text-base rounded-xl shadow-2xl hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 disabled:cursor-not-allowed"
                >
                  {uploading ? (
                    <>
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>
                      Uploading...
                    </>
                  ) : (
                    <>
                      <CloudArrowUpIcon className="h-6 w-6 mr-3" />
                      Upload File
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Batches List */}
          <div className="bg-white/80 backdrop-blur-xl rounded-3xl p-8 shadow-2xl border border-white/30 hover:shadow-3xl transition-all duration-300">
            <h2 className="text-xl font-bold text-slate-800 mb-4 flex items-center">
              <DocumentTextIcon className="h-7 w-7 text-emerald-500 mr-3" />
              Uploaded Documents
            </h2>
            
            {/* Search Bar */}
            <div className="mb-6">
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search batches by ID, date, or records..."
                  className="w-full px-4 py-3 pl-10 bg-white/60 backdrop-blur-sm border border-white/30 rounded-2xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all duration-300"
                />
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-slate-400" />
              </div>
            </div>
            
            {loading ? (
              <div className="flex items-center justify-center h-32">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : batches.length === 0 ? (
              <div className="text-center py-12">
                <div className="w-24 h-24 bg-gradient-to-br from-slate-100 to-slate-200 rounded-full flex items-center justify-center mx-auto mb-4">
                  <DocumentTextIcon className="h-12 w-12 text-slate-400" />
                </div>
                <h3 className="text-base font-semibold text-slate-600 mb-2">No Documents Yet</h3>
                <p className="text-slate-500 mb-4">Upload your first PAN KYC document to get started</p>
                <button className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold rounded-2xl hover:from-blue-600 hover:to-purple-700 transition-all duration-300 transform hover:scale-105">
                  <CloudArrowUpIcon className="h-5 w-4 mr-2" />
                  Upload First Document
                </button>
              </div>
            ) : (
              <>
                <div className="grid gap-4">
                  {batches
                    .slice((currentPage - 1) * documentsPerPage, currentPage * documentsPerPage)
                    .map((batch) => (
                    <div
                      key={batch._id}
                      className={`group relative bg-white/60 backdrop-blur-sm rounded-2xl p-6 cursor-pointer transition-all duration-300 transform hover:scale-105 ${
                        selectedBatch && selectedBatch.batchId === batch._id
                          ? 'ring-2 ring-blue-500/50 bg-gradient-to-r from-blue-50/80 to-purple-50/80 shadow-xl'
                          : 'border border-white/40 hover:border-blue-200/50 hover:shadow-lg'
                      } ${newlyUploadedBatchId === batch._id ? 'animate-pulse ring-2 ring-emerald-500/50' : ''}`}
                      onClick={() => fetchBatchDetails(batch._id)}
                    >
                      {/* Active Indicator */}
                      {selectedBatch && selectedBatch.batchId === batch._id && (
                        <div className="absolute top-4 right-4 w-3 h-3 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full animate-pulse"></div>
                      )}
                      
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex-1">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-3">
                              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center">
                                <DocumentTextIcon className="h-5 w-5 text-white" />
                              </div>
                              <div>
                                <h3 className="text-lg font-semibold text-slate-800 group-hover:text-blue-600 transition-colors">
                                  {batch._id.split('_')[0]}
                                </h3>
                                <p className="text-sm text-slate-500">
                                  Uploaded {new Date(batch.createdAt).toLocaleDateString('en-US', {
                                    year: 'numeric',
                                    month: 'short',
                                    day: 'numeric',
                                    hour: '2-digit',
                                    minute: '2-digit'
                                  })}
                                </p>
                              </div>
                            </div>
                            
                            {/* Stats Display - Moved to the right side */}
                            <div className="flex items-center gap-3">
                              <div className="text-center p-2 bg-gradient-to-br from-blue-50 to-blue-100 rounded-lg">
                                <div className="text-lg font-bold text-blue-600">{batch.totalRecords}</div>
                                <div className="text-xs text-blue-600 font-medium">Total</div>
                              </div>
                              <div className="text-center p-2 bg-gradient-to-br from-green-50 to-green-100 rounded-lg">
                                <div className="text-lg font-bold text-green-600">{batch.verifiedRecords}</div>
                                <div className="text-xs text-green-600 font-medium">Verified</div>
                              </div>
                              <div className="text-center p-2 bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-lg">
                                <div className="text-lg font-bold text-yellow-600">{batch.pendingRecords}</div>
                                <div className="text-xs text-yellow-600 font-medium">Pending</div>
                              </div>
                              <div className="text-center p-2 bg-gradient-to-br from-red-50 to-red-100 rounded-lg">
                                <div className="text-lg font-bold text-red-600">{batch.rejectedRecords + batch.errorRecords}</div>
                                <div className="text-xs text-red-600 font-medium">Issues</div>
                              </div>
                            </div>
                          </div>
                        </div>
                        
                        {/* Quick Actions */}
                        <div className="flex gap-2 ml-4">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDownloadReport(batch._id);
                            }}
                            className="p-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-xl hover:from-blue-600 hover:to-purple-700 transition-all duration-300 transform hover:scale-110"
                            title="Download Report"
                          >
                            <DocumentArrowDownIcon className="h-5 w-5" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteBatch(batch._id);
                            }}
                            className="p-2 bg-gradient-to-r from-red-500 to-pink-600 text-white rounded-xl hover:from-red-600 hover:to-pink-700 transition-all duration-300 transform hover:scale-110"
                            title="Delete Batch"
                          >
                            <TrashIcon className="h-5 w-5" />
                          </button>
                        </div>
                      </div>
                      
                      {/* Progress Bar for Processing */}
                      <div className="mt-4">
                        <div className="flex justify-between text-sm text-slate-600 mb-2">
                          <span>Processing Progress</span>
                          <span>{Math.round(((batch.verifiedRecords + batch.rejectedRecords + batch.errorRecords) / batch.totalRecords) * 100)}%</span>
                        </div>
                        <div className="w-full bg-slate-200 rounded-full h-2 overflow-hidden">
                          <div className="h-full bg-gradient-to-r from-blue-500 to-purple-600 rounded-full transition-all duration-500" 
                               style={{ width: `${((batch.verifiedRecords + batch.rejectedRecords + batch.errorRecords) / batch.totalRecords) * 100}%` }}>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                
                {/* Enhanced Pagination */}
                {batches.length > documentsPerPage && (
                  <div className="flex flex-col sm:flex-row items-center justify-between mt-8 p-6 bg-white/60 backdrop-blur-sm rounded-2xl border border-white/30">
                    <div className="text-sm text-slate-600 mb-4 sm:mb-0">
                      {currentPage === 1 ? (
                        <>Showing latest <span className="font-semibold text-slate-800">{Math.min(documentsPerPage, batches.length)}</span> of <span className="font-semibold text-slate-800">{batches.length}</span> documents</>
                      ) : (
                        <>Showing <span className="font-semibold text-slate-800">{((currentPage - 1) * documentsPerPage) + 1}</span> to <span className="font-semibold text-slate-800">{Math.min(currentPage * documentsPerPage, batches.length)}</span> of <span className="font-semibold text-slate-800">{batches.length}</span> documents</>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                        disabled={currentPage === 1}
                        className="px-4 py-2 text-sm font-medium rounded-xl border border-white/40 bg-white/60 backdrop-blur-sm text-slate-700 hover:bg-white/80 hover:border-white/60 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300"
                      >
                        ← Previous
                      </button>
                      <div className="px-4 py-2 text-sm font-medium text-slate-700 bg-white/60 backdrop-blur-sm rounded-xl border border-white/30">
                        Page {currentPage} of {Math.ceil(batches.length / documentsPerPage)}
                      </div>
                      <button
                        onClick={() => setCurrentPage(prev => Math.min(prev + 1, Math.ceil(batches.length / documentsPerPage)))}
                        disabled={currentPage === Math.ceil(batches.length / documentsPerPage)}
                        className="px-4 py-2 text-sm font-medium rounded-xl border border-white/40 bg-white/60 backdrop-blur-sm text-slate-700 hover:bg-white/80 hover:border-white/60 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300"
                      >
                        Next →
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Batch Details */}
          {selectedBatch && (
            <div className="card" ref={batchDetailsRef}>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-medium text-gray-900">
                  Document Details: {selectedBatch.batchId.split('_')[0]}
                </h2>
                {newlyUploadedBatchId === selectedBatch.batchId && (
                  <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 animate-pulse">
                    ✨ New Upload
                  </span>
                )}
              </div>
              
              <div className="mb-4">
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <div className="bg-gray-50 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-gray-900">{selectedBatch.stats.total}</div>
                    <div className="text-sm text-gray-500">Total</div>
                  </div>
                  <div className="bg-blue-50 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-blue-900">{selectedBatch.stats.pending}</div>
                    <div className="text-sm text-blue-500">Pending</div>
                  </div>
                  <div className="bg-green-50 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-green-900">{selectedBatch.stats.verified}</div>
                    <div className="text-sm text-green-500">Verified</div>
                  </div>
                  <div className="bg-red-50 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-red-900">{selectedBatch.stats.rejected}</div>
                    <div className="text-sm text-red-500">Rejected</div>
                  </div>
                  <div className="bg-yellow-50 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-yellow-900">{selectedBatch.stats.error}</div>
                    <div className="text-sm text-yellow-500">Error</div>
                  </div>
                </div>
              </div>

              {/* Enhanced Table Controls */}
              <div className="bg-white rounded-2xl p-6 border border-gray-100 shadow-lg mb-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-600 rounded-xl flex items-center justify-center">
                        <input
                          type="checkbox"
                          checked={selectedRecords.length === filteredRecords.length && filteredRecords.length > 0}
                          onChange={handleSelectAll}
                          className="w-4 h-4 rounded border-gray-300 text-white focus:ring-blue-500"
                        />
                      </div>
                      <span className="text-sm font-medium text-gray-700">
                        {selectedRecords.length} of {filteredRecords.length} selected
                      </span>
                    </div>
                    {selectedRecords.length > 0 && (
                      <button
                        onClick={handleVerifySelected}
                        disabled={verifying}
                        className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-medium rounded-xl shadow-lg hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {verifying ? (
                          <>
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                            Verifying...
                          </>
                        ) : (
                          <>
                            <CheckCircleIcon className="h-4 w-4 mr-2" />
                            Verify Selected ({selectedRecords.length})
                          </>
                        )}
                      </button>
                    )}
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className="relative">
                      <MagnifyingGlassIcon className="h-5 w-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                      <input
                        type="text"
                        placeholder="Search by PAN, Name, DOB, or Status..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="pl-10 pr-4 py-2 border border-gray-200 rounded-xl text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                      />
                    </div>
                    <div className="flex items-center space-x-2">
                      <label className="text-sm font-medium text-gray-600">Show:</label>
                      <select
                        value={tableRecordsPerPage}
                        onChange={(e) => {
                          setTableRecordsPerPage(Number(e.target.value));
                          setTableCurrentPage(1);
                        }}
                        className="px-3 py-2 border border-gray-200 rounded-xl text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                      >
                        <option value={5}>5</option>
                        <option value={10}>10</option>
                        <option value={25}>25</option>
                        <option value={50}>50</option>
                      </select>
                    </div>
                    <button
                      onClick={handleDownloadTableData}
                      className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-medium rounded-xl shadow-lg hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-300"
                    >
                      <DocumentArrowDownIcon className="h-4 w-4 mr-2" />
                      Download CSV
                    </button>
                  </div>
                </div>
              </div>

              {/* Enhanced Records Table */}
              <div className="bg-white rounded-2xl border border-gray-100 shadow-lg overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="min-w-full">
                    <thead className="bg-gradient-to-r from-blue-50 to-purple-50">
                      <tr>
                        <th className="px-6 py-4 text-left text-xs font-semibold text-blue-700 uppercase tracking-wider">
                          <div className="flex items-center space-x-2">
                            <div className="w-4 h-4 bg-blue-500 rounded-full"></div>
                            <span>Select</span>
                          </div>
                        </th>
                        <th className="px-6 py-4 text-left text-xs font-semibold text-blue-700 uppercase tracking-wider">
                          <div className="flex items-center space-x-2">
                            <div className="w-4 h-4 bg-blue-500 rounded-full"></div>
                            <span>PAN Number</span>
                          </div>
                        </th>
                        <th className="px-6 py-4 text-left text-xs font-semibold text-blue-700 uppercase tracking-wider">
                          <div className="flex items-center space-x-2">
                            <div className="w-4 h-4 bg-blue-500 rounded-full"></div>
                            <span>Name</span>
                          </div>
                        </th>
                        <th className="px-6 py-4 text-left text-xs font-semibold text-blue-700 uppercase tracking-wider">
                          <div className="flex items-center space-x-2">
                            <div className="w-4 h-4 bg-blue-500 rounded-full"></div>
                            <span>Date of Birth</span>
                          </div>
                        </th>
                        <th className="px-6 py-4 text-left text-xs font-semibold text-blue-700 uppercase tracking-wider">
                          <div className="flex items-center space-x-2">
                            <div className="w-4 h-4 bg-blue-500 rounded-full"></div>
                            <span>Actions</span>
                          </div>
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {filteredRecords
                        .slice((tableCurrentPage - 1) * tableRecordsPerPage, tableCurrentPage * tableRecordsPerPage)
                        .map((record) => (
                          <tr key={record._id} className={`hover:bg-gradient-to-r hover:from-blue-50/50 hover:to-purple-50/50 transition-all duration-200 ${record.status === 'verified' ? 'opacity-60' : ''}`}>
                            <td className="px-6 py-4 whitespace-nowrap">
                              {(record.status === 'pending' || record.status === 'rejected' || record.status === 'error') && (
                                <div className="w-6 h-6 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                                  <input
                                    type="checkbox"
                                    checked={selectedRecords.includes(record._id)}
                                    onChange={() => handleRecordSelection(record._id)}
                                    className="w-4 h-4 rounded border-gray-300 text-white focus:ring-blue-500"
                                  />
                                </div>
                              )}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-medium text-gray-900 bg-gray-50 px-3 py-2 rounded-lg">
                                {record.panNumber}
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-medium text-gray-900 bg-gray-50 px-3 py-2 rounded-lg">
                                {record.name}
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-medium text-gray-900 bg-gray-50 px-3 py-2 rounded-lg">
                                {record.dateOfBirth || '-'}
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              {record.status === 'pending' ? (
                                <button
                                  onClick={() => handleVerifySingle(record._id)}
                                  disabled={verifyingRecords.has(record._id)}
                                  className="inline-flex items-center px-3 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white text-sm font-medium rounded-xl shadow-md hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                                  title={`Verify ${record.name} (${record.panNumber})`}
                                >
                                  {verifyingRecords.has(record._id) ? (
                                    <>
                                      <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-white mr-2"></div>
                                      Verifying...
                                    </>
                                  ) : (
                                    <>
                                      <CheckCircleIcon className="h-4 w-4 mr-1" />
                                      Verify
                                    </>
                                  )}
                                </button>
                              ) : record.status === 'rejected' || record.status === 'error' ? (
                                <button
                                  onClick={() => handleVerifySingle(record._id)}
                                  disabled={verifyingRecords.has(record._id)}
                                  className="inline-flex items-center px-3 py-2 bg-gradient-to-r from-orange-500 to-red-600 text-white text-sm font-medium rounded-xl shadow-md hover:from-orange-600 hover:to-red-700 transform hover:scale-105 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                                  title={`Re-verify ${record.name} (${record.panNumber})`}
                                >
                                  {verifyingRecords.has(record._id) ? (
                                    <>
                                      <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-white mr-2"></div>
                                      Re-verifying...
                                    </>
                                  ) : (
                                    <>
                                      <ArrowPathIcon className="h-4 w-4 mr-1" />
                                      Re-verify
                                    </>
                                  )}
                                </button>
                              ) : (
                                <span className="inline-flex items-center px-3 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white text-sm font-medium rounded-xl">
                                  <CheckCircleIcon className="h-4 w-4 mr-1" />
                                  Verified
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
              
              {/* Enhanced Table Pagination */}
              {filteredRecords.length > tableRecordsPerPage && (
                <div className="bg-white rounded-2xl p-6 border border-gray-100 shadow-lg mt-6">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-gray-700">
                      Showing <span className="font-semibold">{((tableCurrentPage - 1) * tableRecordsPerPage) + 1}</span> to{' '}
                      <span className="font-semibold">{Math.min(tableCurrentPage * tableRecordsPerPage, filteredRecords.length)}</span> of{' '}
                      <span className="font-semibold">{filteredRecords.length}</span> results
                      {searchTerm && (
                        <span className="text-gray-500"> (filtered from {selectedBatch.records.length} total)</span>
                      )}
                    </div>
                    <div className="flex items-center space-x-3">
                      <button
                        onClick={() => setTableCurrentPage(prev => Math.max(prev - 1, 1))}
                        disabled={tableCurrentPage === 1}
                        className="px-4 py-2 text-sm font-medium border border-gray-300 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 transition-colors duration-200"
                      >
                        Previous
                      </button>
                      <span className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-50 rounded-xl">
                        {tableCurrentPage} of {Math.ceil(filteredRecords.length / tableRecordsPerPage)}
                      </span>
                      <button
                        onClick={() => setTableCurrentPage(prev => Math.min(prev + 1, Math.ceil(filteredRecords.length / tableRecordsPerPage)))}
                        disabled={tableCurrentPage === Math.ceil(filteredRecords.length / tableRecordsPerPage)}
                        className="px-4 py-2 text-sm font-medium border border-gray-300 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 transition-colors duration-200"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Single KYC Tab Content */}
      {activeTab === 'single' && (
        <div className="bg-gradient-to-br from-blue-50 via-purple-50 to-indigo-50 rounded-2xl p-4 shadow-xl border border-blue-100/50 relative overflow-hidden">
          {/* Background Pattern */}
          <div className="absolute top-0 right-0 w-32 h-32 bg-blue-200/20 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-40 h-40 bg-purple-200/20 rounded-full blur-3xl"></div>
          
          <div className="relative z-10">
            
            <div className="max-w-4xl mx-auto">
              <form onSubmit={handleSingleKycSubmit} className="bg-white/80 backdrop-blur-sm rounded-xl p-4 border border-white/30 shadow-lg">
                {/* Form Fields Layout */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                  {/* PAN Number Field */}
              <div>
                    <label htmlFor="panNumber" className="block text-sm font-semibold text-gray-700 mb-2">
                      <span className="flex items-center">
                        <div className="w-2 h-2 bg-blue-500 rounded-full mr-2"></div>
                  PAN Number *
                      </span>
                </label>
                <div className="relative">
                  <input
                    type="text"
                    id="panNumber"
                    value={singleKycForm.panNumber}
                    onChange={(e) => handleSingleKycFormChange('panNumber', e.target.value)}
                    placeholder="ABCDE1234F"
                    className={`block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 text-center font-mono text-base tracking-wider ${
                      singleKycForm.panNumber.length === 0 
                        ? 'border-gray-200 focus:ring-blue-500 focus:border-blue-500' 
                        : singleKycForm.panNumber.length === 10 && isValidPANFormat(singleKycForm.panNumber)
                        ? 'border-green-500 focus:ring-green-500 focus:border-green-500 bg-green-50'
                        : singleKycForm.panNumber.length === 10 && !isValidPANFormat(singleKycForm.panNumber)
                        ? 'border-red-500 focus:ring-red-500 focus:border-red-500 bg-red-50'
                        : 'border-yellow-500 focus:ring-yellow-500 focus:border-yellow-500 bg-yellow-50'
                    }`}
                    maxLength={10}
                    style={{ textTransform: 'uppercase' }}
                  />
                  {singleKycForm.panNumber.length > 0 && (
                    <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                      {singleKycForm.panNumber.length === 10 && isValidPANFormat(singleKycForm.panNumber) ? (
                        <CheckCircleIcon className="w-5 h-5 text-green-500" />
                      ) : singleKycForm.panNumber.length === 10 && !isValidPANFormat(singleKycForm.panNumber) ? (
                        <XCircleIcon className="w-5 h-5 text-red-500" />
                      ) : (
                        <ClockIcon className="w-5 h-5 text-yellow-500" />
                      )}
                    </div>
                  )}
                </div>
                <div className="mt-2 text-xs text-center">
                  {singleKycForm.panNumber.length === 0 ? (
                    <span className="text-gray-500">Format: ABCDE1234F</span>
                  ) : singleKycForm.panNumber.length === 10 && isValidPANFormat(singleKycForm.panNumber) ? (
                    <span className="text-green-600 font-medium">✓ Valid PAN format</span>
                  ) : singleKycForm.panNumber.length === 10 && !isValidPANFormat(singleKycForm.panNumber) ? (
                    <span className="text-red-600 font-medium">✗ Invalid PAN format</span>
                  ) : (
                    <span className="text-yellow-600 font-medium">
                      {singleKycForm.panNumber.length}/10 characters
                    </span>
                  )}
                </div>
              </div>

                  {/* Name Field */}
              <div>
                    <label htmlFor="name" className="block text-sm font-semibold text-gray-700 mb-3">
                      <span className="flex items-center">
                        <div className="w-2 h-2 bg-purple-500 rounded-full mr-2"></div>
                  Full Name *
                      </span>
                </label>
                <div className="relative">
                  <input
                    type="text"
                    id="name"
                    value={singleKycForm.name}
                    onChange={(e) => handleSingleKycFormChange('name', e.target.value)}
                    placeholder="Enter full name as per PAN"
                    className={`block w-full px-3 py-2 pr-12 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500 transition-all duration-200 ${
                      singleKycForm.name.length === 0 
                        ? 'border-gray-200 focus:ring-purple-500 focus:border-purple-500' 
                        : validateName(singleKycForm.name).isValid
                        ? 'border-green-500 focus:ring-green-500 focus:border-green-500 bg-green-50'
                        : 'border-red-500 focus:ring-red-500 focus:border-red-500 bg-red-50'
                    }`}
                  />
                  {singleKycForm.name.length > 0 && (
                    <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                      {validateName(singleKycForm.name).isValid ? (
                        <CheckCircleIcon className="w-5 h-5 text-green-500" />
                      ) : (
                        <XCircleIcon className="w-5 h-5 text-red-500" />
                      )}
                    </div>
                  )}
                </div>
                <div className="mt-1 text-xs text-center">
                  {singleKycForm.name.length === 0 ? (
                    <span className="text-gray-500">Enter full name (letters, spaces, hyphens, apostrophes only)</span>
                  ) : validateName(singleKycForm.name).isValid ? (
                    <span className="text-green-600 font-medium">✓ Valid name format</span>
                  ) : (
                    <span className="text-red-600 font-medium">✗ {validateName(singleKycForm.name).message}</span>
                  )}
                </div>
              </div>

                  {/* Date of Birth Field */}
              <div>
                    <label htmlFor="dateOfBirth" className="block text-sm font-semibold text-gray-700 mb-3">
                      <span className="flex items-center">
                        <div className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></div>
                  Date of Birth *
                      </span>
                </label>
                <div className="relative">
                  <input
                    type="text"
                    id="dateOfBirth"
                    value={singleKycForm.dateOfBirth}
                    onChange={(e) => handleSingleKycFormChange('dateOfBirth', e.target.value)}
                    onKeyDown={(e) => {
                      // Allow backspace, delete, arrow keys, etc.
                      if (['Backspace', 'Delete', 'ArrowLeft', 'ArrowRight', 'Tab', 'Enter'].includes(e.key)) {
                        return;
                      }
                      // Allow numbers
                      if (/[0-9]/.test(e.key)) {
                        return;
                      }
                      // Prevent other characters
                      e.preventDefault();
                    }}
                    placeholder="DD/MM/YYYY"
                    className={`block w-full px-3 py-2 pr-20 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 transition-all duration-200 text-center font-mono ${
                      singleKycForm.dateOfBirth.length === 0 
                        ? 'border-gray-200 focus:ring-indigo-500 focus:border-indigo-500' 
                        : singleKycForm.dateOfBirth.length === 10 && validateDateOfBirth(singleKycForm.dateOfBirth).isValid
                        ? 'border-green-500 focus:ring-green-500 focus:border-green-500 bg-green-50'
                        : singleKycForm.dateOfBirth.length === 10 && !validateDateOfBirth(singleKycForm.dateOfBirth).isValid
                        ? 'border-red-500 focus:ring-red-500 focus:border-red-500 bg-red-50'
                        : 'border-yellow-500 focus:ring-yellow-500 focus:border-yellow-500 bg-yellow-50'
                    }`}
                    maxLength={10}
                  />
                  
                  {/* Calendar Button */}
                  <button
                    type="button"
                    onClick={() => setIsCalendarOpen(!isCalendarOpen)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 p-1 hover:bg-gray-100 rounded-md transition-colors"
                  >
                    <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                    </svg>
                  </button>

                  {/* Validation Icon */}
                  {singleKycForm.dateOfBirth.length > 0 && (
                    <div className="absolute right-12 top-1/2 transform -translate-y-1/2">
                      {singleKycForm.dateOfBirth.length === 10 && validateDateOfBirth(singleKycForm.dateOfBirth).isValid ? (
                        <CheckCircleIcon className="w-5 h-5 text-green-500" />
                      ) : singleKycForm.dateOfBirth.length === 10 && !validateDateOfBirth(singleKycForm.dateOfBirth).isValid ? (
                        <XCircleIcon className="w-5 h-5 text-red-500" />
                      ) : (
                        <ClockIcon className="w-5 h-5 text-yellow-500" />
                      )}
                    </div>
                  )}
                </div>

                {/* Calendar Dropdown */}
                {isCalendarOpen && (
                  <div 
                    ref={calendarRef}
                    className="absolute z-50 mt-2 bg-white border border-gray-200 rounded-lg shadow-lg p-4 w-80"
                  >
                    {/* Calendar Header */}
                    <div className="flex items-center justify-between mb-4">
                      <button
                        type="button"
                        onClick={() => navigateMonth('prev')}
                        className="p-2 hover:bg-gray-100 rounded-md transition-colors"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                        </svg>
                      </button>
                      
                      <h3 className="text-lg font-semibold text-gray-900">
                        {currentMonth.toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}
                      </h3>
                      
                      <button
                        type="button"
                        onClick={() => navigateMonth('next')}
                        className="p-2 hover:bg-gray-100 rounded-md transition-colors"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </button>
                    </div>

                    {/* Calendar Days */}
                    <div className="grid grid-cols-7 gap-1 mb-2">
                      {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(day => (
                        <div key={day} className="text-xs font-medium text-gray-500 text-center py-2">
                          {day}
                        </div>
                      ))}
                    </div>

                    <div className="grid grid-cols-7 gap-1">
                      {generateCalendarDays().map((day, index) => (
                        <button
                          key={index}
                          type="button"
                          onClick={() => handleCalendarDateSelect(day.date)}
                          disabled={day.isFuture}
                          className={`
                            p-2 text-sm rounded-md transition-colors
                            ${day.isCurrentMonth ? 'text-gray-900' : 'text-gray-400'}
                            ${day.isToday ? 'bg-blue-100 text-blue-900 font-semibold' : ''}
                            ${day.isSelected ? 'bg-indigo-500 text-white font-semibold' : ''}
                            ${day.isFuture ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 cursor-pointer'}
                            ${!day.isCurrentMonth ? 'opacity-50' : ''}
                          `}
                        >
                          {day.date.getDate()}
                        </button>
                      ))}
                    </div>

                    {/* Today Button */}
                    <div className="mt-4 flex justify-center">
                      <button
                        type="button"
                        onClick={() => handleCalendarDateSelect(new Date())}
                        className="px-4 py-2 text-sm bg-indigo-500 text-white rounded-md hover:bg-indigo-600 transition-colors"
                      >
                        Today
                      </button>
                    </div>
                  </div>
                )}

                <div className="mt-1 text-xs text-center">
                  {singleKycForm.dateOfBirth.length === 0 ? (
                    <span className="text-gray-500">Format: DD-MM-YYYY or click calendar</span>
                  ) : singleKycForm.dateOfBirth.length === 10 && validateDateOfBirth(singleKycForm.dateOfBirth).isValid ? (
                    <span className="text-green-600 font-medium">✓ Valid date format</span>
                  ) : singleKycForm.dateOfBirth.length === 10 && !validateDateOfBirth(singleKycForm.dateOfBirth).isValid ? (
                    <span className="text-red-600 font-medium">✗ Invalid date format</span>
                  ) : (
                    <span className="text-yellow-600 font-medium">
                      {singleKycForm.dateOfBirth.length}/10 characters
                    </span>
                  )}
                </div>
              </div>
              </div>

                {/* Action Buttons - Below Form */}
                <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
                <button
                  type="submit"
                  disabled={singleKycVerifying || !validatePAN(singleKycForm.panNumber).isValid || !validateName(singleKycForm.name).isValid || !validateDateOfBirth(singleKycForm.dateOfBirth).isValid}
                    className="inline-flex items-center justify-center px-8 py-4 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold text-lg rounded-xl shadow-xl hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 min-w-[200px]"
                >
                  {singleKycVerifying ? (
                    <>
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>
                      Verifying...
                    </>
                  ) : (
                    <>
                        <CheckCircleIcon className="h-5 w-5 mr-3" />
                      Verify KYC
                    </>
                  )}
                </button>
                
                <button
                  type="button"
                  onClick={resetSingleKycForm}
                    className="inline-flex items-center justify-center px-6 py-3 border-2 border-gray-300 text-sm font-medium rounded-xl text-gray-700 bg-white/80 hover:bg-gray-50 hover:border-gray-400 transition-all duration-200 min-w-[120px]"
                >
                    <ArrowPathIcon className="h-4 w-4 mr-2" />
                  Reset Form
                </button>
              </div>

                {/* Form Validation Messages */}
                <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-xl">
                  <div className="flex items-start">
                    <ExclamationTriangleIcon className="h-5 w-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-blue-800 mb-1">Quick Verification</p>
                      <p className="text-sm text-blue-700">
                        Enter the PAN details exactly as they appear on the PAN card. The verification will be processed instantly.
                      </p>
                    </div>
                  </div>
                </div>
              </form>
            </div>
          </div>
            {/* Single KYC Result */}
            {singleKycResult && (
              <div className="mt-8 bg-white/80 backdrop-blur-sm rounded-2xl p-8 border border-white/30 shadow-xl">
                <div className="text-center mb-6">
                  <h3 className="text-2xl font-bold text-slate-800 mb-2 flex items-center justify-center">
                    {getStatusIcon(singleKycResult.status)}
                    <span className="ml-3">Verification Result</span>
                  </h3>
                  <div className={`inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold ${getStatusColor(singleKycResult.status)}`}>
                    {singleKycResult.status.toUpperCase()}
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6 border border-blue-200">
                    <div className="text-center">
                      <div className="w-12 h-12 bg-blue-500 rounded-xl flex items-center justify-center mx-auto mb-3">
                        <DocumentTextIcon className="h-6 w-6 text-white" />
                      </div>
                      <p className="text-sm font-medium text-blue-600 mb-2">PAN Number</p>
                      <p className="text-lg font-bold text-blue-900 font-mono tracking-wider">{singleKycResult.panNumber}</p>
                    </div>
                  </div>
                  
                  <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl p-6 border border-purple-200">
                    <div className="text-center">
                      <div className="w-12 h-12 bg-purple-500 rounded-xl flex items-center justify-center mx-auto mb-3">
                        <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                        </svg>
                      </div>
                      <p className="text-sm font-medium text-purple-600 mb-2">Full Name</p>
                      <p className="text-lg font-bold text-purple-900">{singleKycResult.name}</p>
                    </div>
                  </div>
                  
                  <div className="bg-gradient-to-br from-indigo-50 to-indigo-100 rounded-xl p-6 border border-indigo-200">
                    <div className="text-center">
                      <div className="w-12 h-12 bg-indigo-500 rounded-xl flex items-center justify-center mx-auto mb-3">
                        <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                        </svg>
                      </div>
                      <p className="text-sm font-medium text-indigo-600 mb-2">Date of Birth</p>
                      <p className="text-lg font-bold text-indigo-900 font-mono">{singleKycResult.dateOfBirth}</p>
                    </div>
                  </div>
                </div>

                {/* Additional Details */}
                <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-gray-50 rounded-xl p-4">
                    <p className="text-sm font-medium text-gray-500 mb-1">Processing Time</p>
                    <p className="text-lg font-semibold text-gray-900">{singleKycResult.processingTime}ms</p>
                  </div>
                  <div className="bg-gray-50 rounded-xl p-4">
                    <p className="text-sm font-medium text-gray-500 mb-1">Processed At</p>
                    <p className="text-lg font-semibold text-gray-900">
                      {singleKycResult.processedAt ? new Date(singleKycResult.processedAt).toLocaleString() : '-'}
                    </p>
                  </div>
                </div>

              </div>
            )}
        </div>
      )}

      {/* Verification Popup Modal */}
      {showVerifyPopup && selectedRecordForVerification && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="bg-gradient-to-r from-blue-500 to-purple-600 text-white p-6 rounded-t-2xl">
              <div className="flex items-center justify-between">
                <h3 className="text-xl font-bold flex items-center">
                  <CheckCircleIcon className="h-6 w-6 mr-2" />
                  Verify PAN Record
                </h3>
                <button
                  onClick={() => {
                    setShowVerifyPopup(false);
                    setSelectedRecordForVerification(null);
                  }}
                  className="text-white/80 hover:text-white transition-colors"
                >
                  <XCircleIcon className="h-6 w-6" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6">
              <div className="mb-6">
                <p className="text-gray-600 mb-4">
                  Please review the record details before verification:
                </p>
                
                <div className="bg-gray-50 rounded-xl p-4 space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium text-gray-500">PAN Number:</span>
                    <span className="text-sm font-semibold text-gray-900 bg-white px-3 py-1 rounded-lg">
                      {selectedRecordForVerification.panNumber}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium text-gray-500">Name:</span>
                    <span className="text-sm font-semibold text-gray-900 bg-white px-3 py-1 rounded-lg">
                      {selectedRecordForVerification.name}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium text-gray-500">Date of Birth:</span>
                    <span className="text-sm font-semibold text-gray-900 bg-white px-3 py-1 rounded-lg">
                      {selectedRecordForVerification.dateOfBirth || 'N/A'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium text-gray-500">Current Status:</span>
                    <span className={`text-sm font-semibold px-3 py-1 rounded-lg ${getStatusColor(selectedRecordForVerification.status)}`}>
                      {selectedRecordForVerification.status}
                    </span>
                  </div>
                </div>
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6">
                <div className="flex items-start">
                  <ExclamationTriangleIcon className="h-5 w-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-blue-800 mb-1">Verification Process</p>
                    <p className="text-sm text-blue-700">
                      This will verify the PAN details against the official database. 
                      The process may take a few seconds to complete.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="bg-gray-50 px-6 py-4 rounded-b-2xl flex items-center justify-end space-x-3">
              <button
                onClick={() => {
                  setShowVerifyPopup(false);
                  setSelectedRecordForVerification(null);
                }}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-xl hover:bg-gray-50 transition-colors duration-200"
              >
                Cancel
              </button>
              <button
                onClick={handleVerifyFromPopup}
                disabled={verifyingRecords.has(selectedRecordForVerification._id)}
                className="inline-flex items-center px-6 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-medium rounded-xl shadow-lg hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
              >
                {verifyingRecords.has(selectedRecordForVerification._id) ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Verifying...
                  </>
                ) : (
                  <>
                    <CheckCircleIcon className="h-4 w-4 mr-2" />
                    Verify Record
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Verify Selected Popup Modal */}
      {showVerifySelectedPopup && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="bg-gradient-to-r from-blue-500 to-purple-600 text-white p-6 rounded-t-2xl">
              <div className="flex items-center justify-between">
                <h3 className="text-xl font-bold flex items-center">
                  <CheckCircleIcon className="h-6 w-6 mr-2" />
                  Verify Selected Records ({selectedRecords.length})
                </h3>
                <button
                  onClick={() => setShowVerifySelectedPopup(false)}
                  className="text-white/80 hover:text-white transition-colors"
                >
                  <XCircleIcon className="h-6 w-6" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6">
              <div className="mb-6">
                <p className="text-gray-600 mb-4">
                  Please review the selected records before verification:
                </p>
                
                {/* Selected Records List */}
                <div className="bg-gray-50 rounded-xl p-4 max-h-96 overflow-y-auto">
                  <div className="space-y-3">
                    {selectedRecords.map((recordId) => {
                      const record = selectedBatch?.records.find(r => r._id === recordId);
                      if (!record) return null;
                      
                      return (
                        <div key={recordId} className="bg-white rounded-lg p-4 border border-gray-200">
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div>
                              <span className="text-xs font-medium text-gray-500 block">PAN Number</span>
                              <span className="text-sm font-semibold text-gray-900">
                                {record.panNumber}
                              </span>
                  </div>
                  <div>
                              <span className="text-xs font-medium text-gray-500 block">Name</span>
                              <span className="text-sm font-semibold text-gray-900">
                                {record.name}
                              </span>
                  </div>
                  <div>
                              <span className="text-xs font-medium text-gray-500 block">Status</span>
                              <span className={`text-xs font-semibold px-2 py-1 rounded-lg ${getStatusColor(record.status)}`}>
                                {record.status}
                      </span>
                    </div>
                  </div>
                  </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6">
                <div className="flex items-start">
                  <ExclamationTriangleIcon className="h-5 w-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-blue-800 mb-1">Batch Verification Process</p>
                    <p className="text-sm text-blue-700">
                      This will verify all {selectedRecords.length} selected records against the official database. 
                      The process may take a few minutes to complete depending on the number of records.
                    </p>
                  </div>
                  </div>
                </div>

              {/* Summary Stats */}
              <div className="bg-gradient-to-r from-blue-50 to-purple-50 rounded-xl p-4 mb-6">
                <h4 className="text-sm font-semibold text-gray-800 mb-3">Verification Summary</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-600">{selectedRecords.length}</div>
                    <div className="text-xs text-gray-600">Total Records</div>
                    </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-yellow-600">
                      {selectedRecords.filter(id => {
                        const record = selectedBatch?.records.find(r => r._id === id);
                        return record?.status === 'pending';
                      }).length}
                  </div>
                    <div className="text-xs text-gray-600">Pending</div>
              </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-orange-600">
                      {selectedRecords.filter(id => {
                        const record = selectedBatch?.records.find(r => r._id === id);
                        return record?.status === 'rejected';
                      }).length}
                    </div>
                    <div className="text-xs text-gray-600">Rejected</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-600">
                      {selectedRecords.filter(id => {
                        const record = selectedBatch?.records.find(r => r._id === id);
                        return record?.status === 'error';
                      }).length}
                    </div>
                    <div className="text-xs text-gray-600">Error</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="bg-gray-50 px-6 py-4 rounded-b-2xl flex items-center justify-end space-x-3">
              <button
                onClick={() => setShowVerifySelectedPopup(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-xl hover:bg-gray-50 transition-colors duration-200"
              >
                Cancel
              </button>
              <button
                onClick={handleVerifySelectedFromPopup}
                disabled={verifying}
                className="inline-flex items-center px-6 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-medium rounded-xl shadow-lg hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
              >
                {verifying ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Verifying {selectedRecords.length} Records...
                  </>
                ) : (
                  <>
                    <CheckCircleIcon className="h-4 w-4 mr-2" />
                    Verify {selectedRecords.length} Records
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
      </div>
    </div>
  );
};

export default PanKyc;

import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../contexts/ToastContext';
import { useNavigate } from 'react-router-dom';
import api from '../../services/api';
import CustomFieldsManager from '../../components/CustomFieldsManager';
import { 
  UserGroupIcon, 
  ChartBarIcon, 
  DocumentTextIcon, 
  CogIcon,
  PlusIcon,
  PencilIcon,
  TrashIcon,
  EyeIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

interface User {
  _id: string;
  name: string;
  email: string;
  role: string;
  moduleAccess: string[];
  status: string;
  branding?: {
    logo?: {
      filename: string;
      originalName: string;
      path: string;
      mimetype: string;
      size: number;
    };
    companyName?: string;
    displayName?: string;
    address?: string;
    gstNumber?: string;
  };
  customFields?: Record<string, any>;
  enabledCustomFields?: string[]; // Array of custom field IDs
  createdAt: string;
  updatedAt: string;
}

interface AuditLog {
  _id: string;
  userId?: {
    _id: string;
    name: string;
    email: string;
  };
  action: string;
  module: string;
  resource: string;
  resourceId: string;
  details: any;
  ipAddress: string;
  userAgent: string;
  status: string;
  createdAt: string;
}

interface SystemStats {
  users: {
    total: number;
    active: number;
    new: number;
    inactive: number;
    suspended: number;
    premium: number;
    basic: number;
    lastActive: Array<{ _id: string; count: number }>;
    roleDistribution: Array<{ role: string; count: number }>;
    moduleAccessStats: Array<{ module: string; count: number }>;
  };
  panKyc: Array<{ _id: string; count: number }>;
  aadhaarPan: Array<{ _id: string; count: number }>;
  activity: Array<{ _id: string; count: number }>;
  dailyActivity: Array<{ _id: string; count: number }>;
  userPerformance: {
    topPerformers: Array<{ userId: string; name: string; count: number; module: string }>;
    recentActivity: Array<{ userId: string; name: string; action: string; timestamp: string }>;
    userEngagement: Array<{ userId: string; name: string; loginCount: number; lastLogin: string }>;
  };
  apiUsage: {
    totalHits: number;
    uniqueUsers: number;
    topApiEndpoints: Array<{ endpoint: string; hits: number; users: number }>;
    userApiHits: Array<{ 
      userId: string; 
      name: string; 
      email: string; 
      totalHits: number; 
      sandboxApiCalls: number;
      successfulApiCalls: number;
      failedApiCalls: number;
      successRate: number;
      endpoints: Array<{ endpoint: string; hits: number; lastUsed: string }>; 
      modules: Array<{ module: string; hits: number }>; 
      hourlyDistribution: Array<{ hour: number; hits: number }>; 
      dailyDistribution: Array<{ date: string; hits: number }> 
    }>;
    moduleUsage: Array<{ module: string; totalHits: number; uniqueUsers: number; avgHitsPerUser: number }>;
    peakUsageHours: Array<{ hour: number; hits: number; users: number }>;
    apiPerformance: Array<{ endpoint: string; avgResponseTime: number; successRate: number; errorRate: number }>;
    panKycUserWise: Array<{
      userId: string;
      name: string;
      email: string;
      totalActivities: number;
      uploads: number;
      apiCalls: number;
      successfulApiCalls: number;
      failedApiCalls: number;
      successRate: number;
    }>;
    aadhaarPanUserWise: Array<{
      userId: string;
      name: string;
      email: string;
      totalActivities: number;
      uploads: number;
      apiCalls: number;
      successfulApiCalls: number;
      failedApiCalls: number;
      successRate: number;
    }>;
  };
}

const Admin: React.FC = () => {
  const { user, refreshUserData } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [users, setUsers] = useState<User[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [systemStats, setSystemStats] = useState<SystemStats | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [userStats, setUserStats] = useState<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [apiUsageStats, setApiUsageStats] = useState<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [userApiHitCounts, setUserApiHitCounts] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(false);
  const [statsTimeRange, setStatsTimeRange] = useState('30');
  const [usersLoading, setUsersLoading] = useState(false);
  const [userSearchTerm, setUserSearchTerm] = useState('');
  const [userFilterRole, setUserFilterRole] = useState('all');
  const [userFilterStatus, setUserFilterStatus] = useState('all');
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditSearchTerm, setAuditSearchTerm] = useState('');
  
  // Archival-related state
  const [archivalStats, setArchivalStats] = useState<any>(null);
  const [usersWithArchivalSettings, setUsersWithArchivalSettings] = useState<any[]>([]);
  const [archivalLoading, setArchivalLoading] = useState(false);
  const [selectedUserForArchival, setSelectedUserForArchival] = useState<any>(null);
  const [userArchivalModalOpen, setUserArchivalModalOpen] = useState(false);
  const [auditFilterAction, setAuditFilterAction] = useState('all');
  const [auditFilterModule, setAuditFilterModule] = useState('all');
  const [auditPage, setAuditPage] = useState(1);
  const [auditPageSize] = useState(10);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);
  const [analyticsTimeRange, setAnalyticsTimeRange] = useState('30');
  const [apiLoading, setApiLoading] = useState(false);
  const [apiTimeRange, setApiTimeRange] = useState('30');
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [showModuleAccess, setShowModuleAccess] = useState(false);
  const [selectedUserForModules, setSelectedUserForModules] = useState<User | null>(null);
  const [showBranding, setShowBranding] = useState(false);
  const [selectedUserForBranding, setSelectedUserForBranding] = useState<User | null>(null);
  const [brandingForm, setBrandingForm] = useState({
    companyName: '',
    displayName: '',
    address: '',
    gstNumber: '',
    logoFile: null as File | null
  });
  const [brandingLoading, setBrandingLoading] = useState(false);
  const [showQrCode, setShowQrCode] = useState(false);
  const [selectedUserForQrCode, setSelectedUserForQrCode] = useState<User | null>(null);
  const [qrCodeData, setQrCodeData] = useState<{ qrCode: string; qrCodeUrl: string; qrCodeString: string } | null>(null);
  const [qrCodeLoading, setQrCodeLoading] = useState(false);

  // Custom Fields
  const [availableCustomFields, setAvailableCustomFields] = useState<any[]>([]);

  // Form states
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    role: 'user',
    moduleAccess: [] as string[],
    status: 'active',
    enabledCustomFields: [] as string[] // Array of custom field IDs
  });

  useEffect(() => {
    if (!user) {
      navigate('/login');
      return;
    }
    
    if (user.role !== 'admin') {
      navigate('/dashboard');
      return;
    }

    // User is admin, stay on /admin and fetch data
    fetchUsers();
    fetchAuditLogs();
    fetchSystemStats();
    fetchUserStats();
    fetchApiUsageStats();
    fetchUserApiHitCounts();
    fetchCustomFields();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, navigate]);

  // Fetch archival data when archival tab is activated
  useEffect(() => {
    if (activeTab === 'archival') {
      fetchArchivalStats();
      fetchUsersWithArchivalSettings();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  const fetchUsers = async () => {
    try {
      setUsersLoading(true);
      const response = await api.get('/admin/users');
      setUsers(response.data.data.users);
    } catch (error) {
      console.error('Error fetching users:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch users. Please try again.',
        duration: 5000
      });
    } finally {
      setUsersLoading(false);
    }
  };

  const fetchCustomFields = async () => {
    try {
      const response = await api.get('/custom-fields', {
        params: {
          isActive: 'true'
        }
      });
      setAvailableCustomFields(response.data.data || []);
    } catch (error) {
      console.error('Error fetching custom fields:', error);
    }
  };

  const refreshUsers = () => {
    fetchUsers();
  };

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.name.toLowerCase().includes(userSearchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(userSearchTerm.toLowerCase());
    const matchesRole = userFilterRole === 'all' || user.role === userFilterRole;
    const matchesStatus = userFilterStatus === 'all' || user.status === userFilterStatus;
    
    return matchesSearch && matchesRole && matchesStatus;
  });

  const fetchAuditLogs = async () => {
    try {
      setAuditLoading(true);
      const response = await api.get('/admin/audit-logs');
      setAuditLogs(response.data.data.logs);
    } catch (error) {
      console.error('Error fetching audit logs:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch audit logs. Please try again.',
        duration: 5000
      });
    } finally {
      setAuditLoading(false);
    }
  };

  const refreshAuditLogs = () => {
    fetchAuditLogs();
  };

  const filteredAuditLogs = auditLogs.filter(log => {
    const matchesSearch = log.userId?.name?.toLowerCase().includes(auditSearchTerm.toLowerCase()) ||
                         log.action.toLowerCase().includes(auditSearchTerm.toLowerCase()) ||
                         log.module.toLowerCase().includes(auditSearchTerm.toLowerCase()) ||
                         log.resource.toLowerCase().includes(auditSearchTerm.toLowerCase());
    const matchesAction = auditFilterAction === 'all' || log.action === auditFilterAction;
    const matchesModule = auditFilterModule === 'all' || log.module === auditFilterModule;
    
    return matchesSearch && matchesAction && matchesModule;
  });

  const paginatedAuditLogs = filteredAuditLogs.slice(
    (auditPage - 1) * auditPageSize,
    auditPage * auditPageSize
  );

  const totalAuditPages = Math.ceil(filteredAuditLogs.length / auditPageSize);

  const fetchSystemStats = async (days: string = statsTimeRange) => {
    try {
      setStatsLoading(true);
      const response = await api.get(`/admin/stats?days=${days}`);
      setSystemStats(response.data.data);
    } catch (error) {
      console.error('Error fetching system stats:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch system statistics. Please try again.',
        duration: 5000
      });
    } finally {
      setStatsLoading(false);
    }
  };

  const fetchUserStats = async (days: string = statsTimeRange) => {
    try {
      const response = await api.get(`/admin/user-stats?days=${days}`);
      setUserStats(response.data.data);
    } catch (error) {
      console.error('Error fetching user stats:', error);
    }
  };

  const fetchApiUsageStats = async (days: string = statsTimeRange) => {
    try {
      const response = await api.get(`/admin/api-usage-stats?days=${days}`);
      setApiUsageStats(response.data.data);
    } catch (error) {
      console.error('Error fetching API usage stats:', error);
    }
  };

  const handleTimeRangeChange = (days: string) => {
    setStatsTimeRange(days);
    fetchSystemStats(days);
    fetchUserStats(days);
    fetchApiUsageStats(days);
  };

  const refreshStats = () => {
    fetchSystemStats();
    fetchUserStats();
    fetchApiUsageStats();
  };

  const fetchAnalyticsData = async (days: string = analyticsTimeRange) => {
    try {
      setAnalyticsLoading(true);
      // Fetch all analytics data in parallel
      await Promise.all([
        fetchSystemStats(days),
        fetchUserStats(days),
        fetchApiUsageStats(days)
      ]);
    } catch (error) {
      console.error('Error fetching analytics data:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch analytics data. Please try again.',
        duration: 5000
      });
    } finally {
      setAnalyticsLoading(false);
    }
  };

  const handleAnalyticsTimeRangeChange = (days: string) => {
    setAnalyticsTimeRange(days);
    fetchAnalyticsData(days);
  };

  const refreshAnalytics = () => {
    fetchAnalyticsData();
  };

  const fetchApiAnalyticsData = async (days: string = apiTimeRange) => {
    try {
      setApiLoading(true);
      await fetchApiUsageStats(days);
    } catch (error) {
      console.error('Error fetching API analytics data:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch API analytics data. Please try again.',
        duration: 5000
      });
    } finally {
      setApiLoading(false);
    }
  };

  const handleApiTimeRangeChange = (days: string) => {
    setApiTimeRange(days);
    fetchApiAnalyticsData(days);
  };

  const refreshApiAnalytics = () => {
    fetchApiAnalyticsData();
  };

  // Mock data for user API hit counts
  const mockUserApiHitCounts = [
    {
      userId: 'user1',
      userName: 'John Doe',
      userEmail: 'john.doe@example.com',
      totalHits: 1247,
      lastActive: new Date(Date.now() - 300000).toISOString(),
      endpoints: [
        { endpoint: '/api/pan-kyc/upload', hits: 456, lastUsed: new Date(Date.now() - 5000).toISOString() },
        { endpoint: '/api/pan-kyc/batches', hits: 234, lastUsed: new Date(Date.now() - 12000).toISOString() },
        { endpoint: '/api/aadhaar-pan/verify', hits: 189, lastUsed: new Date(Date.now() - 18000).toISOString() },
        { endpoint: '/api/users/profile', hits: 123, lastUsed: new Date(Date.now() - 25000).toISOString() }
      ],
      modules: [
        { module: 'pan-kyc', hits: 690 },
        { module: 'aadhaar-pan', hits: 189 },
        { module: 'users', hits: 123 }
      ]
    },
    {
      userId: 'user2',
      userName: 'Jane Smith',
      userEmail: 'jane.smith@example.com',
      totalHits: 892,
      lastActive: new Date(Date.now() - 600000).toISOString(),
      endpoints: [
        { endpoint: '/api/aadhaar-pan/verify', hits: 345, lastUsed: new Date(Date.now() - 12000).toISOString() },
        { endpoint: '/api/aadhaar-pan/upload', hits: 234, lastUsed: new Date(Date.now() - 18000).toISOString() },
        { endpoint: '/api/pan-kyc/batches', hits: 123, lastUsed: new Date(Date.now() - 25000).toISOString() }
      ],
      modules: [
        { module: 'aadhaar-pan', hits: 579 },
        { module: 'pan-kyc', hits: 123 }
      ]
    },
    {
      userId: 'user3',
      userName: 'Mike Johnson',
      userEmail: 'mike.johnson@example.com',
      totalHits: 567,
      lastActive: new Date(Date.now() - 900000).toISOString(),
      endpoints: [
        { endpoint: '/api/users/profile', hits: 234, lastUsed: new Date(Date.now() - 18000).toISOString() },
        { endpoint: '/api/pan-kyc/upload', hits: 123, lastUsed: new Date(Date.now() - 25000).toISOString() },
        { endpoint: '/api/admin/stats', hits: 89, lastUsed: new Date(Date.now() - 32000).toISOString() }
      ],
      modules: [
        { module: 'users', hits: 234 },
        { module: 'pan-kyc', hits: 123 },
        { module: 'admin', hits: 89 }
      ]
    }
  ];

  const fetchUserApiHitCounts = async () => {
    // Simulate API call with mock data
    setUserApiHitCounts(mockUserApiHitCounts);
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      await api.post('/admin/users', formData);
      showToast({
        type: 'success',
        message: 'User created successfully!',
        duration: 4000
      });
      setShowCreateUser(false);
      setFormData({
        name: '',
        email: '',
        password: '',
        role: 'user',
        moduleAccess: [],
        status: 'active',
        enabledCustomFields: []
      });
      fetchUsers();
    } catch (error: any) {
      console.error('Error creating user:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to create user. Please try again.',
        duration: 5000
      });
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUser) return;

    try {
      setLoading(true);
      const { password, ...updateData } = formData;
      const dataToSend = password ? formData : updateData;
      
      await api.put(`/admin/users/${editingUser._id}`, dataToSend);
      showToast({
        type: 'success',
        message: 'User updated successfully!',
        duration: 4000
      });
      setEditingUser(null);
      setFormData({
        name: '',
        email: '',
        password: '',
        role: 'user',
        moduleAccess: [],
        status: 'active',
        enabledCustomFields: []
      });
      fetchUsers();
    } catch (error: any) {
      console.error('Error updating user:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to update user. Please try again.',
        duration: 5000
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (userId: string) => {
    if (!window.confirm('Are you sure you want to delete this user?')) return;

    try {
      setLoading(true);
      await api.delete(`/admin/users/${userId}`);
      showToast({
        type: 'success',
        message: 'User deleted successfully!',
        duration: 4000
      });
      fetchUsers();
    } catch (error: any) {
      console.error('Error deleting user:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to delete user. Please try again.',
        duration: 5000
      });
    } finally {
      setLoading(false);
    }
  };

  const handleManageModuleAccess = (user: User) => {
    setSelectedUserForModules(user);
    setShowModuleAccess(true);
  };

  const handleUpdateModuleAccess = async (userId: string, moduleAccess: string[]) => {
    try {
      await api.patch(`/admin/users/${userId}/module-access`, { moduleAccess });
      showToast({
        type: 'success',
        message: 'User module access updated successfully!',
        duration: 4000
      });
      setShowModuleAccess(false);
      setSelectedUserForModules(null);
      fetchUsers();
    } catch (error: any) {
      console.error('Error updating module access:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to update module access. Please try again.',
        duration: 5000
      });
    }
  };

  const handleManageBranding = (user: User) => {
    setSelectedUserForBranding(user);
    setBrandingForm({
      companyName: user.branding?.companyName || '',
      displayName: user.branding?.displayName || '',
      address: user.branding?.address || '',
      gstNumber: user.branding?.gstNumber || '',
      logoFile: null
    });
    setShowBranding(true);
  };

  const handleViewQrCode = async (user: User, regenerate = false) => {
    setSelectedUserForQrCode(user);
    setQrCodeLoading(true);
    if (!showQrCode) {
      setShowQrCode(true);
    }
    
    try {
      const url = regenerate 
        ? `/admin/users/${user._id}/qr-code?regenerate=true`
        : `/admin/users/${user._id}/qr-code`;
      const response = await api.get(url);
      if (response.data.success) {
        setQrCodeData({
          qrCode: response.data.data.qrCode,
          qrCodeUrl: response.data.data.qrCodeUrl,
          qrCodeString: response.data.data.qrCodeString
        });
        if (regenerate) {
          showToast({
            type: 'success',
            message: 'QR code regenerated successfully',
            duration: 4000
          });
        }
      } else {
        showToast({
          type: 'error',
          message: response.data.message || 'Failed to generate QR code',
          duration: 4000
        });
        if (!showQrCode) {
          setShowQrCode(false);
        }
      }
    } catch (error: any) {
      console.error('Error fetching QR code:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to generate QR code',
        duration: 4000
      });
      if (!showQrCode) {
        setShowQrCode(false);
      }
    } finally {
      setQrCodeLoading(false);
    }
  };

  const handleDownloadQrCode = () => {
    if (!qrCodeData) return;
    
    const link = document.createElement('a');
    link.href = qrCodeData.qrCode;
    link.download = `qr-code-${selectedUserForQrCode?.name || 'user'}.png`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleUpdateBranding = async (userId: string) => {
    try {
      setBrandingLoading(true);
      
      // Update branding text fields
      if (brandingForm.companyName || brandingForm.displayName || brandingForm.address || brandingForm.gstNumber) {
        await api.patch(`/admin/users/${userId}/branding`, {
          companyName: brandingForm.companyName,
          displayName: brandingForm.displayName,
          address: brandingForm.address,
          gstNumber: brandingForm.gstNumber
        });
      }

      // Upload logo if selected
      if (brandingForm.logoFile) {
        const formData = new FormData();
        formData.append('logo', brandingForm.logoFile);
        await api.post(`/admin/users/${userId}/logo`, formData, {
          headers: {
            'Content-Type': 'multipart/form-data'
          }
        });
      }

      showToast({
        type: 'success',
        message: 'User branding updated successfully!',
        duration: 4000
      });
      setShowBranding(false);
      setSelectedUserForModules(null);
      setBrandingForm({ companyName: '', displayName: '', address: '', gstNumber: '', logoFile: null });
      fetchUsers();
      
      // If admin is updating their own branding, refresh the auth context
      if (userId === user?._id) {
        console.log('🔄 Refreshing user data for admin...');
        // Add a small delay to avoid conflicts with initialization
        setTimeout(async () => {
          const refreshedUser = await refreshUserData();
          console.log('🔄 Refreshed user data:', refreshedUser);
        }, 100);
      }
    } catch (error: any) {
      console.error('Error updating branding:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to update branding. Please try again.',
        duration: 5000
      });
    } finally {
      setBrandingLoading(false);
    }
  };

  // Archival-related functions
  const fetchArchivalStats = async () => {
    try {
      setArchivalLoading(true);
      const response = await api.get('/admin/archival/stats');
      setArchivalStats(response.data.data);
    } catch (error) {
      console.error('Error fetching archival stats:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch archival statistics. Please try again.',
        duration: 5000
      });
    } finally {
      setArchivalLoading(false);
    }
  };

  const fetchUsersWithArchivalSettings = async () => {
    try {
      setArchivalLoading(true);
      const response = await api.get(`/admin/archival/users?search=${userSearchTerm}`);
      setUsersWithArchivalSettings(response.data.data.users);
    } catch (error) {
      console.error('Error fetching users with archival settings:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch users with archival settings. Please try again.',
        duration: 5000
      });
    } finally {
      setArchivalLoading(false);
    }
  };

  const triggerArchivalProcess = async () => {
    // Show confirmation dialog
    const confirmed = window.confirm(
      '⚠️ WARNING: This will trigger the archival process which may delete expired records and send warning emails to users.\n\n' +
      'This action will:\n' +
      '• Mark records for deletion that have exceeded retention periods\n' +
      '• Send 7-day warning emails to affected users\n' +
      '• Delete records that have passed the deletion date\n\n' +
      'Are you sure you want to proceed?'
    );

    if (!confirmed) {
      return;
    }

    try {
      setArchivalLoading(true);
      await api.post('/admin/archival/trigger');
      showToast({
        type: 'success',
        message: 'Archival process triggered successfully! The process is now running in the background.',
        duration: 6000
      });
      // Refresh stats after triggering
      setTimeout(() => {
        fetchArchivalStats();
      }, 2000);
    } catch (error) {
      console.error('Error triggering archival process:', error);
      showToast({
        type: 'error',
        message: 'Failed to trigger archival process. Please try again.',
        duration: 5000
      });
    } finally {
      setArchivalLoading(false);
    }
  };

  const openUserArchivalModal = (user: any) => {
    setSelectedUserForArchival(user);
    setUserArchivalModalOpen(true);
  };

  const viewUserArchivalRecords = async (user: any) => {
    // Get user display name for confirmation
    const userName = user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.email || 'Unknown User';
    
    const confirmed = window.confirm(
      `View archival records for ${userName}?\n\n` +
      'This will fetch and display all archival records for this user from both PAN KYC and Aadhaar-PAN modules.'
    );

    if (!confirmed) {
      return;
    }

    try {
      setArchivalLoading(true);
      
      // Debug: Log user object structure
      console.log('User object:', user);
      
      // Fetch both PAN KYC and Aadhaar-PAN records
      const [panKycResponse, aadhaarPanResponse] = await Promise.all([
        api.get(`/admin/archival/users/${user._id}/records?module=panKyc`),
        api.get(`/admin/archival/users/${user._id}/records?module=aadhaarPan`)
      ]);
      
      const panKycRecords = panKycResponse.data.data.records || [];
      const aadhaarPanRecords = aadhaarPanResponse.data.data.records || [];
      
      // Combine and format records
      const allRecords = [
        ...panKycRecords.map((record: any) => ({ ...record, module: 'PAN KYC' })),
        ...aadhaarPanRecords.map((record: any) => ({ ...record, module: 'Aadhaar-PAN' }))
      ];
      
      // Get user display name - handle different possible structures
      const userName = user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.email || 'Unknown User';
      
      if (allRecords.length === 0) {
        alert(`No archival records found for ${userName}`);
        return;
      }
      
      // Show records in an alert for now (you can create a proper modal later)
      const recordSummary = allRecords.map((record: any) => 
        `${record.module}: ${record.status || 'Active'} (${new Date(record.createdAt).toLocaleDateString()})`
      ).join('\n');
      
      alert(`Archival Records for ${userName}:\n\n${recordSummary}`);
    } catch (error) {
      console.error('Error fetching user archival records:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch user archival records. Please try again.',
        duration: 5000
      });
    } finally {
      setArchivalLoading(false);
    }
  };

  const handleEditUser = (user: User) => {
    setEditingUser(user);
    setFormData({
      name: user.name,
      email: user.email,
      password: '',
      role: user.role,
      moduleAccess: user.moduleAccess,
      status: user.status,
      enabledCustomFields: user.enabledCustomFields || []
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'suspended':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
      default:
        return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800';
      case 'suspended':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-yellow-100 text-yellow-800';
    }
  };

  const getActionColor = (action: string) => {
    if (action.includes('create') || action.includes('login')) return 'bg-green-100 text-green-800';
    if (action.includes('delete') || action.includes('failed')) return 'bg-red-100 text-red-800';
    if (action.includes('update') || action.includes('edit')) return 'bg-blue-100 text-blue-800';
    return 'bg-gray-100 text-gray-800';
  };

  if (user?.role !== 'admin') {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <XCircleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900">Access Denied</h2>
          <p className="text-gray-600">You need admin privileges to access this page.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Enhanced Admin Header */}
      <div className="bg-gradient-to-br from-purple-600 via-indigo-700 to-blue-800 rounded-3xl p-8 text-white shadow-2xl relative overflow-hidden">
        {/* Background Pattern */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-white/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-0 left-0 w-40 h-40 bg-white/5 rounded-full blur-3xl"></div>
        
        <div className="relative z-10">
                      <div className="flex items-center mb-4">
              <div className="w-20 h-20 bg-gradient-to-br from-white/30 to-white/10 rounded-3xl flex items-center justify-center mr-8 shadow-2xl border border-white/20 relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-br from-purple-400/20 to-indigo-400/20 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                <CogIcon className="h-10 w-10 text-white relative z-10 group-hover:rotate-180 transition-transform duration-700 ease-in-out" />
                <div className="absolute -inset-1 bg-gradient-to-r from-purple-400 to-indigo-400 rounded-3xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-500"></div>
              </div>
              <div>
                <h1 className="text-4xl font-bold">Admin Dashboard</h1>
                <p className="text-purple-100 text-lg mt-2">
                  Manage users, view system statistics, and monitor audit logs
                </p>
              </div>
            </div>
        </div>
      </div>


      {/* Enhanced System Statistics */}
      {systemStats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-all duration-300 transform hover:scale-105 hover:border-blue-200 cursor-pointer group">
            <div className="flex items-center">
              <div className="w-14 h-14 bg-gradient-to-br from-blue-500 to-blue-600 rounded-2xl flex items-center justify-center mr-4 group-hover:scale-110 transition-transform duration-300 shadow-lg relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                <UserGroupIcon className="h-7 w-7 text-white relative z-10" />
                <div className="absolute -inset-1 bg-gradient-to-r from-blue-400 to-blue-500 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-600 group-hover:text-blue-600 transition-colors duration-300">Total Users</p>
                <p className="text-2xl font-bold text-gray-900 group-hover:text-blue-700 transition-colors duration-300">{systemStats.users.total}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-all duration-300 transform hover:scale-105 hover:border-emerald-200 cursor-pointer group">
            <div className="flex items-center">
              <div className="w-14 h-14 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-2xl flex items-center justify-center mr-4 group-hover:scale-110 transition-transform duration-300 shadow-lg relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                <CheckCircleIcon className="h-7 w-7 text-white relative z-10" />
                <div className="absolute -inset-1 bg-gradient-to-r from-emerald-400 to-teal-500 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-600 group-hover:text-emerald-600 transition-colors duration-300">Active Users</p>
                <p className="text-2xl font-bold text-gray-900 group-hover:text-emerald-700 transition-colors duration-300">{systemStats.users.active}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-all duration-300 transform hover:scale-105 hover:border-purple-200 cursor-pointer group">
            <div className="flex items-center">
              <div className="w-14 h-14 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl flex items-center justify-center mr-4 group-hover:scale-110 transition-transform duration-300 shadow-lg relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                <PlusIcon className="h-7 w-7 text-white relative z-10" />
                <div className="absolute -inset-1 bg-gradient-to-r from-purple-400 to-indigo-500 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-600 group-hover:text-purple-600 transition-colors duration-300">New Users (30d)</p>
                <p className="text-2xl font-bold text-gray-900 group-hover:text-purple-700 transition-colors duration-300">{systemStats.users.new}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-all duration-300 transform hover:scale-105 hover:border-orange-200 cursor-pointer group">
            <div className="flex items-center">
              <div className="w-14 h-14 bg-gradient-to-br from-orange-500 to-red-500 rounded-2xl flex items-center justify-center mr-4 group-hover:scale-110 transition-transform duration-300 shadow-lg relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                <ChartBarIcon className="h-7 w-7 text-white relative z-10" />
                <div className="absolute -inset-1 bg-gradient-to-r from-orange-400 to-red-400 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-600 group-hover:text-orange-600 transition-colors duration-300">Total Activity</p>
                <p className="text-2xl font-bold text-gray-900 group-hover:text-orange-700 transition-colors duration-300">
                  {systemStats.activity.reduce((sum, item) => sum + item.count, 0)}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Enhanced Tab Navigation */}
      <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-2">
        <nav className="flex space-x-2">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'dashboard'
                ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-lg ring-2 ring-purple-200'
                : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50 hover:shadow-md active:scale-95'
            }`}
          >
            <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5a2 2 0 012-2h4a2 2 0 012 2v6H8V5z" />
            </svg>
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab('users')}
            className={`flex items-center px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'users'
                ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-lg ring-2 ring-purple-200'
                : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50 hover:shadow-md active:scale-95'
            }`}
          >
            <UserGroupIcon className="h-5 w-5 mr-2" />
            Users
          </button>
          <button
            onClick={() => {
              setActiveTab('audit');
              fetchAuditLogs();
            }}
            className={`flex items-center px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'audit'
                ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-lg ring-2 ring-purple-200'
                : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50 hover:shadow-md active:scale-95'
            }`}
          >
            <DocumentTextIcon className="h-5 w-5 mr-2" />
            Audit Logs
          </button>
          <button
            onClick={() => setActiveTab('stats')}
            className={`flex items-center px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'stats'
                ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-lg ring-2 ring-purple-200'
                : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50 hover:shadow-md active:scale-95'
            }`}
          >
            <ChartBarIcon className="h-5 w-5 mr-2" />
            Statistics
          </button>
          <button
            onClick={() => setActiveTab('analytics')}
            className={`flex items-center px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'analytics'
                ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-lg ring-2 ring-purple-200'
                : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50 hover:shadow-md active:scale-95'
            }`}
          >
            <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            User Analytics
          </button>
          <button
            onClick={() => setActiveTab('api')}
            className={`flex items-center px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'api'
                ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-lg ring-2 ring-purple-200'
                : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50 hover:shadow-md active:scale-95'
            }`}
          >
            <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
            API Analytics
          </button>
          <button
            onClick={() => setActiveTab('archival')}
            className={`flex items-center px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'archival'
                ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-lg ring-2 ring-purple-200'
                : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50 hover:shadow-md active:scale-95'
            }`}
          >
            <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
            </svg>
            Data Archival
          </button>
          <button
            onClick={() => setActiveTab('customFields')}
            className={`flex items-center px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 transform hover:scale-105 ${
              activeTab === 'customFields'
                ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-lg ring-2 ring-purple-200'
                : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50 hover:shadow-md active:scale-95'
            }`}
          >
            <CogIcon className="h-5 w-5 mr-2" />
            Custom Fields
          </button>
        </nav>
      </div>

      {/* Dashboard Tab */}
      {activeTab === 'dashboard' && (
        <div className="space-y-6">
          {/* Dashboard Header */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="flex items-center">
              <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl flex items-center justify-center mr-4 shadow-lg relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                <svg className="h-6 w-6 text-white relative z-10 group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5a2 2 0 012-2h4a2 2 0 012 2v6H8V5z" />
                </svg>
                <div className="absolute -inset-1 bg-gradient-to-r from-purple-400 to-indigo-400 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
              </div>
              <div>
                <h2 className="text-2xl font-bold text-gray-900">Admin Dashboard Overview</h2>
                <p className="text-sm text-gray-600">System overview and quick access to key metrics</p>
              </div>
              </div>
            </div>

          {/* Quick Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-2xl p-6 border border-blue-200 hover:shadow-lg transition-all duration-300 cursor-pointer group" onClick={() => setActiveTab('users')}>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-blue-600">Total Users</p>
                  <p className="text-3xl font-bold text-blue-900">{systemStats?.users.total || 0}</p>
                  <p className="text-xs text-blue-600 mt-1">+{systemStats?.users.new || 0} new this month</p>
                  </div>
                <div className="w-12 h-12 bg-blue-500 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                    <UserGroupIcon className="h-6 w-6 text-white" />
                  </div>
                </div>
              </div>

            <div className="bg-gradient-to-br from-emerald-50 to-emerald-100 rounded-2xl p-6 border border-emerald-200 hover:shadow-lg transition-all duration-300 cursor-pointer group" onClick={() => setActiveTab('audit')}>
                <div className="flex items-center justify-between">
                  <div>
                  <p className="text-sm font-medium text-emerald-600">Recent Activity</p>
                  <p className="text-3xl font-bold text-emerald-900">{auditLogs.length}</p>
                  <p className="text-xs text-emerald-600 mt-1">audit logs</p>
                  </div>
                <div className="w-12 h-12 bg-emerald-500 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                  <DocumentTextIcon className="h-6 w-6 text-white" />
                  </div>
                </div>
              </div>

            <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-2xl p-6 border border-purple-200 hover:shadow-lg transition-all duration-300 cursor-pointer group" onClick={() => setActiveTab('analytics')}>
                <div className="flex items-center justify-between">
                  <div>
                  <p className="text-sm font-medium text-purple-600">Active Users</p>
                  <p className="text-3xl font-bold text-purple-900">{systemStats?.users.active || 0}</p>
                  <p className="text-xs text-purple-600 mt-1">
                    {systemStats?.users.total ? Math.round((systemStats.users.active / systemStats.users.total) * 100) : 0}% of total
                  </p>
                  </div>
                <div className="w-12 h-12 bg-purple-500 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                  <CheckCircleIcon className="h-6 w-6 text-white" />
                  </div>
                </div>
              </div>

            <div className="bg-gradient-to-br from-orange-50 to-orange-100 rounded-2xl p-6 border border-orange-200 hover:shadow-lg transition-all duration-300 cursor-pointer group" onClick={() => setActiveTab('api')}>
                <div className="flex items-center justify-between">
                  <div>
                  <p className="text-sm font-medium text-orange-600">API Hits</p>
                  <p className="text-3xl font-bold text-orange-900">{systemStats?.apiUsage?.totalHits || 0}</p>
                  <p className="text-xs text-orange-600 mt-1">total requests</p>
                  </div>
                <div className="w-12 h-12 bg-orange-500 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                    <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                  </div>
                </div>
              </div>
            </div>

          {/* Quick Actions */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
              <div className="space-y-3">
                <button
                  onClick={() => setShowCreateUser(true)}
                  className="w-full flex items-center justify-between p-4 bg-gradient-to-r from-purple-50 to-indigo-50 rounded-xl border border-purple-200 hover:shadow-md transition-all duration-200 group"
                >
                  <div className="flex items-center">
                    <div className="w-10 h-10 bg-purple-500 rounded-lg flex items-center justify-center mr-3 group-hover:scale-110 transition-transform duration-300">
                      <PlusIcon className="h-5 w-5 text-white" />
                    </div>
                    <div className="text-left">
                      <p className="font-medium text-gray-900">Create New User</p>
                      <p className="text-sm text-gray-600">Add a new user to the system</p>
                    </div>
                  </div>
                  <svg className="h-5 w-5 text-gray-400 group-hover:text-purple-600 transition-colors duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </button>

                <button
                  onClick={() => setActiveTab('audit')}
                  className="w-full flex items-center justify-between p-4 bg-gradient-to-r from-emerald-50 to-teal-50 rounded-xl border border-emerald-200 hover:shadow-md transition-all duration-200 group"
                >
                  <div className="flex items-center">
                    <div className="w-10 h-10 bg-emerald-500 rounded-lg flex items-center justify-center mr-3 group-hover:scale-110 transition-transform duration-300">
                      <DocumentTextIcon className="h-5 w-5 text-white" />
              </div>
                    <div className="text-left">
                      <p className="font-medium text-gray-900">View Audit Logs</p>
                      <p className="text-sm text-gray-600">Monitor system activities</p>
                    </div>
                  </div>
                  <svg className="h-5 w-5 text-gray-400 group-hover:text-emerald-600 transition-colors duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </button>

                <button
                  onClick={() => setActiveTab('stats')}
                  className="w-full flex items-center justify-between p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl border border-blue-200 hover:shadow-md transition-all duration-200 group"
                >
                  <div className="flex items-center">
                    <div className="w-10 h-10 bg-blue-500 rounded-lg flex items-center justify-center mr-3 group-hover:scale-110 transition-transform duration-300">
                      <ChartBarIcon className="h-5 w-5 text-white" />
                    </div>
                    <div className="text-left">
                      <p className="font-medium text-gray-900">View Statistics</p>
                      <p className="text-sm text-gray-600">Detailed system metrics</p>
                    </div>
                  </div>
                  <svg className="h-5 w-5 text-gray-400 group-hover:text-blue-600 transition-colors duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </button>
              </div>
            </div>

            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
              <div className="space-y-3">
                {auditLogs.slice(0, 5).map((log) => (
                  <div key={log._id} className="flex items-center p-3 bg-gray-50 rounded-lg">
                    <div className="w-8 h-8 bg-gray-200 rounded-full flex items-center justify-center mr-3">
                      <EyeIcon className="h-4 w-4 text-gray-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate">
                        {log.userId?.name || 'System'} - {log.action}
                      </p>
                      <p className="text-xs text-gray-500">
                        {log.module} • {new Date(log.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                ))}
                {auditLogs.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    <DocumentTextIcon className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                    <p>No recent activity</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Enhanced Users Tab */}
      {activeTab === 'users' && (
        <div className="space-y-6">
          {/* Users Header with Controls */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl flex items-center justify-center mr-4 shadow-lg relative overflow-hidden group">
                  <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  <UserGroupIcon className="h-6 w-6 text-white relative z-10 group-hover:scale-110 transition-transform duration-300" />
                  <div className="absolute -inset-1 bg-gradient-to-r from-purple-400 to-indigo-400 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
                </div>
              <div>
                  <h2 className="text-2xl font-bold text-gray-900">User Management</h2>
                  <p className="text-sm text-gray-600">Manage users, roles, and permissions</p>
              </div>
            </div>

              <div className="flex items-center space-x-3">
                <button
                  onClick={refreshUsers}
                  disabled={usersLoading}
                  className="inline-flex items-center px-4 py-2 bg-gray-100 text-gray-700 font-medium rounded-lg hover:bg-gray-200 transition-colors duration-200 disabled:opacity-50"
                >
                  {usersLoading ? (
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-gray-600 mr-2"></div>
                  ) : (
                    <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                  )}
                  {usersLoading ? 'Loading...' : 'Refresh'}
                </button>
              <button
                onClick={() => setShowCreateUser(true)}
                className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-purple-500 to-indigo-600 text-white font-medium rounded-xl shadow-lg hover:from-purple-600 hover:to-indigo-700 transform hover:scale-105 hover:shadow-xl active:scale-95 transition-all duration-300 ring-2 ring-purple-200/50 hover:ring-purple-300/50"
              >
                <PlusIcon className="h-4 w-4 mr-2" />
                Add User
              </button>
                  </div>
            </div>
          </div>

          {/* Search and Filter Controls */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {/* Search */}
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-gray-700 mb-2">Search Users</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <svg className="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
            </div>
                  <input
                    type="text"
                    placeholder="Search by name or email..."
                    value={userSearchTerm}
                    onChange={(e) => setUserSearchTerm(e.target.value)}
                    className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                  />
                </div>
              </div>

              {/* Role Filter */}
                  <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Role</label>
                <select
                  value={userFilterRole}
                  onChange={(e) => setUserFilterRole(e.target.value)}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                >
                  <option value="all">All Roles</option>
                  <option value="admin">Admin</option>
                  <option value="user">User</option>
                </select>
              </div>

              {/* Status Filter */}
                  <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Status</label>
                <select
                  value={userFilterStatus}
                  onChange={(e) => setUserFilterStatus(e.target.value)}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                >
                  <option value="all">All Status</option>
                  <option value="active">Active</option>
                  <option value="suspended">Suspended</option>
                  <option value="inactive">Inactive</option>
                </select>
                  </div>
                  </div>

            {/* Results Summary */}
            <div className="mt-4 flex items-center justify-between">
              <div className="text-sm text-gray-600">
                Showing {filteredUsers.length} of {users.length} users
                {userSearchTerm && (
                  <span className="ml-2 text-purple-600">
                    for "{userSearchTerm}"
                  </span>
                )}
                </div>
              <div className="flex items-center space-x-2 text-sm text-gray-500">
                <span>Active: {users.filter(u => u.status === 'active').length}</span>
                <span>•</span>
                <span>Admins: {users.filter(u => u.role === 'admin').length}</span>
                <span>•</span>
                <span>Users: {users.filter(u => u.role === 'user').length}</span>
              </div>
            </div>
              </div>
              
          {/* Loading State */}
          {usersLoading && (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-purple-600 mx-auto mb-4"></div>
                <p className="text-lg font-medium text-gray-600">Loading users...</p>
                <p className="text-sm text-gray-500">Please wait while we fetch the user data</p>
          </div>
        </div>
      )}

          {/* Users List */}
          {!usersLoading && (
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden">
              {filteredUsers.length > 0 ? (
              <div className="divide-y divide-gray-100">
                  {filteredUsers.map((user) => (
                  <div key={user._id} className="p-6 hover:bg-gradient-to-r hover:from-purple-50/50 hover:to-indigo-50/50 transition-all duration-200">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center shadow-lg relative overflow-hidden group cursor-pointer">
                            <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                            <span className="text-lg font-bold text-white relative z-10 group-hover:scale-110 transition-transform duration-300">
                              {user.name.charAt(0).toUpperCase()}
                            </span>
                            <div className="absolute -inset-1 bg-gradient-to-r from-purple-400 to-indigo-400 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="text-lg font-semibold text-gray-900">{user.name}</div>
                          <div className="text-sm text-gray-600">{user.email}</div>
                          <div className="flex items-center mt-2 space-x-2">
                            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                              {user.role}
                            </span>
                            <div className="flex items-center">
                              {getStatusIcon(user.status)}
                              <span className={`ml-1 inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(user.status)}`}>
                                {user.status}
                              </span>
                            </div>
                          </div>
                          <div className="flex items-center mt-3">
                            <span className="text-xs text-gray-500 mr-2">Modules:</span>
                            {user.moduleAccess.length > 0 ? (
                              user.moduleAccess.map((module) => (
                                <span
                                  key={module}
                                  className="inline-flex items-center px-2 py-1 rounded-lg text-xs font-medium bg-blue-100 text-blue-800 mr-2"
                                >
                                  {module === 'pan-kyc' ? 'PAN KYC' : 
                                   module === 'aadhaar-pan' ? 'Aadhaar-PAN' : 
                                   module === 'aadhaar-verification' ? 'Aadhaar Verification' :
                                   module === 'selfie-upload' ? 'Selfie Upload' :
                                   module === 'qr-code' ? 'QR Code' : module}
                                </span>
                              ))
                            ) : (
                              <span className="text-xs text-gray-400">No modules assigned</span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3">
                        <button
                          onClick={() => handleManageModuleAccess(user)}
                          className="p-3 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded-xl transition-all duration-300 transform hover:scale-110 active:scale-95 hover:shadow-md relative overflow-hidden group"
                          title="Manage Module Access"
                        >
                          <div className="absolute inset-0 bg-gradient-to-br from-blue-100 to-blue-200 opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
                          <CogIcon className="h-5 w-5 relative z-10 group-hover:rotate-180 transition-transform duration-500 ease-in-out" />
                        </button>
                        {user.moduleAccess && user.moduleAccess.includes('qr-code') && (
                          <button
                            onClick={() => handleViewQrCode(user)}
                            className="p-3 text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition-all duration-300 transform hover:scale-110 active:scale-95 hover:shadow-md relative overflow-hidden group"
                            title="View QR Code"
                          >
                            <div className="absolute inset-0 bg-gradient-to-br from-indigo-100 to-indigo-200 opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
                            <svg className="h-5 w-5 relative z-10 group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" />
                            </svg>
                          </button>
                        )}
                        <button
                          onClick={() => handleManageBranding(user)}
                          className="p-3 text-gray-400 hover:text-green-600 hover:bg-green-50 rounded-xl transition-all duration-300 transform hover:scale-110 active:scale-95 hover:shadow-md relative overflow-hidden group"
                          title="Manage Branding"
                        >
                          <div className="absolute inset-0 bg-gradient-to-br from-green-100 to-green-200 opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
                          <svg className="h-5 w-5 relative z-10 group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zM21 5a2 2 0 00-2-2h-4a2 2 0 00-2 2v12a4 4 0 004 4h4a2 2 0 002-2V5z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => handleEditUser(user)}
                          className="p-3 text-gray-400 hover:text-gray-600 hover:bg-gray-50 rounded-xl transition-all duration-300 transform hover:scale-110 active:scale-95 hover:shadow-md relative overflow-hidden group"
                          title="Edit User"
                        >
                          <div className="absolute inset-0 bg-gradient-to-br from-gray-100 to-gray-200 opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
                          <PencilIcon className="h-5 w-5 relative z-10 group-hover:rotate-12 transition-transform duration-300 ease-in-out" />
                        </button>
                        <button
                          onClick={() => handleDeleteUser(user._id)}
                          className="p-3 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-xl transition-all duration-300 transform hover:scale-110 active:scale-95 hover:shadow-md relative overflow-hidden group"
                          title="Delete User"
                        >
                          <div className="absolute inset-0 bg-gradient-to-br from-red-100 to-red-200 opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
                          <TrashIcon className="h-5 w-5 relative z-10 group-hover:scale-110 transition-transform duration-300" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              ) : (
                <div className="text-center py-16">
                  <UserGroupIcon className="h-16 w-16 text-gray-300 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No users found</h3>
                  <p className="text-gray-600 mb-4">
                    {userSearchTerm || userFilterRole !== 'all' || userFilterStatus !== 'all'
                      ? 'Try adjusting your search or filter criteria.'
                      : 'Get started by creating your first user.'
                    }
                  </p>
                  {(!userSearchTerm && userFilterRole === 'all' && userFilterStatus === 'all') && (
                    <button
                      onClick={() => setShowCreateUser(true)}
                      className="inline-flex items-center px-4 py-2 bg-purple-600 text-white font-medium rounded-lg hover:bg-purple-700 transition-colors duration-200"
                    >
                      <PlusIcon className="h-4 w-4 mr-2" />
                      Create First User
                    </button>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Audit Logs Tab */}
      {activeTab === 'audit' && (
        <div className="space-y-6">
          {/* Audit Logs Header with Controls */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-2xl flex items-center justify-center mr-4 shadow-lg relative overflow-hidden group">
                  <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  <DocumentTextIcon className="h-6 w-6 text-white relative z-10 group-hover:scale-110 transition-transform duration-300" />
                  <div className="absolute -inset-1 bg-gradient-to-r from-emerald-400 to-teal-400 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
            </div>
                <div>
                  <h2 className="text-2xl font-bold text-gray-900">Audit Logs</h2>
                  <p className="text-sm text-gray-600">Track system activities and user actions</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-3">
                <button
                  onClick={refreshAuditLogs}
                  disabled={auditLoading}
                  className="inline-flex items-center px-4 py-2 bg-gray-100 text-gray-700 font-medium rounded-lg hover:bg-gray-200 transition-colors duration-200 disabled:opacity-50"
                >
                  {auditLoading ? (
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-gray-600 mr-2"></div>
                  ) : (
                    <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                  )}
                  {auditLoading ? 'Loading...' : 'Refresh'}
                </button>
                          </div>
                        </div>
                          </div>

          {/* Search and Filter Controls */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {/* Search */}
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-gray-700 mb-2">Search Logs</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <svg className="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                          </div>
                  <input
                    type="text"
                    placeholder="Search by user, action, module..."
                    value={auditSearchTerm}
                    onChange={(e) => setAuditSearchTerm(e.target.value)}
                    className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500"
                  />
                </div>
              </div>

              {/* Action Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Action</label>
                <select
                  value={auditFilterAction}
                  onChange={(e) => setAuditFilterAction(e.target.value)}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500"
                >
                  <option value="all">All Actions</option>
                  <option value="create">Create</option>
                  <option value="update">Update</option>
                  <option value="delete">Delete</option>
                  <option value="login">Login</option>
                  <option value="logout">Logout</option>
                  <option value="upload">Upload</option>
                  <option value="download">Download</option>
                </select>
              </div>

              {/* Module Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Module</label>
                <select
                  value={auditFilterModule}
                  onChange={(e) => setAuditFilterModule(e.target.value)}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500"
                >
                  <option value="all">All Modules</option>
                  <option value="auth">Authentication</option>
                  <option value="pan-kyc">PAN KYC</option>
                  <option value="aadhaar-pan">Aadhaar-PAN</option>
                  <option value="user_management">User Management</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            </div>

            {/* Results Summary */}
            <div className="mt-4 flex items-center justify-between">
              <div className="text-sm text-gray-600">
                Showing {paginatedAuditLogs.length} of {filteredAuditLogs.length} logs
                {auditSearchTerm && (
                  <span className="ml-2 text-emerald-600">
                    for "{auditSearchTerm}"
                  </span>
                )}
              </div>
              <div className="flex items-center space-x-2 text-sm text-gray-500">
                <span>Page {auditPage} of {totalAuditPages}</span>
                <span>•</span>
                <span>Total: {auditLogs.length} logs</span>
              </div>
            </div>
          </div>

          {/* Loading State */}
          {auditLoading && (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-emerald-600 mx-auto mb-4"></div>
                <p className="text-lg font-medium text-gray-600">Loading audit logs...</p>
                <p className="text-sm text-gray-500">Please wait while we fetch the activity data</p>
              </div>
            </div>
          )}

          {/* Audit Logs List */}
          {!auditLoading && (
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden">
              {paginatedAuditLogs.length > 0 ? (
                <>
                  <div className="divide-y divide-gray-100">
                    {paginatedAuditLogs.map((log) => (
                      <div key={log._id} className="p-6 hover:bg-gradient-to-r hover:from-emerald-50/50 hover:to-teal-50/50 transition-all duration-200">
                        <div className="flex items-start justify-between">
                          <div className="flex items-start">
                            <div className="flex-shrink-0">
                              <div className="h-12 w-12 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center shadow-lg relative overflow-hidden group">
                                <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                                <EyeIcon className="h-6 w-6 text-white relative z-10 group-hover:scale-110 transition-transform duration-300" />
                                <div className="absolute -inset-1 bg-gradient-to-r from-emerald-400 to-teal-400 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
                              </div>
                            </div>
                            <div className="ml-4 flex-1">
                              <div className="flex items-center space-x-2 mb-2">
                                <h3 className="text-lg font-semibold text-gray-900">
                                  {log.userId?.name || 'System'}
                                </h3>
                                <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${getActionColor(log.action)}`}>
                              {log.action}
                            </span>
                              </div>
                              <div className="text-sm text-gray-600 mb-2">
                                <span className="font-medium">{log.module}</span> • 
                                <span className="ml-1">{log.resource}</span>
                                {log.resourceId && (
                                  <span className="ml-1 text-gray-500">(ID: {log.resourceId})</span>
                                )}
                              </div>
                              <div className="flex items-center space-x-4 text-xs text-gray-500">
                                <span className="flex items-center">
                                  <svg className="h-4 w-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                                  </svg>
                                  {new Date(log.createdAt).toLocaleString()}
                            </span>
                            {log.ipAddress && (
                                  <span className="flex items-center">
                                    <svg className="h-4 w-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9v-9m0-9v9" />
                                    </svg>
                                    {log.ipAddress}
                              </span>
                            )}
                                <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                                  log.status === 'success' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                                }`}>
                                  {log.status}
                                </span>
                          </div>
                              {log.details && Object.keys(log.details).length > 0 && (
                                <div className="mt-3 p-3 bg-gray-50 rounded-lg">
                                  <details className="text-sm">
                                    <summary className="cursor-pointer text-gray-700 font-medium">View Details</summary>
                                    <pre className="mt-2 text-xs text-gray-600 whitespace-pre-wrap">
                                      {JSON.stringify(log.details, null, 2)}
                                    </pre>
                                  </details>
                        </div>
                              )}
                      </div>
                    </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Pagination */}
                  {totalAuditPages > 1 && (
                    <div className="bg-gray-50 px-6 py-4 flex items-center justify-between border-t border-gray-200">
                      <div className="flex items-center text-sm text-gray-700">
                        <span>
                          Showing {((auditPage - 1) * auditPageSize) + 1} to {Math.min(auditPage * auditPageSize, filteredAuditLogs.length)} of {filteredAuditLogs.length} results
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setAuditPage(Math.max(1, auditPage - 1))}
                          disabled={auditPage === 1}
                          className="px-3 py-2 text-sm font-medium text-gray-500 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          Previous
                        </button>
                        <div className="flex items-center space-x-1">
                          {Array.from({ length: Math.min(5, totalAuditPages) }, (_, i) => {
                            const pageNum = i + 1;
                            return (
                              <button
                                key={pageNum}
                                onClick={() => setAuditPage(pageNum)}
                                className={`px-3 py-2 text-sm font-medium rounded-lg ${
                                  auditPage === pageNum
                                    ? 'bg-emerald-600 text-white'
                                    : 'text-gray-500 bg-white border border-gray-300 hover:bg-gray-50'
                                }`}
                              >
                                {pageNum}
                              </button>
                            );
                          })}
                        </div>
                        <button
                          onClick={() => setAuditPage(Math.min(totalAuditPages, auditPage + 1))}
                          disabled={auditPage === totalAuditPages}
                          className="px-3 py-2 text-sm font-medium text-gray-500 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="text-center py-16">
                  <DocumentTextIcon className="h-16 w-16 text-gray-300 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No audit logs found</h3>
                  <p className="text-gray-600 mb-4">
                    {auditSearchTerm || auditFilterAction !== 'all' || auditFilterModule !== 'all'
                      ? 'Try adjusting your search or filter criteria.'
                      : 'No activity has been recorded yet.'
                    }
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Statistics Tab */}
      {activeTab === 'stats' && (
        <div className="space-y-6">
          {/* Statistics Header with Controls */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-2xl flex items-center justify-center mr-4 shadow-lg relative overflow-hidden group">
                  <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  <ChartBarIcon className="h-6 w-6 text-white relative z-10 group-hover:scale-110 transition-transform duration-300" />
                  <div className="absolute -inset-1 bg-gradient-to-r from-blue-400 to-indigo-400 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-gray-900">System Statistics</h2>
                  <p className="text-sm text-gray-600">Real-time system performance and usage metrics</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-3">
                {/* Time Range Selector */}
                <div className="flex items-center space-x-2">
                  <label className="text-sm font-medium text-gray-700">Time Range:</label>
                  <select
                    value={statsTimeRange}
                    onChange={(e) => handleTimeRangeChange(e.target.value)}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    disabled={statsLoading}
                  >
                    <option value="7">Last 7 days</option>
                    <option value="30">Last 30 days</option>
                    <option value="90">Last 90 days</option>
                  </select>
                </div>
                
                {/* Refresh Button */}
                <button
                  onClick={refreshStats}
                  disabled={statsLoading}
                  className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-blue-500 to-indigo-600 text-white font-medium rounded-lg shadow-lg hover:from-blue-600 hover:to-indigo-700 transform hover:scale-105 hover:shadow-xl active:scale-95 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {statsLoading ? (
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  ) : (
                    <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                  )}
                  {statsLoading ? 'Loading...' : 'Refresh'}
                </button>
              </div>
            </div>
          </div>

          {/* Loading State */}
          {statsLoading && (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-600 mx-auto mb-4"></div>
                <p className="text-lg font-medium text-gray-600">Loading statistics...</p>
                <p className="text-sm text-gray-500">Please wait while we fetch the latest data</p>
              </div>
            </div>
          )}

          {/* Statistics Content */}
          {!statsLoading && systemStats && (
            <div className="space-y-6">
              {/* Overview Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-2xl p-6 border border-blue-200 hover:shadow-lg transition-all duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-blue-600">Total Users</p>
                      <p className="text-3xl font-bold text-blue-900">{systemStats.users.total}</p>
                      <p className="text-xs text-blue-600 mt-1">+{systemStats.users.new} new this period</p>
                    </div>
                    <div className="w-12 h-12 bg-blue-500 rounded-xl flex items-center justify-center">
                      <UserGroupIcon className="h-6 w-6 text-white" />
                    </div>
                  </div>
                </div>

                <div className="bg-gradient-to-br from-emerald-50 to-emerald-100 rounded-2xl p-6 border border-emerald-200 hover:shadow-lg transition-all duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-emerald-600">Active Users</p>
                      <p className="text-3xl font-bold text-emerald-900">{systemStats.users.active}</p>
                      <p className="text-xs text-emerald-600 mt-1">
                        {Math.round((systemStats.users.active / systemStats.users.total) * 100)}% of total
                      </p>
                    </div>
                    <div className="w-12 h-12 bg-emerald-500 rounded-xl flex items-center justify-center">
                      <CheckCircleIcon className="h-6 w-6 text-white" />
                    </div>
                  </div>
                </div>

                <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-2xl p-6 border border-purple-200 hover:shadow-lg transition-all duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-purple-600">Total Activity</p>
                      <p className="text-3xl font-bold text-purple-900">
                        {systemStats.activity.reduce((sum, item) => sum + item.count, 0)}
                      </p>
                      <p className="text-xs text-purple-600 mt-1">Actions performed</p>
                    </div>
                    <div className="w-12 h-12 bg-purple-500 rounded-xl flex items-center justify-center">
                      <ChartBarIcon className="h-6 w-6 text-white" />
                    </div>
                  </div>
                </div>

                <div className="bg-gradient-to-br from-orange-50 to-orange-100 rounded-2xl p-6 border border-orange-200 hover:shadow-lg transition-all duration-300">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-orange-600">Daily Activity</p>
                      <p className="text-3xl font-bold text-orange-900">
                        {systemStats.dailyActivity.length > 0 
                          ? Math.round(systemStats.dailyActivity.reduce((sum, item) => sum + item.count, 0) / systemStats.dailyActivity.length)
                          : 0
                        }
                      </p>
                      <p className="text-xs text-orange-600 mt-1">Average per day</p>
                    </div>
                    <div className="w-12 h-12 bg-orange-500 rounded-xl flex items-center justify-center">
                      <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                  </div>
                </div>
              </div>

              {/* Detailed Statistics */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* PAN KYC Statistics */}
                <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
                  <div className="flex items-center mb-6">
                    <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center mr-3">
                      <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                  </div>
                    <h3 className="text-lg font-semibold text-gray-900">PAN KYC Statistics</h3>
                  </div>
                  <div className="space-y-3">
                    {systemStats.panKyc.length > 0 ? (
                      systemStats.panKyc.map((stat) => (
                        <div key={stat._id} className="flex items-center justify-between p-3 bg-gradient-to-r from-indigo-50 to-purple-50 rounded-xl border border-indigo-200">
                          <div className="flex items-center">
                            <div className="w-8 h-8 bg-indigo-500 rounded-lg flex items-center justify-center text-white text-sm font-bold mr-3">
                              {stat._id.charAt(0).toUpperCase()}
                            </div>
                            <span className="text-sm font-medium text-gray-700 capitalize">{stat._id}</span>
                          </div>
                          <span className="text-lg font-bold text-indigo-600">{stat.count}</span>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-8 text-gray-500">
                        <svg className="h-12 w-12 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        <p>No PAN KYC data available</p>
                      </div>
                    )}
              </div>
            </div>

            {/* Aadhaar-PAN Statistics */}
                <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
                  <div className="flex items-center mb-6">
                    <div className="w-10 h-10 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl flex items-center justify-center mr-3">
                      <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />
                      </svg>
                  </div>
                    <h3 className="text-lg font-semibold text-gray-900">Aadhaar-PAN Statistics</h3>
              </div>
                  <div className="space-y-3">
                    {systemStats.aadhaarPan.length > 0 ? (
                      systemStats.aadhaarPan.map((stat) => (
                        <div key={stat._id} className="flex items-center justify-between p-3 bg-gradient-to-r from-emerald-50 to-teal-50 rounded-xl border border-emerald-200">
                          <div className="flex items-center">
                            <div className="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center text-white text-sm font-bold mr-3">
                              {stat._id.charAt(0).toUpperCase()}
                            </div>
                            <span className="text-sm font-medium text-gray-700 capitalize">{stat._id}</span>
                          </div>
                          <span className="text-lg font-bold text-emerald-600">{stat.count}</span>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-8 text-gray-500">
                        <svg className="h-12 w-12 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />
                        </svg>
                        <p>No Aadhaar-PAN data available</p>
                      </div>
                    )}
                  </div>
            </div>
          </div>

          {/* Activity Statistics */}
              <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
                <div className="flex items-center mb-6">
                  <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-red-600 rounded-xl flex items-center justify-center mr-3">
                    <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                </div>
                  <h3 className="text-lg font-semibold text-gray-900">Recent Activity</h3>
            </div>
                <div className="space-y-3">
                  {systemStats.activity.length > 0 ? (
                    systemStats.activity.slice(0, 10).map((stat, index) => (
                      <div key={stat._id} className="flex items-center justify-between p-3 bg-gradient-to-r from-orange-50 to-red-50 rounded-xl border border-orange-200">
                        <div className="flex items-center">
                          <div className="w-8 h-8 bg-orange-500 rounded-lg flex items-center justify-center text-white text-sm font-bold mr-3">
                            {index + 1}
          </div>
                          <span className="text-sm font-medium text-gray-700 capitalize">
                            {stat._id.replace(/_/g, ' ')}
                          </span>
                        </div>
                        <span className="text-lg font-bold text-orange-600">{stat.count}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-gray-500">
                      <svg className="h-12 w-12 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                      </svg>
                      <p>No activity data available</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Daily Activity Chart */}
              {systemStats.dailyActivity.length > 0 && (
                <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
                  <div className="flex items-center mb-6">
                    <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center mr-3">
                      <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2zm0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                      </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900">Daily Activity Trend</h3>
                  </div>
                  <div className="space-y-3">
                    {systemStats.dailyActivity.map((day, index) => {
                      const maxCount = Math.max(...systemStats.dailyActivity.map(d => d.count));
                      const percentage = maxCount > 0 ? (day.count / maxCount) * 100 : 0;
                      
                      return (
                        <div key={day._id} className="flex items-center">
                          <div className="w-20 text-sm text-gray-600 font-medium">
                            {new Date(day._id).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                          </div>
                          <div className="flex-1 mx-4">
                            <div className="w-full bg-gray-200 rounded-full h-6 relative overflow-hidden">
                              <div 
                                className="h-6 bg-gradient-to-r from-blue-500 to-indigo-600 rounded-full transition-all duration-1000 ease-out"
                                style={{ width: `${percentage}%` }}
                              ></div>
                            </div>
                          </div>
                          <div className="w-16 text-sm font-bold text-gray-900 text-right">
                            {day.count}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Error State */}
          {!statsLoading && !systemStats && (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <XCircleIcon className="h-16 w-16 text-red-500 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to Load Statistics</h3>
                <p className="text-gray-600 mb-4">There was an error loading the system statistics.</p>
                <button
                  onClick={refreshStats}
                  className="inline-flex items-center px-4 py-2 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors duration-200"
                >
                  <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  Try Again
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* User Analytics Tab */}
      {activeTab === 'analytics' && (
        <div className="space-y-6">
          {/* Analytics Header with Controls */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div className="flex items-center">
              <div className="w-12 h-12 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-2xl flex items-center justify-center mr-4 shadow-lg relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                <svg className="h-6 w-6 text-white relative z-10 group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                <div className="absolute -inset-1 bg-gradient-to-r from-emerald-400 to-teal-500 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
              </div>
                <div>
              <h2 className="text-2xl font-bold text-gray-900">User Analytics Dashboard</h2>
                  <p className="text-sm text-gray-600">Comprehensive user behavior and performance insights</p>
                </div>
            </div>
              
              <div className="flex items-center space-x-3">
                {/* Time Range Selector */}
                <div className="flex items-center space-x-2">
                  <label className="text-sm font-medium text-gray-700">Time Range:</label>
                  <select
                    value={analyticsTimeRange}
                    onChange={(e) => handleAnalyticsTimeRangeChange(e.target.value)}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500"
                    disabled={analyticsLoading}
                  >
                    <option value="7">Last 7 days</option>
                    <option value="30">Last 30 days</option>
                    <option value="90">Last 90 days</option>
                  </select>
                </div>
                
                {/* Refresh Button */}
                <button
                  onClick={refreshAnalytics}
                  disabled={analyticsLoading}
                  className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-emerald-500 to-teal-600 text-white font-medium rounded-lg shadow-lg hover:from-emerald-600 hover:to-teal-700 transform hover:scale-105 hover:shadow-xl active:scale-95 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {analyticsLoading ? (
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  ) : (
                    <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                  )}
                  {analyticsLoading ? 'Loading...' : 'Refresh'}
                </button>
              </div>
            </div>
          </div>

          {/* Loading State */}
          {analyticsLoading && (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-emerald-600 mx-auto mb-4"></div>
                <p className="text-lg font-medium text-gray-600">Loading analytics data...</p>
                <p className="text-sm text-gray-500">Please wait while we fetch the latest insights</p>
              </div>
            </div>
          )}

          {/* Analytics Content */}
          {!analyticsLoading && systemStats && (
            <div className="space-y-6">

            {/* Enhanced User Statistics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-2xl p-6 border border-blue-200 hover:shadow-lg transition-all duration-300">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-blue-600">Total Users</p>
                    <p className="text-2xl font-bold text-blue-900">{systemStats?.users.total || 0}</p>
                  </div>
                  <div className="w-12 h-12 bg-blue-500 rounded-xl flex items-center justify-center">
                    <UserGroupIcon className="h-6 w-6 text-white" />
                  </div>
                </div>
              </div>

              <div className="bg-gradient-to-br from-emerald-50 to-emerald-100 rounded-2xl p-6 border border-emerald-200 hover:shadow-lg transition-all duration-300">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-emerald-600">Active Users</p>
                    <p className="text-2xl font-bold text-emerald-900">{systemStats?.users.active || 0}</p>
                  </div>
                  <div className="w-12 h-12 bg-emerald-500 rounded-xl flex items-center justify-center">
                    <CheckCircleIcon className="h-6 w-6 text-white" />
                  </div>
                </div>
              </div>

              <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-2xl p-6 border border-purple-200 hover:shadow-lg transition-all duration-300">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-purple-600">New Users (30d)</p>
                    <p className="text-2xl font-bold text-purple-900">{systemStats?.users.new || 0}</p>
                  </div>
                  <div className="w-12 h-12 bg-purple-500 rounded-xl flex items-center justify-center">
                    <PlusIcon className="h-6 w-6 text-white" />
                  </div>
                </div>
              </div>

              <div className="bg-gradient-to-br from-orange-50 to-orange-100 rounded-2xl p-6 border border-orange-200 hover:shadow-lg transition-all duration-300">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-orange-600">Inactive Users</p>
                    <p className="text-2xl font-bold text-orange-900">{systemStats?.users.inactive || 0}</p>
                  </div>
                  <div className="w-12 h-12 bg-orange-500 rounded-xl flex items-center justify-center">
                    <ExclamationTriangleIcon className="h-6 w-6 text-white" />
                  </div>
                </div>
              </div>
            </div>

            {/* User Performance Metrics */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
              {/* Top Performers */}
              <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                  <svg className="h-5 w-5 mr-2 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
                  </svg>
                  Top Performers
                </h3>
                <div className="space-y-3">
                  {systemStats?.userPerformance?.topPerformers?.slice(0, 5).map((performer, index) => (
                    <div key={performer.userId} className="flex items-center justify-between p-3 bg-gradient-to-r from-emerald-50 to-teal-50 rounded-xl border border-emerald-200">
                      <div className="flex items-center">
                        <div className="w-8 h-8 bg-emerald-500 rounded-full flex items-center justify-center text-white text-sm font-bold mr-3">
                          {index + 1}
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">{performer.name}</p>
                          <p className="text-sm text-gray-600">{performer.module}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-lg font-bold text-emerald-600">{performer.count}</p>
                        <p className="text-xs text-gray-500">records</p>
                      </div>
                    </div>
                  )) || (
                    <div className="text-center py-8 text-gray-500">
                      <svg className="h-12 w-12 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                      </svg>
                      <p>No performance data available</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Recent User Activity */}
              <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                  <svg className="h-5 w-5 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Recent User Activity
                </h3>
                <div className="space-y-3">
                  {systemStats?.userPerformance?.recentActivity?.slice(0, 5).map((activity, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl border border-blue-200">
                      <div className="flex items-center">
                        <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm font-bold mr-3">
                          {index + 1}
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">{activity.name}</p>
                          <p className="text-sm text-gray-600">{activity.action}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-gray-500">{new Date(activity.timestamp).toLocaleDateString()}</p>
                      </div>
                    </div>
                  )) || (
                    <div className="text-center py-8 text-gray-500">
                      <svg className="h-12 w-12 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <p>No recent activity data</p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* User Engagement Metrics */}
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <svg className="h-5 w-5 mr-2 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                User Engagement Metrics
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="text-center p-4 bg-gradient-to-r from-purple-50 to-indigo-50 rounded-xl border border-purple-200">
                  <div className="w-16 h-16 bg-purple-500 rounded-full flex items-center justify-center mx-auto mb-3">
                    <svg className="h-8 w-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  </div>
                  <p className="text-2xl font-bold text-purple-900">{(systemStats?.users.total || 0) - (systemStats?.users.inactive || 0)}</p>
                  <p className="text-sm text-gray-600">Engaged Users</p>
                </div>

                <div className="text-center p-4 bg-gradient-to-r from-emerald-50 to-teal-50 rounded-xl border border-emerald-200">
                  <div className="w-16 h-16 bg-emerald-500 rounded-full flex items-center justify-center mx-auto mb-3">
                    <svg className="h-8 w-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <p className="text-2xl font-bold text-emerald-900">{Math.round(((systemStats?.users.active || 0) / (systemStats?.users.total || 1)) * 100)}%</p>
                  <p className="text-sm text-gray-600">Active Rate</p>
                </div>

                <div className="text-center p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl border border-blue-200">
                  <div className="w-16 h-16 bg-blue-500 rounded-full flex items-center justify-center mx-auto mb-3">
                    <svg className="h-8 w-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <p className="text-2xl font-bold text-blue-900">{systemStats?.users.new || 0}</p>
                  <p className="text-sm text-gray-600">New This Month</p>
                </div>
              </div>
            </div>
          </div>
          )}

          {/* Error State */}
          {!analyticsLoading && !systemStats && (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <XCircleIcon className="h-16 w-16 text-red-500 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to Load Analytics</h3>
                <p className="text-gray-600 mb-4">There was an error loading the analytics data.</p>
                <button
                  onClick={refreshAnalytics}
                  className="inline-flex items-center px-4 py-2 bg-emerald-600 text-white font-medium rounded-lg hover:bg-emerald-700 transition-colors duration-200"
                >
                  <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  Try Again
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* API Analytics Tab */}
      {activeTab === 'api' && (
        <div className="space-y-6">
          {/* Sandbox API Analytics Header */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-gradient-to-br from-orange-500 to-red-600 rounded-2xl flex items-center justify-center mr-4 shadow-lg relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                <svg className="h-6 w-6 text-white relative z-10 group-hover:scale-110 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                  <div className="absolute -inset-1 bg-gradient-to-r from-orange-400 to-red-500 rounded-2xl blur opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
              </div>
                <div>
                  <h2 className="text-2xl font-bold text-gray-900">Sandbox API Analytics Dashboard</h2>
                  <p className="text-sm text-gray-600">Monitor sandbox API usage and performance</p>
                </div>
            </div>

              <div className="flex items-center space-x-3">
                {/* Time Range Selector */}
                <div className="flex items-center space-x-2">
                  <label className="text-sm font-medium text-gray-700">Time Range:</label>
                  <select
                    value={apiTimeRange}
                    onChange={(e) => handleApiTimeRangeChange(e.target.value)}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                    disabled={apiLoading}
                  >
                    <option value="7">Last 7 days</option>
                    <option value="30">Last 30 days</option>
                    <option value="90">Last 90 days</option>
                  </select>
                  </div>
                
                {/* Refresh Button */}
                <button
                  onClick={refreshApiAnalytics}
                  disabled={apiLoading}
                  className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-orange-500 to-red-600 text-white font-medium rounded-lg shadow-lg hover:from-orange-600 hover:to-red-700 transform hover:scale-105 hover:shadow-xl active:scale-95 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {apiLoading ? (
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  ) : (
                    <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                  )}
                  {apiLoading ? 'Loading...' : 'Refresh'}
                </button>
                  </div>
                </div>
              </div>

          {/* Loading State */}
          {apiLoading && (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-orange-600 mx-auto mb-4"></div>
                <p className="text-lg font-medium text-gray-600">Loading sandbox API analytics...</p>
                <p className="text-sm text-gray-500">Please wait while we fetch the latest sandbox API data</p>
              </div>
            </div>
          )}

          {/* Sandbox API Analytics Content */}
          {!apiLoading && systemStats && (
            <div className="space-y-6">




            {/* Consolidated User API Activity */}
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-6 flex items-center">
                <svg className="h-5 w-5 mr-2 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                User API Activity Summary
              </h3>
              
              {/* Table Header */}
              <div className="grid grid-cols-12 gap-4 p-4 bg-gray-50 rounded-lg font-semibold text-sm text-gray-700 mb-4">
                <div className="col-span-3">User</div>
                <div className="col-span-2 text-center">PAN KYC API</div>
                <div className="col-span-2 text-center">Aadhaar PAN API</div>
                <div className="col-span-2 text-center">Total API</div>
                <div className="col-span-2 text-center">Success Rate</div>
                <div className="col-span-1 text-center">Status</div>
              </div>

              {/* Table Content */}
              <div className="space-y-3">
                {(() => {
                  // Combine PAN KYC and Aadhaar PAN data
                  const panKycData = systemStats?.apiUsage?.panKycUserWise || [];
                  const aadhaarPanData = systemStats?.apiUsage?.aadhaarPanUserWise || [];
                  
                  // Create a map to combine user data
                  const userMap = new Map();
                  
                  // Add PAN KYC data
                  panKycData.forEach(user => {
                    userMap.set(user.userId, {
                      userId: user.userId,
                      name: user.name,
                      email: user.email,
                      panKycApiCalls: user.apiCalls,
                      panKycUploads: user.uploads,
                      panKycTotal: user.totalActivities,
                      panKycSuccess: user.successfulApiCalls,
                      panKycFailed: user.failedApiCalls,
                      panKycSuccessRate: user.successRate
                    });
                  });
                  
                  // Add Aadhaar PAN data
                  aadhaarPanData.forEach(user => {
                    const existing = userMap.get(user.userId);
                    if (existing) {
                      existing.aadhaarPanApiCalls = user.apiCalls;
                      existing.aadhaarPanUploads = user.uploads;
                      existing.aadhaarPanTotal = user.totalActivities;
                      existing.aadhaarPanSuccess = user.successfulApiCalls;
                      existing.aadhaarPanFailed = user.failedApiCalls;
                      existing.aadhaarPanSuccessRate = user.successRate;
                    } else {
                      userMap.set(user.userId, {
                        userId: user.userId,
                        name: user.name,
                        email: user.email,
                        panKycApiCalls: 0,
                        panKycUploads: 0,
                        panKycTotal: 0,
                        panKycSuccess: 0,
                        panKycFailed: 0,
                        panKycSuccessRate: 0,
                        aadhaarPanApiCalls: user.apiCalls,
                        aadhaarPanUploads: user.uploads,
                        aadhaarPanTotal: user.totalActivities,
                        aadhaarPanSuccess: user.successfulApiCalls,
                        aadhaarPanFailed: user.failedApiCalls,
                        aadhaarPanSuccessRate: user.successRate
                      });
                    }
                  });
                  
                  const combinedUsers = Array.from(userMap.values());
                  
                  return combinedUsers.length > 0 ? (
                    combinedUsers.map((user, index) => {
                      const totalApiCalls = (user.panKycApiCalls || 0) + (user.aadhaarPanApiCalls || 0);
                      const totalSuccess = (user.panKycSuccess || 0) + (user.aadhaarPanSuccess || 0);
                      // eslint-disable-next-line @typescript-eslint/no-unused-vars
                      const totalFailed = (user.panKycFailed || 0) + (user.aadhaarPanFailed || 0);
                      const overallSuccessRate = totalApiCalls > 0 ? (totalSuccess / totalApiCalls) * 100 : 0;
                      
                      return (
                        <div key={user.userId} className="grid grid-cols-12 gap-4 p-4 bg-gradient-to-r from-purple-50 to-indigo-50 rounded-lg border border-purple-200 hover:shadow-md transition-all duration-200">
                          {/* User Info */}
                          <div className="col-span-3">
                            <div className="flex items-center space-x-3">
                              <div className="w-8 h-8 bg-purple-500 rounded-full flex items-center justify-center text-white text-sm font-bold">
                                {index + 1}
                              </div>
                              <div>
                                <p className="font-semibold text-gray-900">{user.name}</p>
                                <p className="text-xs text-gray-600">{user.email}</p>
                              </div>
                            </div>
                          </div>
                          
                          {/* PAN KYC API */}
                          <div className="col-span-2 text-center">
                            <div className="space-y-1">
                              <p className="text-lg font-bold text-blue-600">{user.panKycApiCalls || 0}</p>
                              <div className="text-xs text-gray-500">
                                <p>📤 {user.panKycUploads || 0} uploads</p>
                                <p>✓ {user.panKycSuccess || 0} ✓</p>
                                <p>✗ {user.panKycFailed || 0} ✗</p>
                              </div>
                            </div>
                          </div>
                          
                          {/* Aadhaar PAN API */}
                          <div className="col-span-2 text-center">
                            <div className="space-y-1">
                              <p className="text-lg font-bold text-green-600">{user.aadhaarPanApiCalls || 0}</p>
                              <div className="text-xs text-gray-500">
                                <p>📤 {user.aadhaarPanUploads || 0} uploads</p>
                                <p>✓ {user.aadhaarPanSuccess || 0} ✓</p>
                                <p>✗ {user.aadhaarPanFailed || 0} ✗</p>
                              </div>
                            </div>
                          </div>
                          
                          {/* Total API */}
                          <div className="col-span-2 text-center">
                            <p className="text-xl font-bold text-purple-600">{totalApiCalls}</p>
                            <p className="text-xs text-gray-500">total calls</p>
                          </div>
                          
                          {/* Success Rate */}
                          <div className="col-span-2 text-center">
                            <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
                              overallSuccessRate >= 90 ? 'bg-green-100 text-green-800' :
                              overallSuccessRate >= 70 ? 'bg-yellow-100 text-yellow-800' :
                              'bg-red-100 text-red-800'
                            }`}>
                              {Math.round(overallSuccessRate)}%
                            </span>
                          </div>
                          
                          {/* Status */}
                          <div className="col-span-1 text-center">
                            <div className={`w-3 h-3 rounded-full mx-auto ${
                              totalApiCalls > 0 ? 'bg-green-400' : 'bg-gray-300'
                            }`}></div>
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <div className="text-center py-8 text-gray-500">
                      <svg className="h-12 w-12 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                      </svg>
                      <p>No API activity data available</p>
                    </div>
                  );
                })()}
              </div>
            </div>

                  </div>
          )}

          {/* Error State */}
          {!apiLoading && !systemStats && (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <XCircleIcon className="h-16 w-16 text-red-500 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to Load Sandbox API Analytics</h3>
                <p className="text-gray-600 mb-4">There was an error loading the sandbox API analytics data.</p>
                <button
                  onClick={refreshApiAnalytics}
                  className="inline-flex items-center px-4 py-2 bg-orange-600 text-white font-medium rounded-lg hover:bg-orange-700 transition-colors duration-200"
                >
                  <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  Try Again
                </button>
              </div>
                              </div>
                            )}
        </div>
      )}

      {/* Create/Edit User Modal */}
      {(showCreateUser || editingUser) && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50 flex items-center justify-center p-4">
          <div className="relative w-full max-w-3xl shadow-lg rounded-xl bg-white max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex justify-between items-center rounded-t-xl">
              <h3 className="text-lg font-semibold text-gray-900">
                {editingUser ? 'Edit User' : 'Create New User'}
              </h3>
              <button
                type="button"
                onClick={() => {
                  setShowCreateUser(false);
                  setEditingUser(null);
                  setFormData({
                    name: '',
                    email: '',
                    password: '',
                    role: 'user',
                    moduleAccess: [],
                    status: 'active',
                    enabledCustomFields: []
                  });
                }}
                className="text-gray-400 hover:text-gray-600 transition-colors"
              >
                <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="p-6">
              <form onSubmit={editingUser ? handleUpdateUser : handleCreateUser} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Name</label>
                  <input
                    type="text"
                    required
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Email</label>
                  <input
                    type="email"
                    required
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Password {editingUser && '(leave blank to keep current)'}
                  </label>
                  <input
                    type="password"
                    required={!editingUser}
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Role</label>
                  <select
                    value={formData.role}
                    onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500"
                  >
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Status</label>
                  <select
                    value={formData.status}
                    onChange={(e) => setFormData({ ...formData, status: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500"
                  >
                    <option value="active">Active</option>
                    <option value="suspended">Suspended</option>
                  </select>
                </div>
                
                {/* Custom Fields Access Control */}
                {editingUser && availableCustomFields.length > 0 && (
                  <div className="border-t border-gray-200 pt-4 mt-4">
                    <h4 className="text-sm font-semibold text-gray-900 mb-3">Enable Custom Fields for this User</h4>
                    <p className="text-xs text-gray-500 mb-3">Select which custom fields this user can access</p>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {availableCustomFields.map((field) => (
                        <label key={field._id} className="flex items-center space-x-2 p-2 hover:bg-gray-50 rounded-md cursor-pointer">
                          <input
                            type="checkbox"
                            checked={formData.enabledCustomFields.includes(field._id)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setFormData({
                                  ...formData,
                                  enabledCustomFields: [...formData.enabledCustomFields, field._id]
                                });
                              } else {
                                setFormData({
                                  ...formData,
                                  enabledCustomFields: formData.enabledCustomFields.filter(id => id !== field._id)
                                });
                              }
                            }}
                            className="h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-300 rounded"
                          />
                          <span className="text-sm font-medium text-gray-700">{field.fieldLabel}</span>
                          <span className="text-xs text-gray-400">({field.fieldType})</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}
                
                <div className="flex justify-end pt-6 border-t border-gray-200 mt-6">
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-6 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-medium rounded-lg hover:from-purple-700 hover:to-indigo-700 transition-all duration-200 shadow-md hover:shadow-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
                  >
                    {loading && (
                      <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                    )}
                    {loading ? 'Saving...' : (editingUser ? 'Update User' : 'Create User')}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Module Access Management Modal */}
      {showModuleAccess && selectedUserForModules && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                Manage Module Access for {selectedUserForModules.name}
              </h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Module Access</label>
                  <div className="space-y-2">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={selectedUserForModules.moduleAccess.includes('pan-kyc')}
                        onChange={(e) => {
                          const newModuleAccess = e.target.checked
                            ? [...selectedUserForModules.moduleAccess, 'pan-kyc']
                            : selectedUserForModules.moduleAccess.filter(m => m !== 'pan-kyc');
                          setSelectedUserForModules({
                            ...selectedUserForModules,
                            moduleAccess: newModuleAccess
                          });
                        }}
                        className="h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-300 rounded"
                      />
                      <span className="ml-2 text-sm text-gray-700">PAN KYC</span>
                    </label>
                    
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={selectedUserForModules.moduleAccess.includes('aadhaar-pan')}
                        onChange={(e) => {
                          const newModuleAccess = e.target.checked
                            ? [...selectedUserForModules.moduleAccess, 'aadhaar-pan']
                            : selectedUserForModules.moduleAccess.filter(m => m !== 'aadhaar-pan');
                          setSelectedUserForModules({
                            ...selectedUserForModules,
                            moduleAccess: newModuleAccess
                          });
                        }}
                        className="h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-300 rounded"
                      />
                      <span className="ml-2 text-sm text-gray-700">Aadhaar-PAN Linking</span>
                    </label>
                    
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={selectedUserForModules.moduleAccess.includes('aadhaar-verification')}
                        onChange={(e) => {
                          const newModuleAccess = e.target.checked
                            ? [...selectedUserForModules.moduleAccess, 'aadhaar-verification']
                            : selectedUserForModules.moduleAccess.filter(m => m !== 'aadhaar-verification');
                          setSelectedUserForModules({
                            ...selectedUserForModules,
                            moduleAccess: newModuleAccess
                          });
                        }}
                        className="h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-300 rounded"
                      />
                      <span className="ml-2 text-sm text-gray-700">Aadhaar Verification</span>
                    </label>
                    
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={selectedUserForModules.moduleAccess.includes('selfie-upload')}
                        onChange={(e) => {
                          const newModuleAccess = e.target.checked
                            ? [...selectedUserForModules.moduleAccess, 'selfie-upload']
                            : selectedUserForModules.moduleAccess.filter(m => m !== 'selfie-upload');
                          setSelectedUserForModules({
                            ...selectedUserForModules,
                            moduleAccess: newModuleAccess
                          });
                        }}
                        className="h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-300 rounded"
                      />
                      <span className="ml-2 text-sm text-gray-700">Selfie Upload</span>
                    </label>
                    
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={selectedUserForModules.moduleAccess.includes('qr-code')}
                        onChange={(e) => {
                          const newModuleAccess = e.target.checked
                            ? [...selectedUserForModules.moduleAccess, 'qr-code']
                            : selectedUserForModules.moduleAccess.filter(m => m !== 'qr-code');
                          setSelectedUserForModules({
                            ...selectedUserForModules,
                            moduleAccess: newModuleAccess
                          });
                        }}
                        className="h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-300 rounded"
                      />
                      <span className="ml-2 text-sm text-gray-700">QR Code</span>
                    </label>
                  </div>
                </div>
                
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => {
                      setShowModuleAccess(false);
                      setSelectedUserForModules(null);
                    }}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleUpdateModuleAccess(selectedUserForModules._id, selectedUserForModules.moduleAccess)}
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-purple-600 hover:bg-purple-700"
                  >
                    Update Access
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Branding Management Modal */}
      {showBranding && selectedUserForBranding && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                Manage Branding for {selectedUserForBranding.name}
              </h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Company Name</label>
                  <input
                    type="text"
                    value={brandingForm.companyName || ''}
                    onChange={(e) => setBrandingForm({ ...brandingForm, companyName: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                    placeholder="Enter company name"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Display Name</label>
                  <input
                    type="text"
                    value={brandingForm.displayName || ''}
                    onChange={(e) => setBrandingForm({ ...brandingForm, displayName: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                    placeholder="Enter display name"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Address</label>
                  <textarea
                    value={brandingForm.address || ''}
                    onChange={(e) => setBrandingForm({ ...brandingForm, address: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                    placeholder="Enter company address"
                    rows={3}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">GST Number</label>
                  <input
                    type="text"
                    value={brandingForm.gstNumber || ''}
                    onChange={(e) => setBrandingForm({ ...brandingForm, gstNumber: e.target.value.toUpperCase() })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                    placeholder="Enter GST number (e.g., 22ABCDE1234F1Z5)"
                    maxLength={15}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Logo</label>
                  <div className="flex items-center space-x-3">
                    {selectedUserForBranding.branding?.logo && (
                      <img
                        src={`/api/admin/users/${selectedUserForBranding._id}/logo`}
                        alt="Current logo"
                        className="w-12 h-12 object-contain border border-gray-300 rounded"
                      />
                    )}
                    <input
                      type="file"
                      accept="image/*"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) {
                          setBrandingForm({ ...brandingForm, logoFile: file });
                        }
                      }}
                      className="flex-1 text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-purple-50 file:text-purple-700 hover:file:bg-purple-100"
                    />
                  </div>
                </div>
                
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => {
                      setShowBranding(false);
                      setSelectedUserForBranding(null);
                      setBrandingForm({ companyName: '', displayName: '', address: '', gstNumber: '', logoFile: null });
                    }}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleUpdateBranding(selectedUserForBranding._id)}
                    disabled={brandingLoading}
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 disabled:opacity-50"
                  >
                    {brandingLoading ? 'Updating...' : 'Update Branding'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* QR Code Modal */}
      {showQrCode && selectedUserForQrCode && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                QR Code for {selectedUserForQrCode.name}
              </h3>
              
              {qrCodeLoading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600"></div>
                </div>
              ) : qrCodeData ? (
                <div className="space-y-4">
                  <div className="flex justify-center">
                    <img 
                      src={qrCodeData.qrCode} 
                      alt="QR Code" 
                      className="w-64 h-64 border-4 border-gray-200 rounded-lg p-4 bg-white"
                    />
                  </div>
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <p className="text-xs text-gray-600 mb-1">QR Code URL:</p>
                    <p className="text-xs font-mono text-gray-800 break-all">{qrCodeData.qrCodeUrl}</p>
                  </div>
                  <div className="flex space-x-3 pt-4">
                    <button
                      type="button"
                      onClick={() => {
                        setShowQrCode(false);
                        setSelectedUserForQrCode(null);
                        setQrCodeData(null);
                      }}
                      className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                    >
                      Close
                    </button>
                    <button
                      onClick={handleDownloadQrCode}
                      className="flex-1 px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-purple-600 hover:bg-purple-700"
                    >
                      Download
                    </button>
                    <button
                      onClick={() => handleViewQrCode(selectedUserForQrCode, true)}
                      className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                    >
                      Regenerate
                    </button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <p className="text-gray-600">Failed to load QR code</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Data Archival Tab */}
      {activeTab === 'archival' && (
        <div className="space-y-6">
          {/* Archival Header */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-gradient-to-br from-orange-500 to-red-600 rounded-2xl flex items-center justify-center mr-4 shadow-lg">
                  <svg className="h-6 w-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                  </svg>
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-gray-900">Data Archival Management</h2>
                  <p className="text-gray-600">Manage user-wise data retention and archival processes</p>
                </div>
              </div>
              <button
                onClick={() => triggerArchivalProcess()}
                className="px-4 py-2 bg-gradient-to-r from-orange-500 to-red-600 text-white rounded-lg hover:from-orange-600 hover:to-red-700 transition-all duration-300 shadow-lg hover:shadow-xl"
              >
                Trigger Archival Process
              </button>
            </div>
          </div>

          {/* Archival Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-blue-100 rounded-2xl flex items-center justify-center mr-4">
                  <DocumentTextIcon className="h-6 w-6 text-blue-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Records</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {(archivalStats?.stats?.panKyc?.totalRecords || 0) + (archivalStats?.stats?.aadhaarPan?.totalRecords || 0)}
                  </p>
                </div>
              </div>
            </div>
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-yellow-100 rounded-2xl flex items-center justify-center mr-4">
                  <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Marked for Deletion</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {(archivalStats?.stats?.panKyc?.markedForDeletion || 0) + (archivalStats?.stats?.aadhaarPan?.markedForDeletion || 0)}
                  </p>
                </div>
              </div>
            </div>
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-green-100 rounded-2xl flex items-center justify-center mr-4">
                  <CheckCircleIcon className="h-6 w-6 text-green-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Warnings Sent</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {(archivalStats?.stats?.panKyc?.warningSent || 0) + (archivalStats?.stats?.aadhaarPan?.warningSent || 0)}
                  </p>
                </div>
              </div>
            </div>
            <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-red-100 rounded-2xl flex items-center justify-center mr-4">
                  <XCircleIcon className="h-6 w-6 text-red-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Deleted Records</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {(archivalStats?.stats?.panKyc?.deleted || 0) + (archivalStats?.stats?.aadhaarPan?.deleted || 0)}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* User Archival Management */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-gray-900">User Archival Settings</h3>
              <div className="flex space-x-2">
                <input
                  type="text"
                  placeholder="Search users..."
                  value={userSearchTerm}
                  onChange={(e) => setUserSearchTerm(e.target.value)}
                  className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                />
                <button
                  onClick={() => fetchUsersWithArchivalSettings()}
                  className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
                >
                  Refresh
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">PAN KYC Settings</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Aadhaar-PAN Settings</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {usersWithArchivalSettings?.map((user) => (
                    <tr key={user._id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <div className="text-sm font-medium text-gray-900">{user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'Unknown User'}</div>
                          <div className="text-sm text-gray-500">{user.email}</div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-900">
                          <div>Retention: {user.archivalSettings?.panKyc?.retentionPeriodDays || 'Default'} days</div>
                          <div>Warning: {user.archivalSettings?.panKyc?.warningPeriodDays || 'Default'} days</div>
                          <div className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            user.archivalSettings?.panKyc?.isEnabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                          }`}>
                            {user.archivalSettings?.panKyc?.isEnabled ? 'Enabled' : 'Disabled'}
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-900">
                          <div>Retention: {user.archivalSettings?.aadhaarPan?.retentionPeriodDays || 'Default'} days</div>
                          <div>Warning: {user.archivalSettings?.aadhaarPan?.warningPeriodDays || 'Default'} days</div>
                          <div className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            user.archivalSettings?.aadhaarPan?.isEnabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                          }`}>
                            {user.archivalSettings?.aadhaarPan?.isEnabled ? 'Enabled' : 'Disabled'}
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button
                          onClick={() => openUserArchivalModal(user)}
                          disabled={archivalLoading}
                          className="text-purple-600 hover:text-purple-900 mr-3 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {archivalLoading ? 'Loading...' : 'Configure'}
                        </button>
                        <button
                          onClick={() => viewUserArchivalRecords(user)}
                          disabled={archivalLoading}
                          className="text-blue-600 hover:text-blue-900 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {archivalLoading ? 'Loading...' : 'View Records'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* User Archival Configuration Modal */}
      {userArchivalModalOpen && selectedUserForArchival && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                Configure Archival Settings for {selectedUserForArchival.name || `${selectedUserForArchival.firstName || ''} ${selectedUserForArchival.lastName || ''}`.trim() || selectedUserForArchival.email || 'Unknown User'}
              </h3>
              
              <div className="space-y-6">
                {/* PAN KYC Settings */}
                <div className="border border-gray-200 rounded-lg p-4">
                  <h4 className="text-md font-semibold text-gray-800 mb-3">PAN KYC Settings</h4>
                  <div className="space-y-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Retention Period (days)</label>
                      <input
                        type="number"
                        min="1"
                        max="3650"
                        defaultValue={selectedUserForArchival.archivalSettings?.panKyc?.retentionPeriodDays || 365}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500"
                        placeholder="365"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Warning Period (days)</label>
                      <input
                        type="number"
                        min="1"
                        max="30"
                        defaultValue={selectedUserForArchival.archivalSettings?.panKyc?.warningPeriodDays || 7}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500"
                        placeholder="7"
                      />
                    </div>
                    <div className="flex items-center">
                      <input
                        type="checkbox"
                        defaultChecked={selectedUserForArchival.archivalSettings?.panKyc?.isEnabled !== false}
                        className="h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-300 rounded"
                      />
                      <label className="ml-2 text-sm text-gray-700">Enable archival for PAN KYC</label>
                    </div>
                  </div>
                </div>

                {/* Aadhaar-PAN Settings */}
                <div className="border border-gray-200 rounded-lg p-4">
                  <h4 className="text-md font-semibold text-gray-800 mb-3">Aadhaar-PAN Settings</h4>
                  <div className="space-y-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Retention Period (days)</label>
                      <input
                        type="number"
                        min="1"
                        max="3650"
                        defaultValue={selectedUserForArchival.archivalSettings?.aadhaarPan?.retentionPeriodDays || 365}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500"
                        placeholder="365"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Warning Period (days)</label>
                      <input
                        type="number"
                        min="1"
                        max="30"
                        defaultValue={selectedUserForArchival.archivalSettings?.aadhaarPan?.warningPeriodDays || 7}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500"
                        placeholder="7"
                      />
                    </div>
                    <div className="flex items-center">
                      <input
                        type="checkbox"
                        defaultChecked={selectedUserForArchival.archivalSettings?.aadhaarPan?.isEnabled !== false}
                        className="h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-300 rounded"
                      />
                      <label className="ml-2 text-sm text-gray-700">Enable archival for Aadhaar-PAN</label>
                    </div>
                  </div>
                </div>
                
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => {
                      setUserArchivalModalOpen(false);
                      setSelectedUserForArchival(null);
                    }}
                    className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => {
                      const confirmed = window.confirm(
                        'Are you sure you want to save these archival settings?\n\n' +
                        'This will update the retention and warning periods for this user.'
                      );
                      
                      if (confirmed) {
                        // TODO: Implement save functionality
                        alert('Save functionality will be implemented');
                        setUserArchivalModalOpen(false);
                        setSelectedUserForArchival(null);
                      }
                    }}
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-purple-600 hover:bg-purple-700"
                  >
                    Save Settings
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Custom Fields Tab */}
      {activeTab === 'customFields' && (
        <CustomFieldsManager />
      )}
    </div>
  );
};

export default Admin;

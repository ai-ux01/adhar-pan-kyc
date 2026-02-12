import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../contexts/ToastContext';
import api from '../../services/api';
import {
  DocumentTextIcon,
  UserGroupIcon,
  CheckCircleIcon,
  ChartBarIcon,
  ArrowUpIcon,
  ArrowDownIcon,
  ClockIcon,
  DocumentMagnifyingGlassIcon,
  UserIcon,
  ShieldCheckIcon,
  IdentificationIcon
} from '@heroicons/react/24/outline';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

interface Stats {
  totalRecords: number;
  panKycRecords: number;
  aadhaarPanRecords: number;
  aadhaarVerificationRecords: number;
  verifiedRecords: number;
  panKyc: {
    total: number;
    verified: number;
    pending: number;
    failed: number;
  };
  aadhaarPan: {
    total: number;
    linked: number;
    notLinked: number;
    pending: number;
  };
  aadhaarVerification: {
    total: number;
    verified: number;
    rejected: number;
    pending: number;
    error: number;
  };
  recentActivity: Array<{
    _id: string;
    batchId: string;
    status: string;
    module: string;
    type: string;
    createdAt: string;
    displayName?: string;
    identifier?: string;
    lastActivity?: string;
    activityType?: string;
  }>;
}

const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [stats, setStats] = useState<Stats>({
    totalRecords: 0,
    panKycRecords: 0,
    aadhaarPanRecords: 0,
    aadhaarVerificationRecords: 0,
    verifiedRecords: 0,
    panKyc: {
      total: 0,
      verified: 0,
      pending: 0,
      failed: 0
    },
    aadhaarPan: {
      total: 0,
      linked: 0,
      notLinked: 0,
      pending: 0
    },
    aadhaarVerification: {
      total: 0,
      verified: 0,
      rejected: 0,
      pending: 0,
      error: 0
    },
    recentActivity: []
  });
  const [loading, setLoading] = useState(true);
  const [animateStats, setAnimateStats] = useState(false);
  const [activityLoading, setActivityLoading] = useState(false);
  const [qrCodeData, setQrCodeData] = useState<{ qrCode: string; qrCodeUrl: string; qrCodeString: string } | null>(null);
  const [qrCodeLoading, setQrCodeLoading] = useState(false);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        setLoading(true);
        
        // Fetch real stats from API
        const response = await api.get('/dashboard/stats');
        
        if (response.data.success) {
          setStats(response.data.data);
          
          // Trigger animation after data loads
          setTimeout(() => setAnimateStats(true), 300);
        } else {
          throw new Error('Failed to fetch stats');
        }
      } catch (error: any) {
        console.error('Error fetching stats:', error);
        
        // Show error toast
        showToast({
          message: 'Failed to load dashboard statistics',
          type: 'error'
        });
        
        // Fallback to dummy data for demonstration
        const panKycRecords = 0;
        const aadhaarPanRecords = 0;
        const aadhaarVerificationRecords = 0;
        const fallbackStats = {
          totalRecords: panKycRecords + aadhaarPanRecords + aadhaarVerificationRecords,
          panKycRecords: panKycRecords,
          aadhaarPanRecords: aadhaarPanRecords,
          aadhaarVerificationRecords: aadhaarVerificationRecords,
          verifiedRecords: 0,
          panKyc: {
            total: 0,
            verified: 0,
            pending: 0,
            failed: 0
          },
          aadhaarPan: {
            total: 0,
            linked: 0,
            notLinked: 0,
            pending: 0
          },
          aadhaarVerification: {
            total: 0,
            verified: 0,
            rejected: 0,
            pending: 0,
            error: 0
          },
          recentActivity: []
        };
        
        setStats(fallbackStats);
      } finally {
        setLoading(false);
      }
    };

    if (user) {
      fetchStats();
    }
  }, [user, showToast]);

  // Function to fetch recent activity separately
  const fetchRecentActivity = async () => {
    try {
      setActivityLoading(true);
      const response = await api.get('/dashboard/recent-activity');
      
      if (response.data.success) {
        setStats(prevStats => ({
          ...prevStats,
          recentActivity: response.data.data
        }));
      }
    } catch (error: any) {
      console.error('Error fetching recent activity:', error);
    } finally {
      setActivityLoading(false);
    }
  };

  // Auto-refresh recent activity every 30 seconds
  useEffect(() => {
    if (!user) return;

    // Initial fetch
    fetchRecentActivity();

    // Set up interval for auto-refresh
    const interval = setInterval(() => {
      fetchRecentActivity();
    }, 30000); // 30 seconds

    return () => clearInterval(interval);
  }, [user]);

  // Fetch QR code if user has QR code module access
  useEffect(() => {
    const fetchQrCode = async () => {
      if (!user || !user.moduleAccess || !user.moduleAccess.includes('qr-code')) {
        return;
      }

      try {
        setQrCodeLoading(true);
        const response = await api.get('/users/qr-code');
        if (response.data.success) {
          setQrCodeData({
            qrCode: response.data.data.qrCode,
            qrCodeUrl: response.data.data.qrCodeUrl,
            qrCodeString: response.data.data.qrCodeString
          });
        }
      } catch (error: any) {
        console.error('Error fetching QR code:', error);
        // Don't show error toast as QR code might not be generated yet
      } finally {
        setQrCodeLoading(false);
      }
    };

    if (user) {
      fetchQrCode();
    }
  }, [user]);

  const handleDownloadQrCode = () => {
    if (!qrCodeData) return;
    
    const link = document.createElement('a');
    link.href = qrCodeData.qrCode;
    link.download = `qr-code-${user?.name || 'user'}.png`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    showToast({
      message: 'QR code downloaded successfully',
      type: 'success'
    });
  };

  const AnimatedNumber = ({ value, className }: { value: number; className?: string }) => (
    <span className={`transition-all duration-1000 ease-out ${className}`}>
      {value}
    </span>
  );

  // Chart data
  const totalRecordsData = [
    { name: 'PAN KYC', value: stats.panKycRecords, color: '#3b82f6' },
    { name: 'Aadhaar-PAN', value: stats.aadhaarPanRecords, color: '#10b981' }
  ];

  const panKycData = [
    { name: 'Total Records', value: stats.panKycRecords, color: '#3b82f6' }
  ];

  const aadhaarPanData = [
    { name: 'Total Records', value: stats.aadhaarPanRecords, color: '#10b981' }
  ];

  const aadhaarVerificationData = [
    { name: 'Total Records', value: stats.aadhaarVerificationRecords, color: '#8b5cf6' }
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 p-6">
        <div className="max-w-7xl mx-auto">
          {/* Skeleton Loading */}
          <div className="animate-pulse">
            <div className="h-12 bg-gray-200 rounded-3xl w-1/3 mb-8"></div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="bg-gray-200 rounded-3xl h-32"></div>
              ))}
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-gray-200 rounded-3xl h-64"></div>
              <div className="bg-gray-200 rounded-3xl h-64"></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header with staggered animation */}
        <div className="mb-8 animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
          <h1 className="text-3xl font-bold text-slate-800 tracking-tight drop-shadow-lg">
            Welcome back, {user?.branding?.displayName || user?.name || 'User'}! 👋
          </h1>
          <p className="mt-2 text-slate-600 font-medium">
            Here's what's happening with your AVIHR IDSYS today
          </p>
        </div>

        {/* Stats Cards with staggered animations - Module-wise */}
        <div className={`grid gap-6 mb-8 ${
          // For normal users, always display stats in one row
          user?.role !== 'admin' ? 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4' :
          // For admin users, use the original dynamic grid
          user?.moduleAccess?.length === 2 ? 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3' :
          user?.moduleAccess?.length === 1 ? 'grid-cols-1 md:grid-cols-2' :
          'grid-cols-1'
        }`}>
          {/* Total Records - Show only if user has access to any module or is admin */}
          {((user?.moduleAccess && user.moduleAccess.length > 0) || user?.role === 'admin') && (
            <div 
              className="bg-white/80 backdrop-blur-xl rounded-3xl p-6 shadow-xl border border-white/30 hover:shadow-2xl hover:scale-105 transition-all duration-300 ease-out cursor-pointer group animate-fade-in-up"
              style={{ animationDelay: '0.2s' }}
            >
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl group-hover:scale-110 transition-transform duration-300">
                  <DocumentTextIcon className="h-6 w-6 text-white" />
                </div>
                <div className="text-right">
                  <p className="text-xs font-medium text-slate-600">Total Records</p>
                  <AnimatedNumber 
                    value={stats.totalRecords} 
                    className="text-xl font-bold text-slate-900"
                  />
                </div>
              </div>
              {/* Pie Chart */}
              <div className="h-32 bg-gray-50 rounded-xl flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={totalRecordsData}
                      cx="50%"
                      cy="50%"
                      innerRadius={20}
                      outerRadius={40}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {totalRecordsData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              {/* Legend */}
              <div className="mt-3 space-y-1">
                {totalRecordsData.map((item) => (
                  <div key={item.name} className="flex items-center text-xs">
                    <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: item.color }}></div>
                    <span className="text-slate-600">{item.name}: {item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* PAN KYC Records - Show only for users with pan-kyc access */}
          {user?.moduleAccess?.includes('pan-kyc') && (
            <div 
              className="bg-white/80 backdrop-blur-xl rounded-3xl p-6 shadow-xl border border-white/30 hover:shadow-2xl hover:scale-105 transition-all duration-300 ease-out cursor-pointer group animate-fade-in-up"
              style={{ animationDelay: '0.3s' }}
            >
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-2xl group-hover:scale-110 transition-transform duration-300">
                  <DocumentMagnifyingGlassIcon className="h-6 w-6 text-white" />
                </div>
                <div className="text-right">
                  <p className="text-xs font-medium text-slate-600">PAN KYC Records</p>
                  <AnimatedNumber 
                    value={stats.panKycRecords} 
                    className="text-xl font-bold text-slate-900"
                  />
                </div>
              </div>
              {/* Pie Chart */}
              <div className="h-32 bg-gray-50 rounded-xl flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={panKycData}
                      cx="50%"
                      cy="50%"
                      innerRadius={20}
                      outerRadius={40}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {panKycData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              {/* Legend */}
              <div className="mt-3 space-y-1">
                {panKycData.map((item) => (
                  <div key={item.name} className="flex items-center text-xs">
                    <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: item.color }}></div>
                    <span className="text-slate-600">{item.name}: {item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Aadhaar-PAN Records - Show only for users with aadhaar-pan access */}
          {user?.moduleAccess?.includes('aadhaar-pan') && (
            <div 
              className="bg-white/80 backdrop-blur-xl rounded-3xl p-6 shadow-xl border border-white/30 hover:shadow-2xl hover:scale-105 transition-all duration-300 ease-out cursor-pointer group animate-fade-in-up"
              style={{ animationDelay: '0.4s' }}
            >
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-gradient-to-br from-orange-500 to-red-600 rounded-2xl group-hover:scale-110 transition-transform duration-300">
                  <UserIcon className="h-6 w-6 text-white" />
                </div>
                <div className="text-right">
                  <p className="text-xs font-medium text-slate-600">Aadhaar-PAN Records</p>
                  <AnimatedNumber 
                    value={stats.aadhaarPanRecords} 
                    className="text-xl font-bold text-slate-900"
                  />
                </div>
              </div>
              {/* Pie Chart */}
              <div className="h-32 bg-gray-50 rounded-xl flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={aadhaarPanData}
                      cx="50%"
                      cy="50%"
                      innerRadius={20}
                      outerRadius={40}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {aadhaarPanData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              {/* Legend */}
              <div className="mt-3 space-y-1">
                {aadhaarPanData.map((item) => (
                  <div key={item.name} className="flex items-center text-xs">
                    <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: item.color }}></div>
                    <span className="text-slate-600">{item.name}: {item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Aadhaar Verification Records - Show only for users with aadhaar-verification access */}
          {user?.moduleAccess?.includes('aadhaar-verification') && (
            <div 
              className="bg-white/80 backdrop-blur-xl rounded-3xl p-6 shadow-xl border border-white/30 hover:shadow-2xl hover:scale-105 transition-all duration-300 ease-out cursor-pointer group animate-fade-in-up"
              style={{ animationDelay: '0.5s' }}
            >
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl group-hover:scale-110 transition-transform duration-300">
                  <IdentificationIcon className="h-6 w-6 text-white" />
                </div>
                <div className="text-right">
                  <p className="text-xs font-medium text-slate-600">Aadhaar Verification</p>
                  <AnimatedNumber 
                    value={stats.aadhaarVerificationRecords} 
                    className="text-xl font-bold text-slate-900"
                  />
                </div>
              </div>
              {/* Pie Chart */}
              <div className="h-32 bg-gray-50 rounded-xl flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={aadhaarVerificationData}
                      cx="50%"
                      cy="50%"
                      innerRadius={20}
                      outerRadius={40}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {aadhaarVerificationData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              {/* Legend */}
              <div className="mt-3 space-y-1">
                {aadhaarVerificationData.map((item) => (
                  <div key={item.name} className="flex items-center text-xs">
                    <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: item.color }}></div>
                    <span className="text-slate-600">{item.name}: {item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* No Module Access Message */}
          {(!user?.moduleAccess || user.moduleAccess.length === 0) && user?.role !== 'admin' && (
            <div 
              className="bg-white/80 backdrop-blur-xl rounded-3xl p-8 shadow-xl border border-white/30 animate-fade-in-up col-span-full"
              style={{ animationDelay: '0.2s' }}
            >
              <div className="text-center">
                <div className="text-gray-400 mb-4">
                  <ChartBarIcon className="h-16 w-16 mx-auto mb-3 opacity-50" />
                </div>
                <h3 className="text-base font-semibold text-gray-700 mb-2">No Module Access</h3>
                <p className="text-gray-600 mb-4">You don't have access to any modules yet.</p>
                <p className="text-xs text-gray-500">Contact your administrator to get module permissions and start using the system.</p>
              </div>
            </div>
          )}
        </div>

        {/* Quick Actions and Recent Activity with staggered animations */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Quick Actions */}
          <div 
            className="bg-white/80 backdrop-blur-xl rounded-3xl p-6 shadow-xl border border-white/30 animate-fade-in-up"
            style={{ animationDelay: '0.5s' }}
          >
            <div className="flex items-center mb-6">
              <div className="p-2 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl mr-3">
                <ChartBarIcon className="h-5 w-5 text-white" />
              </div>
              <h2 className="text-xl font-semibold text-slate-800">Quick Actions</h2>
            </div>
            <div className="space-y-3">
              {/* PAN KYC Module Actions */}
              {user?.moduleAccess?.includes('pan-kyc') && (
                <>
                  <button 
                    onClick={() => window.location.href = '/pan-kyc'}
                    className="w-full p-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-2xl hover:from-blue-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-200 ease-out shadow-lg hover:shadow-xl flex items-center justify-center"
                  >
                    <DocumentTextIcon className="h-5 w-5 mr-2" />
                    Upload PAN KYC Document
                  </button>
                  <button 
                    onClick={() => window.location.href = '/pan-kyc'}
                    className="w-full p-3 bg-gradient-to-r from-indigo-500 to-blue-600 text-white rounded-2xl hover:from-indigo-600 hover:to-blue-700 transform hover:scale-105 transition-all duration-200 ease-out shadow-lg hover:shadow-xl flex items-center justify-center"
                  >
                    <DocumentMagnifyingGlassIcon className="h-5 w-5 mr-2" />
                    View PAN KYC Records
                  </button>
                </>
              )}

              {/* Aadhaar-PAN Module Actions */}
              {user?.moduleAccess?.includes('aadhaar-pan') && (
                <>
                  <button 
                    onClick={() => window.location.href = '/aadhaar-pan'}
                    className="w-full p-3 bg-gradient-to-r from-emerald-500 to-teal-600 text-white rounded-2xl hover:from-emerald-600 hover:to-teal-700 transform hover:scale-105 transition-all duration-200 ease-out shadow-lg hover:shadow-xl flex items-center justify-center"
                  >
                    <UserIcon className="h-5 w-5 mr-2" />
                    Upload Aadhaar-PAN Document
                  </button>
                  <button 
                    onClick={() => window.location.href = '/aadhaar-pan'}
                    className="w-full p-3 bg-gradient-to-r from-cyan-500 to-emerald-600 text-white rounded-2xl hover:from-cyan-600 hover:to-emerald-700 transform hover:scale-105 transition-all duration-200 ease-out shadow-lg hover:shadow-xl flex items-center justify-center"
                  >
                    <UserIcon className="h-5 w-5 mr-2" />
                    View Aadhaar-PAN Records
                  </button>
                </>
              )}

              {/* Aadhaar Verification Module Actions */}
              {user?.moduleAccess?.includes('aadhaar-verification') && (
                <>
                  <button 
                    onClick={() => window.location.href = '/aadhaar-verification'}
                    className="w-full p-3 bg-gradient-to-r from-purple-500 to-indigo-600 text-white rounded-2xl hover:from-purple-600 hover:to-indigo-700 transform hover:scale-105 transition-all duration-200 ease-out shadow-lg hover:shadow-xl flex items-center justify-center"
                  >
                    <IdentificationIcon className="h-5 w-5 mr-2" />
                    Verify Aadhaar
                  </button>
                  <button 
                    onClick={() => window.location.href = '/aadhaar-verification-records'}
                    className="w-full p-3 bg-gradient-to-r from-violet-500 to-purple-600 text-white rounded-2xl hover:from-violet-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-200 ease-out shadow-lg hover:shadow-xl flex items-center justify-center"
                  >
                    <IdentificationIcon className="h-5 w-5 mr-2" />
                    View Aadhaar Records
                  </button>
                </>
              )}

              {/* Admin Module Actions */}
              {user?.role === 'admin' && (
                <button 
                  onClick={() => window.location.href = '/admin'}
                  className="w-full p-3 bg-gradient-to-r from-purple-500 to-indigo-600 text-white rounded-2xl hover:from-purple-600 hover:to-indigo-700 transform hover:scale-105 transition-all duration-200 ease-out shadow-lg hover:shadow-xl flex items-center justify-center"
                >
                  <ShieldCheckIcon className="h-5 w-5 mr-2" />
                  Admin Panel
                </button>
              )}

              {/* No Module Access Message */}
              {(!user?.moduleAccess || user.moduleAccess.length === 0) && user?.role !== 'admin' && (
                <div className="text-center py-8">
                  <div className="text-gray-500 mb-2">
                    <UserGroupIcon className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  </div>
                  <p className="text-gray-600 font-medium">No module access granted</p>
                  <p className="text-xs text-gray-500 mt-1">Contact your administrator for module permissions</p>
                </div>
              )}
            </div>
          </div>

          {/* QR Code Section */}
          {user?.moduleAccess && user.moduleAccess.includes('qr-code') && (
            <div 
              className="bg-white/80 backdrop-blur-xl rounded-3xl p-6 shadow-xl border border-white/30 animate-fade-in-up"
              style={{ animationDelay: '0.55s' }}
            >
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center">
                  <div className="p-2 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl mr-3">
                    <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" />
                    </svg>
                  </div>
                  <h2 className="text-xl font-semibold text-slate-800">My QR Code</h2>
                </div>
              </div>
              
              {qrCodeLoading ? (
                <div className="flex items-center justify-center py-12">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
                </div>
              ) : qrCodeData ? (
                <div className="space-y-4">
                  <div className="flex justify-center bg-gray-50 p-4 rounded-2xl">
                    <img 
                      src={qrCodeData.qrCode} 
                      alt="QR Code" 
                      className="w-48 h-48 border-4 border-white rounded-lg shadow-lg"
                    />
                  </div>
                  <div className="bg-gradient-to-r from-indigo-50 to-purple-50 p-4 rounded-xl border border-indigo-100">
                    <p className="text-xs font-medium text-slate-600 mb-2">QR Code URL:</p>
                    <p className="text-xs font-mono text-slate-800 break-all bg-white p-2 rounded border border-indigo-200">
                      {qrCodeData.qrCodeUrl}
                    </p>
                  </div>
                  <div className="flex space-x-3">
                    <button
                      onClick={handleDownloadQrCode}
                      className="flex-1 bg-gradient-to-r from-indigo-500 to-purple-600 text-white font-semibold py-3 px-4 rounded-xl hover:from-indigo-600 hover:to-purple-700 transform hover:scale-105 transition-all duration-200 ease-out shadow-lg hover:shadow-xl flex items-center justify-center"
                    >
                      <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                      </svg>
                      Download QR Code
                    </button>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(qrCodeData.qrCodeUrl);
                        showToast({
                          message: 'QR Code URL copied to clipboard!',
                          type: 'success'
                        });
                      }}
                      className="flex-1 bg-white border-2 border-indigo-300 text-indigo-700 font-semibold py-3 px-4 rounded-xl hover:bg-indigo-50 transform hover:scale-105 transition-all duration-200 ease-out shadow-md hover:shadow-lg flex items-center justify-center"
                    >
                      <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                      Copy URL
                    </button>
                  </div>
                  <p className="text-xs text-center text-slate-500 mt-2">
                    Share this QR code for Aadhaar verification
                  </p>
                </div>
              ) : (
                <div className="text-center py-8">
                  <div className="text-gray-400 mb-3">
                    <svg className="h-12 w-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" />
                    </svg>
                  </div>
                  <p className="text-gray-600 font-medium mb-1">QR Code not generated</p>
                  <p className="text-xs text-gray-500">Contact your administrator to generate your QR code</p>
                </div>
              )}
            </div>
          )}

          {/* Recent Activity */}
          <div 
            className="bg-white/80 backdrop-blur-xl rounded-3xl p-6 shadow-xl border border-white/30 animate-fade-in-up"
            style={{ animationDelay: '0.6s' }}
          >
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center">
                <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-2xl mr-3">
                  <ClockIcon className="h-5 w-5 text-white" />
                </div>
                <h2 className="text-xl font-semibold text-slate-800">Recent Activity</h2>
              </div>
              <button
                onClick={fetchRecentActivity}
                disabled={activityLoading}
                className="p-2 bg-slate-100 hover:bg-slate-200 rounded-xl transition-colors duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                title="Refresh activity"
              >
                <svg 
                  className={`h-4 w-4 text-slate-600 ${activityLoading ? 'animate-spin' : ''}`} 
                  fill="none" 
                  viewBox="0 0 24 24" 
                  stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
            </div>
            <div className="space-y-4">
              {stats.recentActivity.length > 0 ? (
                stats.recentActivity.slice(0, 5).map((activity, index) => {
                  const getStatusColor = (status: string, module: string) => {
                    if (module === 'PAN KYC') {
                      switch (status) {
                        case 'verified':
                        case 'valid':
                          return 'from-green-50 to-emerald-50';
                        case 'pending':
                          return 'from-yellow-50 to-orange-50';
                        case 'failed':
                        case 'invalid':
                        case 'error':
                          return 'from-red-50 to-pink-50';
                        default:
                          return 'from-blue-50 to-purple-50';
                      }
                    } else {
                      switch (status) {
                        case 'linked':
                          return 'from-green-50 to-emerald-50';
                        case 'not-linked':
                          return 'from-red-50 to-pink-50';
                        case 'pending':
                          return 'from-yellow-50 to-orange-50';
                        default:
                          return 'from-blue-50 to-purple-50';
                      }
                    }
                  };

                  const getIconColor = (status: string, module: string) => {
                    if (module === 'PAN KYC') {
                      switch (status) {
                        case 'verified':
                        case 'valid':
                          return 'bg-green-500';
                        case 'pending':
                          return 'bg-yellow-500';
                        case 'failed':
                        case 'invalid':
                        case 'error':
                          return 'bg-red-500';
                        default:
                          return 'bg-blue-500';
                      }
                    } else {
                      switch (status) {
                        case 'linked':
                          return 'bg-green-500';
                        case 'not-linked':
                          return 'bg-red-500';
                        case 'pending':
                          return 'bg-yellow-500';
                        default:
                          return 'bg-blue-500';
                      }
                    }
                  };

                  const getStatusText = (activity: any) => {
                    const { status, module, displayName, identifier, activityType, batchId } = activity;
                    
                    // Clean up the display name - remove raw IDs and batch IDs
                    let cleanDisplayName = displayName || identifier || 'Document';
                    
                    // Remove batch ID patterns (format: xxxxxxxx:xxxxxxxx)
                    cleanDisplayName = cleanDisplayName.replace(/^[a-f0-9]{32}:[a-f0-9]{32}\s*/, '');
                    
                    // Remove raw ID patterns
                    cleanDisplayName = cleanDisplayName.replace(/^[a-f0-9]{24}:[a-f0-9]{32}\s*/, '');
                    
                    // If still empty or just IDs, use a generic name
                    if (!cleanDisplayName || cleanDisplayName.trim() === '' || /^[a-f0-9:]+$/.test(cleanDisplayName)) {
                      cleanDisplayName = module === 'PAN KYC' ? 'PAN Document' : 'Aadhaar-PAN Document';
                    }
                    
                    if (module === 'PAN KYC') {
                      switch (status) {
                        case 'verified':
                        case 'valid':
                          return `${cleanDisplayName} - PAN KYC verified successfully`;
                        case 'pending':
                          return `${cleanDisplayName} - PAN KYC verification pending`;
                        case 'failed':
                        case 'invalid':
                        case 'error':
                          return `${cleanDisplayName} - PAN KYC verification failed`;
                        default:
                          return `${cleanDisplayName} - PAN KYC document processed`;
                      }
                    } else {
                      switch (status) {
                        case 'linked':
                          return `${cleanDisplayName} - Aadhaar-PAN linked successfully`;
                        case 'not-linked':
                          return `${cleanDisplayName} - Aadhaar-PAN linking failed`;
                        case 'pending':
                          return `${cleanDisplayName} - Aadhaar-PAN linking pending`;
                        default:
                          return `${cleanDisplayName} - Aadhaar-PAN document processed`;
                      }
                    }
                  };

                  const formatTimeAgo = (dateString: string) => {
                    const now = new Date();
                    const date = new Date(dateString);
                    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);
                    
                    if (diffInSeconds < 60) return 'Just now';
                    
                    const diffInMinutes = Math.floor(diffInSeconds / 60);
                    if (diffInMinutes < 60) return `${diffInMinutes} minute${diffInMinutes > 1 ? 's' : ''} ago`;
                    
                    const diffInHours = Math.floor(diffInMinutes / 60);
                    if (diffInHours < 24) return `${diffInHours} hour${diffInHours > 1 ? 's' : ''} ago`;
                    
                    const diffInDays = Math.floor(diffInHours / 24);
                    if (diffInDays < 7) return `${diffInDays} day${diffInDays > 1 ? 's' : ''} ago`;
                    
                    const diffInWeeks = Math.floor(diffInDays / 7);
                    return `${diffInWeeks} week${diffInWeeks > 1 ? 's' : ''} ago`;
                  };

                  return (
                    <div 
                      key={activity._id}
                      className={`flex items-center p-3 bg-gradient-to-r ${getStatusColor(activity.status, activity.module)} rounded-2xl hover:bg-gradient-to-r hover:from-opacity-80 hover:to-opacity-80 transition-all duration-200 ease-out cursor-pointer group`}
                    >
                      <div className={`p-2 ${getIconColor(activity.status, activity.module)} rounded-2xl mr-3 group-hover:scale-110 transition-transform duration-200`}>
                        {activity.module === 'PAN KYC' ? (
                          <DocumentTextIcon className="h-4 w-4 text-white" />
                        ) : (
                          <UserIcon className="h-4 w-4 text-white" />
                        )}
                      </div>
                      <div className="flex-1">
                        <p className="text-xs font-medium text-slate-800">
                          {getStatusText(activity)}
                        </p>
                        <p className="text-xs text-slate-500">
                          {formatTimeAgo(activity.lastActivity || activity.createdAt)}
                        </p>
                        {activity.identifier && (
                          <p className="text-xs text-slate-400 mt-1">
                            ID: {activity.identifier.length > 20 ? 
                              `${activity.identifier.substring(0, 8)}...${activity.identifier.substring(activity.identifier.length - 8)}` : 
                              activity.identifier
                            }
                          </p>
                        )}
                      </div>
                      <div className={`w-2 h-2 ${getIconColor(activity.status, activity.module)} rounded-full animate-pulse`}></div>
                    </div>
                  );
                })
              ) : (
                <div className="text-center py-8">
                  <div className="p-3 bg-gray-100 rounded-2xl inline-block mb-3">
                    <ClockIcon className="h-6 w-6 text-gray-400" />
                  </div>
                  <p className="text-xs text-gray-500">No recent activity</p>
                  <p className="text-xs text-gray-400 mt-1">Upload documents to see activity here</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

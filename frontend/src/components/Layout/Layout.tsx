import React, { useState, useMemo, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import {
  Bars3Icon,
  XMarkIcon,
  DocumentTextIcon,
  IdentificationIcon,
  Cog6ToothIcon,
  ChevronDownIcon,
  UserCircleIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const { user, logout } = useAuth();
  const location = useLocation();
  const profileDropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (profileDropdownRef.current && !profileDropdownRef.current.contains(event.target as Node)) {
        setProfileDropdownOpen(false);
      }
    };

    if (profileDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [profileDropdownOpen]);



  // Memoize the logo URL to avoid unnecessary re-renders
  const logoUrl = useMemo(() => {
    if (user?.branding?.logo && user?._id) {
      // Determine API base URL - same logic as api.ts
      const getApiBaseURL = () => {
        if (process.env.REACT_APP_API_URL) {
          return process.env.REACT_APP_API_URL;
        }
        const isProduction = window.location.hostname !== 'localhost' && 
                             window.location.hostname !== '127.0.0.1' &&
                             !window.location.hostname.startsWith('192.168.');
        return isProduction ? 'https://adhar-pan-kyc-1.onrender.com/api' : 'http://localhost:3002/api';
      };
      const baseUrl = getApiBaseURL();
      // Use the API endpoint to serve the logo - this ensures proper path resolution and fallback handling
      const url = `${baseUrl.replace('/api', '')}/api/admin/users/${user._id}/logo`;
      // Add cache busting parameter based on logo filename to ensure fresh image loads
      const cacheBuster = user.branding.logo.filename ? `?v=${user.branding.logo.filename}` : '';
      return `${url}${cacheBuster}`;
    }
    return null;
  }, [user?.branding?.logo, user?._id]);



  const navigation = [
    ...(user?.role !== 'admin' ? [{
      name: 'Dashboard',
      href: '/dashboard',
      icon: ChartBarIcon,
      current: location.pathname === '/dashboard',
    }] : []),
    {
      name: 'PAN KYC',
      href: '/pan-kyc',
      icon: DocumentTextIcon,
      current: location.pathname === '/pan-kyc',
      module: 'pan-kyc',
    },
    {
      name: 'Aadhaar-PAN',
      href: '/aadhaar-pan',
      icon: IdentificationIcon,
      current: location.pathname === '/aadhaar-pan',
      module: 'aadhaar-pan',
    },
    {
      name: 'Aadhaar Verification',
      href: '/aadhaar-verification',
      icon: IdentificationIcon,
      current: location.pathname.startsWith('/aadhaar-verification'),
      module: 'aadhaar-verification',
    },
    ...(user?.role === 'admin' ? [{
      name: 'Admin',
      href: '/admin',
      icon: Cog6ToothIcon,
      current: location.pathname === '/admin',
    }] : []),
  ];

  const filteredNavigation = navigation.filter(item => {
    if (item.module) {
      return user?.moduleAccess?.includes(item.module);
    }
    return true;
  });

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50">
      {/* Sidebar for mobile */}
      <div className={`fixed inset-0 z-50 lg:hidden ${sidebarOpen ? 'block' : 'hidden'}`}>
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setSidebarOpen(false)} />
        <div className="fixed inset-y-0 left-0 flex w-64 flex-col bg-white/95 backdrop-blur-xl shadow-2xl border-r border-white/30 relative overflow-hidden">
          {/* Enhanced Background Pattern */}
          <div className="absolute inset-0 bg-gradient-to-br from-emerald-50/30 via-teal-50/30 to-cyan-50/30"></div>
          <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-200/20 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-40 h-40 bg-teal-200/20 rounded-full blur-3xl"></div>
          
          <div className="relative z-10">
            {/* Enhanced Header */}
            <div className="flex flex-col items-center justify-center h-48 px-4 bg-gradient-to-r from-emerald-500/20 via-teal-500/20 to-cyan-500/20 border-b border-white/30 relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-white/10 to-transparent"></div>
              <div className="relative z-10 flex flex-col items-center">
                {logoUrl ? (
                  <div className="relative group">
                    <img
                      src={logoUrl}
                      alt="Company Logo"
                      className="h-20 w-20 object-contain rounded-3xl shadow-2xl mb-3 border-2 border-white/40 transition-all duration-300 group-hover:scale-105 group-hover:shadow-3xl"
                      onError={(e) => {
                        console.error('Failed to load logo:', logoUrl);
                        const target = e.target as HTMLImageElement;
                        target.style.display = 'none';
                      }}
                    />
                    <div className="absolute inset-0 rounded-3xl bg-gradient-to-br from-emerald-400/20 to-teal-400/20 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  </div>
                ) : (
                  <div className="h-20 w-20 bg-gradient-to-br from-emerald-500 via-teal-600 to-cyan-700 rounded-3xl flex items-center justify-center shadow-2xl mb-3 border-2 border-white/40 relative overflow-hidden group hover:scale-105 transition-all duration-300">
                    <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent"></div>
                    <span className="text-white font-bold text-3xl relative z-10">K</span>
                    <div className="absolute inset-0 bg-gradient-to-br from-emerald-400/20 to-teal-400/20 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  </div>
                )}
                <span className="text-sm font-semibold bg-gradient-to-r from-emerald-800 via-teal-700 to-cyan-600 bg-clip-text text-transparent text-center">
                  {user?.branding?.displayName || user?.branding?.companyName || 'KYC System'}
                </span>
              </div>
              <button
                onClick={() => setSidebarOpen(false)}
                className="absolute top-3 right-3 text-slate-500 hover:text-slate-700 p-2 rounded-2xl hover:bg-white/60 hover:shadow-lg transition-all duration-300"
              >
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>
            
            {/* Enhanced Navigation */}
            <nav className="flex-1 space-y-3 px-4 py-6">
              {filteredNavigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`group flex items-center px-4 py-3 text-sm font-medium rounded-2xl transition-all duration-300 transform hover:scale-105 ${
                    item.current
                      ? 'bg-gradient-to-r from-emerald-500/20 via-teal-500/20 to-cyan-500/20 text-emerald-700 shadow-xl border border-emerald-200/50'
                      : 'text-slate-600 hover:bg-white/80 hover:text-slate-800 hover:shadow-lg'
                  }`}
                  onClick={() => setSidebarOpen(false)}
                >
                  <div className={`p-2.5 rounded-xl mr-3 transition-all duration-300 ${
                    item.current 
                      ? 'bg-gradient-to-br from-emerald-500 to-teal-600 text-white shadow-lg' 
                      : 'bg-slate-100 text-slate-500 group-hover:bg-gradient-to-br group-hover:from-emerald-500 group-hover:to-teal-600 group-hover:text-white group-hover:shadow-lg'
                  }`}>
                    <item.icon className="h-5 w-5 flex-shrink-0" />
                  </div>
                  {item.name}
                </Link>
              ))}
            </nav>
            
            {/* Enhanced Mobile Profile Section */}
            <div className="border-t border-white/30 px-4 py-6 bg-gradient-to-r from-slate-50/60 to-emerald-50/60">
              <div className="flex items-center px-4 py-4 bg-white/80 rounded-2xl backdrop-blur-sm shadow-lg border border-white/40">
                <div className="h-12 w-12 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center shadow-lg">
                  <span className="text-white font-semibold text-lg">
                    {user?.name?.charAt(0).toUpperCase()}
                  </span>
                </div>
                <div className="ml-4">
                  <div className="text-sm font-semibold text-slate-800">{user?.name}</div>
                  <div className="text-xs text-slate-600">{user?.email}</div>
                </div>
              </div>
              <div className="mt-4 space-y-3">
                <Link
                  to="/profile"
                  className="flex items-center px-4 py-3 text-sm text-slate-600 hover:bg-white/80 hover:text-slate-800 rounded-2xl transition-all duration-300 hover:shadow-lg"
                  onClick={() => setSidebarOpen(false)}
                >
                  <UserCircleIcon className="mr-3 h-5 w-5 text-slate-400" />
                  Profile
                </Link>

                <button
                  onClick={() => {
                    logout();
                    setSidebarOpen(false);
                  }}
                  className="flex w-full items-center px-4 py-3 text-sm text-red-600 hover:bg-red-50/80 hover:text-red-800 rounded-2xl transition-all duration-300 hover:shadow-lg"
                >
                  <svg className="mr-3 h-5 w-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                  </svg>
                  Logout
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Static sidebar for desktop */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col">
        <div className="flex flex-col flex-grow bg-white/95 backdrop-blur-xl shadow-2xl border-r border-white/30 relative overflow-hidden">
          {/* Enhanced Background Pattern */}
          <div className="absolute inset-0 bg-gradient-to-br from-emerald-50/30 via-teal-50/30 to-cyan-50/30"></div>
          <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-200/20 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-40 h-40 bg-teal-200/20 rounded-full blur-3xl"></div>
          
          <div className="relative z-10">
            {/* Enhanced Header */}
            <div className="flex flex-col items-center justify-center h-48 px-4 bg-gradient-to-r from-emerald-500/20 via-teal-500/20 to-cyan-500/20 border-b border-white/30 relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-white/10 to-transparent"></div>
              <div className="relative z-10 flex flex-col items-center">
                {logoUrl ? (
                  <div className="relative group">
                    <img
                      src={logoUrl}
                      alt="Company Logo"
                      className="h-20 w-20 object-contain rounded-3xl shadow-2xl mb-3 border-2 border-white/40 transition-all duration-300 group-hover:scale-105 group-hover:shadow-3xl"
                      onError={(e) => {
                        console.error('Failed to load logo:', logoUrl);
                        const target = e.target as HTMLImageElement;
                        target.style.display = 'none';
                      }}
                    />
                    <div className="absolute inset-0 rounded-3xl bg-gradient-to-br from-emerald-400/20 to-teal-400/20 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  </div>
                ) : (
                  <div className="h-20 w-20 bg-gradient-to-br from-emerald-500 via-teal-600 to-cyan-700 rounded-3xl flex items-center justify-center shadow-2xl mb-3 border-2 border-white/40 relative overflow-hidden group hover:scale-105 transition-all duration-300">
                    <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent"></div>
                    <span className="text-white font-bold text-3xl relative z-10">K</span>
                    <div className="absolute inset-0 rounded-3xl bg-gradient-to-br from-emerald-400/20 to-teal-400/20 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  </div>
                )}
                <div className="text-center">
                  <span className="text-sm font-semibold bg-gradient-to-r from-emerald-800 via-teal-700 to-cyan-600 bg-clip-text text-transparent">
                    {user?.branding?.displayName || user?.branding?.companyName || 'KYC System'}
                  </span>
                  {(() => {
                    console.log('🎨 Layout - user.branding:', user?.branding);
                    console.log('🎨 Layout - address:', (user?.branding as any)?.address);
                    console.log('🎨 Layout - gstNumber:', (user?.branding as any)?.gstNumber);
                    return ((user?.branding as any)?.address || (user?.branding as any)?.gstNumber);
                  })() && (
                    <div className="mt-2 space-y-1">
                      {(user?.branding as any)?.address && (
                        <p className="text-xs text-emerald-700/80 leading-tight">
                          {(user?.branding as any).address}
                        </p>
                      )}
                      {(user?.branding as any)?.gstNumber && (
                        <p className="text-xs text-emerald-700/80 font-mono">
                          GST: {(user?.branding as any).gstNumber}
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
            
            {/* Enhanced Navigation */}
            <nav className="flex-1 space-y-3 px-4 py-6">
              {filteredNavigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`group flex items-center px-4 py-3 text-sm font-medium rounded-2xl transition-all duration-300 transform hover:scale-105 ${
                    item.current
                      ? 'bg-gradient-to-r from-emerald-500/20 via-teal-500/20 to-cyan-500/20 text-emerald-700 shadow-xl border border-emerald-200/50'
                      : 'text-slate-600 hover:bg-white/80 hover:text-slate-800 hover:shadow-lg'
                  }`}
                >
                  <div className={`p-2.5 rounded-xl mr-3 transition-all duration-300 ${
                    item.current 
                      ? 'bg-gradient-to-br from-emerald-500 to-teal-600 text-white shadow-lg' 
                      : 'bg-slate-100 text-slate-500 group-hover:bg-gradient-to-br group-hover:from-emerald-500 group-hover:to-teal-600 group-hover:text-white group-hover:shadow-lg'
                  }`}>
                    <item.icon className="h-5 w-5 flex-shrink-0" />
                  </div>
                  {item.name}
                </Link>
              ))}
            </nav>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Enhanced Top bar */}
        <div className="z-40 flex h-16 shrink-0 items-center gap-x-4 border-b border-white/30 bg-white/90 backdrop-blur-xl px-4 shadow-xl sm:gap-x-6 sm:px-6 lg:px-8 relative overflow-visible">
          {/* Enhanced Background Pattern */}
          <div className="absolute inset-0 bg-gradient-to-r from-emerald-50/40 via-teal-50/40 to-cyan-50/40"></div>
          <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-200/20 rounded-full blur-2xl"></div>
          
          <div className="relative z-10 flex items-center w-full">
            <button
              type="button"
              className="-m-2.5 p-2.5 text-slate-700 hover:text-slate-900 hover:bg-white/60 rounded-2xl transition-all duration-300 lg:hidden hover:shadow-lg"
              onClick={() => setSidebarOpen(true)}
            >
              <span className="sr-only">Open sidebar</span>
              <Bars3Icon className="h-6 w-6" />
            </button>

            <div className="flex flex-1 gap-x-4 self-stretch lg:gap-x-6">
              <div className="flex flex-1"></div>
              <div className="flex items-center gap-x-4 lg:gap-x-6">

                {/* Enhanced Profile dropdown */}
                <div className="relative overflow-visible" ref={profileDropdownRef}>
                  <button
                    onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
                    className="flex items-center gap-x-3 p-2.5 rounded-2xl hover:bg-white/60 hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-emerald-500/50 transition-all duration-300"
                  >
                    <div className="h-9 w-9 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center shadow-lg">
                      <span className="text-white font-semibold text-sm">
                        {user?.name?.charAt(0).toUpperCase()}
                      </span>
                    </div>
                    <div className="hidden lg:block text-left">
                      <div className="text-sm font-semibold text-slate-900">{user?.name}</div>
                      <div className="text-xs text-slate-600">{user?.email}</div>
                      {user?.branding?.companyName && (
                        <div className="text-xs text-slate-500">{user.branding.companyName}</div>
                      )}
                    </div>
                    <ChevronDownIcon className="h-4 w-4 text-slate-500" />
                  </button>

                  {/* Simple Dropdown menu */}
                  {profileDropdownOpen && (
                    <div 
                      className="absolute right-0 mt-2 w-56 bg-white rounded-lg shadow-lg border border-gray-200 z-50"
                      style={{ 
                        display: 'block',
                        position: 'absolute',
                        top: '100%',
                        right: '0',
                        marginTop: '8px'
                      }}
                    >
                      <div className="py-1">
                        {/* Profile link - only show for non-admin users */}
                        {user?.role !== 'admin' && (
                          <Link
                            to="/profile"
                            className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 w-full text-left"
                            onClick={() => setProfileDropdownOpen(false)}
                          >
                            <div className="flex items-center">
                              <UserCircleIcon className="mr-3 h-5 w-5 text-gray-400" />
                              Profile
                            </div>
                          </Link>
                        )}
                        
                        {/* Logout button */}
                        <button
                          onClick={() => {
                            logout();
                            setProfileDropdownOpen(false);
                          }}
                          className="block w-full px-4 py-2 text-sm text-red-700 hover:bg-red-50 text-left"
                        >
                          <div className="flex items-center">
                            <svg className="mr-3 h-5 w-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                            </svg>
                            Logout
                          </div>
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="py-6">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            {children}
          </div>
        </main>

        {/* Footer */}
        <footer className="fixed bottom-4 right-4 z-50">
          <div className="bg-white/90 backdrop-blur-sm border border-gray-200/50 rounded-lg px-4 py-3 shadow-lg">
            <div className="flex items-center space-x-4">
              <p className="text-xs text-gray-600 font-medium">
                Powered by <span className="text-blue-600 font-semibold">@ AVIHR Software Pvt Ltd</span>
              </p>
              <div className="flex items-center space-x-3 text-xs">
                <a 
                  href="/terms-and-conditions" 
                  className="text-gray-500 hover:text-blue-600 transition-colors duration-200"
                >
                  Terms
                </a>
                <span className="text-gray-300">|</span>
                <a 
                  href="/privacy-policy" 
                  className="text-gray-500 hover:text-blue-600 transition-colors duration-200"
                >
                  Privacy
                </a>
              </div>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default Layout;

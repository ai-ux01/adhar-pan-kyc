import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { ToastProvider } from './contexts/ToastContext';

// Components
import Layout from './components/Layout/Layout';
import Login from './pages/Auth/Login';
import Register from './pages/Auth/Register';
import ForgotPassword from './pages/Auth/ForgotPassword';
import ResetPassword from './pages/Auth/ResetPassword';
import VerifyEmail from './pages/Auth/VerifyEmail';
import Dashboard from './pages/Dashboard/Dashboard';
import PanKyc from './pages/PanKyc/PanKyc';
import PanKycRecords from './pages/PanKyc/PanKycRecords';
import AadhaarPan from './pages/AadhaarPan/AadhaarPan';
import AadhaarPanRecords from './pages/AadhaarPan/AadhaarPanRecords';
import AadhaarVerification from './pages/AadhaarVerification/AadhaarVerification';
import AadhaarVerificationRecords from './pages/AadhaarVerification/AadhaarVerificationRecords';
import QrVerification from './pages/AadhaarVerification/QrVerification';
import ProfileWrapper from './pages/Profile/ProfileWrapper';
import Admin from './pages/Admin/Admin';
import TermsAndConditions from './pages/Legal/TermsAndConditions';
import PrivacyPolicy from './pages/Legal/PrivacyPolicy';

import NotFound from './pages/NotFound/NotFound';

// Protected Route Component
const ProtectedRoute: React.FC<{ children: React.ReactNode; requiredRole?: string }> = ({ 
  children, 
  requiredRole 
}) => {
  const { user, loading, isAuthenticated } = useAuth();

  console.log('🔒 ProtectedRoute state:', { user: !!user, loading, isAuthenticated });

  if (loading) {
    console.log('🔒 ProtectedRoute: Loading...');
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    console.log('🔒 ProtectedRoute: Not authenticated, redirecting to login');
    return <Navigate to="/login" replace />;
  }

  if (requiredRole && user.role !== requiredRole) {
    console.log('🔒 ProtectedRoute: Role mismatch, redirecting to dashboard');
    return <Navigate to="/dashboard" replace />;
  }

  console.log('🔒 ProtectedRoute: Access granted');
  return <>{children}</>;
};

// Module Access Route Component
const ModuleRoute: React.FC<{ 
  children: React.ReactNode; 
  module: string;
}> = ({ children, module }) => {
  const { user, isAuthenticated, loading } = useAuth();

  console.log('🔒 ModuleRoute state:', { user: !!user, loading, isAuthenticated, module });

  if (loading) {
    console.log('🔒 ModuleRoute: Loading...');
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    console.log('🔒 ModuleRoute: Not authenticated, redirecting to login');
    return <Navigate to="/login" replace />;
  }

  // Check if user has access to the specific module (including admin users)
  if (!user.moduleAccess || !user.moduleAccess.includes(module)) {
    console.log('🔒 ModuleRoute: Module access denied, redirecting to dashboard');
    return <Navigate to="/dashboard" replace />;
  }

  console.log('🔒 ModuleRoute: Access granted');
  return <>{children}</>;
};

// Main App Component
const AppContent: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50">
      <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password/:token" element={<ResetPassword />} />
          <Route path="/verify-email/:token" element={<VerifyEmail />} />
          
          {/* Legal Pages - Public Routes */}
          <Route path="/terms-and-conditions" element={<TermsAndConditions />} />
          <Route path="/privacy-policy" element={<PrivacyPolicy />} />
          
          {/* Public QR Code Verification Route */}
          <Route path="/verify/qr/:qrCode" element={<QrVerification />} />

          {/* Protected Routes */}
          <Route path="/" element={
            <ProtectedRoute>
              <Layout>
                <Dashboard />
              </Layout>
            </ProtectedRoute>
          } />

          <Route path="/dashboard" element={
            <ProtectedRoute>
              <Layout>
                <Dashboard />
              </Layout>
            </ProtectedRoute>
          } />

          <Route path="/pan-kyc" element={
            <ModuleRoute module="pan-kyc">
              <Layout>
                <PanKyc />
              </Layout>
            </ModuleRoute>
          } />

          <Route path="/pan-kyc-records" element={
            <ModuleRoute module="pan-kyc">
              <Layout>
                <PanKycRecords />
              </Layout>
            </ModuleRoute>
          } />

          <Route path="/aadhaar-pan" element={
            <ModuleRoute module="aadhaar-pan">
              <Layout>
                <AadhaarPan />
              </Layout>
            </ModuleRoute>
          } />

          <Route path="/aadhaar-pan-records" element={
            <ModuleRoute module="aadhaar-pan">
              <Layout>
                <AadhaarPanRecords />
              </Layout>
            </ModuleRoute>
          } />

          <Route path="/aadhaar-verification" element={
            <ModuleRoute module="aadhaar-verification">
              <Layout>
                <AadhaarVerification />
              </Layout>
            </ModuleRoute>
          } />

          <Route path="/aadhaar-verification-records" element={
            <ModuleRoute module="aadhaar-verification">
              <Layout>
                <AadhaarVerificationRecords />
              </Layout>
            </ModuleRoute>
          } />


          <Route path="/profile" element={
            <ProtectedRoute>
              <Layout>
                <ProfileWrapper />
              </Layout>
            </ProtectedRoute>
          } />

          <Route path="/admin" element={
            <ProtectedRoute requiredRole="admin">
              <Layout>
                <Admin />
              </Layout>
            </ProtectedRoute>
          } />

          {/* 404 Route */}
          <Route path="*" element={<NotFound />} />
        </Routes>


      </div>
  );
};

// Root App Component with Providers
const App: React.FC = () => {
  return (
    <Router>
      <ThemeProvider>
        <AuthProvider>
          <ToastProvider>
            <AppContent />
          </ToastProvider>
        </AuthProvider>
      </ThemeProvider>
    </Router>
  );
};

export default App;

import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { useAuth } from '../../contexts/AuthContext';
import { EyeIcon, EyeSlashIcon, LockClosedIcon, EnvelopeIcon, CheckCircleIcon, ShieldCheckIcon, DocumentCheckIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import logoImage from '../../logo.jpeg';

interface LoginFormData {
  email: string;
  password: string;
  rememberMe?: boolean;
}


const Login: React.FC = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const { login, isAuthenticated, user } = useAuth();

  // Redirect if already authenticated
  React.useEffect(() => {
    if (isAuthenticated && user) {
      window.location.href = '/dashboard';
    }
  }, [isAuthenticated, user]);

  const { register, handleSubmit, formState: { errors } } = useForm<LoginFormData>();

  const onSubmit = async (data: LoginFormData) => {
    // Basic validation
    if (!data.email || !data.password) {
      setError('Please fill in all required fields');
      return;
    }

    setIsLoading(true);
    setError(''); // Clear any previous errors
    try {
      await login(data.email, data.password, data.rememberMe || false);
    } catch (error: any) {
      console.error('Login error:', error);
      // Set user-friendly error message
      if (error.response?.status === 429) {
        setError('Too many login attempts. Please wait a few minutes before trying again.');
      } else if (error.response?.data?.message) {
        setError(error.response.data.message);
      } else if (error.message) {
        setError(error.message);
      } else {
        setError('Login failed. Please check your credentials and try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-950 via-indigo-950 to-black relative overflow-hidden">
      {/* Enhanced Cosmic Background Elements */}
      <div className="absolute inset-0 overflow-hidden">
        {/* Floating Stars */}
        <div className="absolute top-20 left-20 w-3 h-3 bg-white rounded-full animate-pulse opacity-80 shadow-lg shadow-white/50"></div>
        <div className="absolute top-40 right-32 w-2 h-2 bg-blue-300 rounded-full animate-pulse opacity-90 shadow-lg shadow-blue-300/50"></div>
        <div className="absolute bottom-32 left-32 w-2.5 h-2.5 bg-purple-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-purple-300/50"></div>
        <div className="absolute top-1/2 left-1/4 w-1.5 h-1.5 bg-cyan-300 rounded-full animate-pulse opacity-70 shadow-lg shadow-cyan-300/50"></div>
        <div className="absolute top-1/3 right-1/4 w-2 h-2 bg-pink-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-pink-300/50"></div>
        
        {/* Additional Cosmic Elements */}
        <div className="absolute top-1/4 left-1/3 w-1 h-1 bg-yellow-200 rounded-full animate-pulse opacity-60 shadow-lg shadow-yellow-200/50"></div>
        <div className="absolute bottom-1/4 right-1/3 w-1.5 h-1.5 bg-emerald-300 rounded-full animate-pulse opacity-70 shadow-lg shadow-emerald-300/50"></div>
        
        {/* Large Nebula Effect */}
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
      </div>
      
      {/* Centered Form */}
      <div className="min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12 relative z-10">
        <div className="max-w-md w-full space-y-8">
          {/* Enhanced Header */}
          <div className="text-center">
            <div className="mx-auto h-20 w-20 bg-gradient-to-br from-white to-white rounded-2xl flex items-center justify-center shadow-xl shadow-blue-500/30 overflow-hidden">
              <img 
                src={logoImage} 
                alt="DUMMY Logo" 
                className="w-full h-full object-contain p-2"
              />
            </div>
            
            {/* Product Name */}
            <h1 className="mt-6 text-3xl font-bold text-white drop-shadow-lg">
              AVIHR IDSYS
            </h1>
            
            {/* Feature Descriptions - Horizontal with Icons */}
            <div className="mt-6 grid grid-cols-2 gap-3 max-w-lg mx-auto">
              <div className="flex items-center space-x-2 bg-white/10 backdrop-blur-sm rounded-lg px-3 py-2 border border-white/20 hover:bg-white/20 hover:scale-105 transition-all duration-300 group">
                <CheckCircleIcon className="w-4 h-4 text-green-300 flex-shrink-0 group-hover:text-green-200 transition-colors duration-300" />
                <span className="text-xs text-purple-100 font-medium group-hover:text-white transition-colors duration-300">Real-Time PAN Verification</span>
              </div>
              <div className="flex items-center space-x-2 bg-white/10 backdrop-blur-sm rounded-lg px-3 py-2 border border-white/20 hover:bg-white/20 hover:scale-105 transition-all duration-300 group">
                <ShieldCheckIcon className="w-4 h-4 text-blue-300 flex-shrink-0 group-hover:text-blue-200 transition-colors duration-300" />
                <span className="text-xs text-purple-100 font-medium group-hover:text-white transition-colors duration-300">PAN-AADHAAR Link Status</span>
              </div>
              <div className="flex items-center space-x-2 bg-white/10 backdrop-blur-sm rounded-lg px-3 py-2 border border-white/20 hover:bg-white/20 hover:scale-105 transition-all duration-300 group">
                <DocumentCheckIcon className="w-4 h-4 text-yellow-300 flex-shrink-0 group-hover:text-yellow-200 transition-colors duration-300" />
                <span className="text-xs text-purple-100 font-medium group-hover:text-white transition-colors duration-300">Prevent Fraudulent Documents</span>
              </div>
              <div className="flex items-center space-x-2 bg-white/10 backdrop-blur-sm rounded-lg px-3 py-2 border border-white/20 hover:bg-white/20 hover:scale-105 transition-all duration-300 group">
                <ExclamationTriangleIcon className="w-4 h-4 text-red-300 flex-shrink-0 group-hover:text-red-200 transition-colors duration-300" />
                <span className="text-xs text-purple-100 font-medium group-hover:text-white transition-colors duration-300">Eliminate Incomplete Information</span>
              </div>
            </div>
            
            <p className="mt-4 text-lg text-purple-100 font-medium">
              Sign in to your account
            </p>
          </div>

          {/* Enhanced Form Container */}
          <div className="bg-white/95 backdrop-blur-2xl rounded-2xl p-6 shadow-xl shadow-purple-500/20 border border-white/50 transform hover:scale-[1.01] transition-all duration-500">
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              {/* Enhanced Email Field */}
              <div>
                <label htmlFor="email" className="block text-sm font-bold text-gray-700 mb-2">
                  Email address
                </label>
                <div className="relative group">
                  <EnvelopeIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 h-6 w-6 text-purple-500 transition-colors duration-300 group-focus-within:text-purple-600" />
                  <input
                    id="email"
                    type="email"
                    {...register('email')}
                    className="block w-full pl-10 pr-3 py-3 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/80 backdrop-blur-sm hover:bg-white/90"
                    placeholder="Enter your email"
                  />
                </div>
                {errors.email && (
                  <p className="text-sm text-red-600 mt-2 ml-1">{errors.email.message}</p>
                )}
              </div>

              {/* Enhanced Password Field */}
              <div>
                <label htmlFor="password" className="block text-sm font-bold text-gray-700 mb-3">
                  Password
                </label>
                <div className="relative group">
                  <LockClosedIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 h-6 w-6 text-purple-500 transition-colors duration-300 group-focus-within:text-purple-600" />
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    {...register('password')}
                    className="block w-full pl-12 pr-16 py-4 border-2 border-gray-200 rounded-2xl focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/80 backdrop-blur-sm hover:bg-white/90"
                    placeholder="Enter your password"
                  />
                  <button
                    type="button"
                    className="absolute right-4 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-purple-600 transition-colors duration-300 p-1 rounded-lg hover:bg-purple-50"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
                  </button>
                </div>
                {errors.password && (
                  <p className="text-sm text-red-600 mt-2 ml-1">{errors.password.message}</p>
                )}
              </div>

              {/* Error Message Display */}
              {error && (
                <div className="bg-red-50 border-2 border-red-200 rounded-2xl p-4">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                      </svg>
                    </div>
                    <div className="ml-3">
                      <p className="text-sm font-medium text-red-800">{error}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Enhanced Remember Me & Forgot Password */}
              <div className="flex items-center justify-between">
                <div className="flex items-center group">
                  <input
                    id="remember-me"
                    type="checkbox"
                    {...register('rememberMe')}
                    className="h-5 w-5 text-purple-600 focus:ring-4 focus:ring-purple-500/20 border-2 border-gray-300 rounded-xl transition-all duration-300 hover:border-purple-400"
                  />
                  <label htmlFor="remember-me" className="ml-3 block text-sm text-gray-700 font-medium group-hover:text-gray-900 transition-colors duration-300">
                    Remember me
                  </label>
                </div>
                <Link
                  to="/forgot-password"
                  className="text-sm text-purple-600 hover:text-purple-700 font-medium transition-colors duration-300 hover:underline"
                >
                  Forgot password?
                </Link>
              </div>

              {/* Magnificent Submit Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex justify-center py-4 px-6 border border-transparent rounded-2xl shadow-2xl shadow-purple-500/30 text-sm font-bold text-white bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:from-purple-700 hover:via-indigo-700 hover:to-cyan-700 focus:outline-none focus:ring-4 focus:ring-purple-500/30 disabled:opacity-50 transform hover:scale-[1.02] hover:shadow-3xl hover:shadow-purple-500/40 transition-all duration-300"
              >
                {isLoading ? (
                  <div className="flex items-center space-x-2">
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    <span>Signing in...</span>
                  </div>
                ) : (
                  'Sign in'
                )}
              </button>
            </form>
          </div>

          {/* Enhanced Footer */}
          <div className="text-center">
            <p className="text-sm text-purple-100 drop-shadow-lg">
              By signing in, you agree to our{' '}
              <a href="/terms-and-conditions" className="text-purple-200 hover:text-purple-100 font-medium transition-colors duration-300 hover:underline">
                Terms of Service
              </a>{' '}
              and{' '}
              <a href="/privacy-policy" className="text-purple-200 hover:text-purple-100 font-medium transition-colors duration-300 hover:underline">
                Privacy Policy
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;

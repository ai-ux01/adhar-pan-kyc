import React, { useState, useEffect } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { LockClosedIcon, SparklesIcon, EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import api from '../../services/api';

interface ResetPasswordFormData {
  password: string;
  confirmPassword: string;
}

const schema = yup.object({
  password: yup.string()
    .min(8, 'Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain at least one uppercase letter, one lowercase letter, and one number')
    .required('Password is required'),
  confirmPassword: yup.string()
    .oneOf([yup.ref('password')], 'Passwords must match')
    .required('Please confirm your password'),
}).required();

const ResetPassword: React.FC = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState<string>('');
  const [tokenValid, setTokenValid] = useState<boolean | null>(null);
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();

  const { register, handleSubmit, formState: { errors } } = useForm<ResetPasswordFormData>({
    resolver: yupResolver(schema)
  });

  // Validate token on component mount
  useEffect(() => {
    const validateToken = async () => {
      if (!token) {
        setTokenValid(false);
        return;
      }

      try {
        await api.get(`/auth/validate-reset-token/${token}`);
        setTokenValid(true);
      } catch (error) {
        console.error('Token validation failed:', error);
        setTokenValid(false);
      }
    };

    validateToken();
  }, [token]);

  const onSubmit = async (data: ResetPasswordFormData) => {
    if (!token) {
      setError('Invalid reset token');
      return;
    }

    setIsLoading(true);
    setError('');
    try {
      await api.post('/auth/reset-password', {
        token,
        password: data.password
      });
      setIsSuccess(true);
    } catch (error: any) {
      console.error('Reset password error:', error);
      if (error.response?.data?.message) {
        setError(error.response.data.message);
      } else if (error.message) {
        setError(error.message);
      } else {
        setError('Failed to reset password. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  if (tokenValid === null) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-950 via-indigo-950 to-black flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white mx-auto mb-4"></div>
          <p className="text-white">Validating reset token...</p>
        </div>
      </div>
    );
  }

  if (tokenValid === false) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-950 via-indigo-950 to-black relative overflow-hidden">
        {/* Enhanced Cosmic Background Elements */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-20 left-20 w-3 h-3 bg-white rounded-full animate-pulse opacity-80 shadow-lg shadow-white/50"></div>
          <div className="absolute top-40 right-32 w-2 h-2 bg-blue-300 rounded-full animate-pulse opacity-90 shadow-lg shadow-blue-300/50"></div>
          <div className="absolute bottom-32 left-32 w-2.5 h-2.5 bg-purple-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-purple-300/50"></div>
          <div className="absolute top-1/2 left-1/4 w-1.5 h-1.5 bg-cyan-300 rounded-full animate-pulse opacity-70 shadow-lg shadow-cyan-300/50"></div>
          <div className="absolute top-1/3 right-1/4 w-2 h-2 bg-pink-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-pink-300/50"></div>
          
          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
        </div>
        
        <div className="min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12 relative z-10">
          <div className="max-w-md w-full space-y-8">
            <div className="text-center">
              <div className="mx-auto h-24 w-24 bg-gradient-to-br from-red-500 via-pink-500 to-orange-400 rounded-[2rem] flex items-center justify-center shadow-2xl shadow-red-500/30">
                <SparklesIcon className="h-12 w-12 text-white drop-shadow-lg" />
              </div>
              <h2 className="mt-8 text-4xl font-black text-white tracking-tight drop-shadow-2xl">
                Invalid Token
              </h2>
              <p className="mt-4 text-lg text-purple-100 font-medium drop-shadow-lg">
                This password reset link is invalid or has expired
              </p>
            </div>

            <div className="bg-white/95 backdrop-blur-2xl rounded-[2rem] p-10 shadow-2xl shadow-red-500/20 border border-white/50">
              <div className="text-center space-y-6">
                <div className="bg-red-50 border-2 border-red-200 rounded-2xl p-6">
                  <div className="flex items-center justify-center mb-4">
                    <svg className="h-12 w-12 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                  </div>
                  <p className="text-sm font-medium text-red-800">
                    The password reset link you clicked is either invalid or has expired. 
                    Please request a new password reset link.
                  </p>
                </div>
                
                <div className="space-y-4">
                  <Link
                    to="/forgot-password"
                    className="w-full flex justify-center py-4 px-6 border border-transparent rounded-2xl shadow-2xl shadow-purple-500/30 text-sm font-bold text-white bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:from-purple-700 hover:via-indigo-700 hover:to-cyan-700 focus:outline-none focus:ring-4 focus:ring-purple-500/30 transform hover:scale-[1.02] hover:shadow-3xl hover:shadow-purple-500/40 transition-all duration-300"
                  >
                    Request New Reset Link
                  </Link>
                  
                  <Link
                    to="/login"
                    className="w-full text-sm text-purple-600 hover:text-purple-700 font-medium transition-colors duration-300 hover:underline"
                  >
                    Back to Login
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (isSuccess) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-950 via-indigo-950 to-black relative overflow-hidden">
        {/* Enhanced Cosmic Background Elements */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-20 left-20 w-3 h-3 bg-white rounded-full animate-pulse opacity-80 shadow-lg shadow-white/50"></div>
          <div className="absolute top-40 right-32 w-2 h-2 bg-blue-300 rounded-full animate-pulse opacity-90 shadow-lg shadow-blue-300/50"></div>
          <div className="absolute bottom-32 left-32 w-2.5 h-2.5 bg-purple-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-purple-300/50"></div>
          <div className="absolute top-1/2 left-1/4 w-1.5 h-1.5 bg-cyan-300 rounded-full animate-pulse opacity-70 shadow-lg shadow-cyan-300/50"></div>
          <div className="absolute top-1/3 right-1/4 w-2 h-2 bg-pink-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-pink-300/50"></div>
          
          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
        </div>
        
        <div className="min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12 relative z-10">
          <div className="max-w-md w-full space-y-8">
            <div className="text-center">
              <div className="mx-auto h-24 w-24 bg-gradient-to-br from-green-500 via-emerald-500 to-teal-400 rounded-[2rem] flex items-center justify-center shadow-2xl shadow-green-500/30 transform hover:scale-110 transition-transform duration-300">
                <SparklesIcon className="h-12 w-12 text-white drop-shadow-lg" />
              </div>
              <h2 className="mt-8 text-4xl font-black text-white tracking-tight drop-shadow-2xl">
                Password Reset
              </h2>
              <p className="mt-4 text-lg text-purple-100 font-medium drop-shadow-lg">
                Your password has been successfully reset
              </p>
            </div>

            <div className="bg-white/95 backdrop-blur-2xl rounded-[2rem] p-10 shadow-2xl shadow-green-500/20 border border-white/50">
              <div className="text-center space-y-6">
                <div className="bg-green-50 border-2 border-green-200 rounded-2xl p-6">
                  <div className="flex items-center justify-center mb-4">
                    <svg className="h-12 w-12 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <p className="text-sm font-medium text-green-800">
                    Your password has been successfully updated. You can now sign in with your new password.
                  </p>
                </div>
                
                <Link
                  to="/login"
                  className="w-full flex justify-center py-4 px-6 border border-transparent rounded-2xl shadow-2xl shadow-purple-500/30 text-sm font-bold text-white bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:from-purple-700 hover:via-indigo-700 hover:to-cyan-700 focus:outline-none focus:ring-4 focus:ring-purple-500/30 transform hover:scale-[1.02] hover:shadow-3xl hover:shadow-purple-500/40 transition-all duration-300"
                >
                  Sign In Now
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-950 via-indigo-950 to-black relative overflow-hidden">
      {/* Enhanced Cosmic Background Elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-20 left-20 w-3 h-3 bg-white rounded-full animate-pulse opacity-80 shadow-lg shadow-white/50"></div>
        <div className="absolute top-40 right-32 w-2 h-2 bg-blue-300 rounded-full animate-pulse opacity-90 shadow-lg shadow-blue-300/50"></div>
        <div className="absolute bottom-32 left-32 w-2.5 h-2.5 bg-purple-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-purple-300/50"></div>
        <div className="absolute top-1/2 left-1/4 w-1.5 h-1.5 bg-cyan-300 rounded-full animate-pulse opacity-70 shadow-lg shadow-cyan-300/50"></div>
        <div className="absolute top-1/3 right-1/4 w-2 h-2 bg-pink-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-pink-300/50"></div>
        
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
      </div>
      
      <div className="min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12 relative z-10">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <div className="mx-auto h-24 w-24 bg-gradient-to-br from-purple-500 via-indigo-500 to-cyan-400 rounded-[2rem] flex items-center justify-center shadow-2xl shadow-purple-500/30 transform hover:scale-110 transition-transform duration-300">
              <SparklesIcon className="h-12 w-12 text-white drop-shadow-lg" />
            </div>
            <h2 className="mt-8 text-4xl font-black text-white tracking-tight drop-shadow-2xl">
              Reset Password
            </h2>
            <p className="mt-4 text-lg text-purple-100 font-medium drop-shadow-lg">
              Enter your new password below
            </p>
          </div>

          <div className="bg-white/95 backdrop-blur-2xl rounded-2xl p-6 shadow-xl shadow-purple-500/20 border border-white/50 transform hover:scale-[1.01] transition-all duration-500">
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              {/* New Password Field */}
              <div>
                <label htmlFor="password" className="block text-sm font-bold text-gray-700 mb-2">
                  New Password
                </label>
                <div className="relative group">
                  <LockClosedIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 h-6 w-6 text-purple-500 transition-colors duration-300 group-focus-within:text-purple-600" />
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    {...register('password')}
                    className="block w-full pl-12 pr-16 py-4 border-2 border-gray-200 rounded-2xl focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/80 backdrop-blur-sm hover:bg-white/90"
                    placeholder="Enter new password"
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

              {/* Confirm Password Field */}
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-bold text-gray-700 mb-2">
                  Confirm New Password
                </label>
                <div className="relative group">
                  <LockClosedIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 h-6 w-6 text-purple-500 transition-colors duration-300 group-focus-within:text-purple-600" />
                  <input
                    id="confirmPassword"
                    type={showConfirmPassword ? 'text' : 'password'}
                    {...register('confirmPassword')}
                    className="block w-full pl-12 pr-16 py-4 border-2 border-gray-200 rounded-2xl focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/80 backdrop-blur-sm hover:bg-white/90"
                    placeholder="Confirm new password"
                  />
                  <button
                    type="button"
                    className="absolute right-4 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-purple-600 transition-colors duration-300 p-1 rounded-lg hover:bg-purple-50"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  >
                    {showConfirmPassword ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
                  </button>
                </div>
                {errors.confirmPassword && (
                  <p className="text-sm text-red-600 mt-2 ml-1">{errors.confirmPassword.message}</p>
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

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex justify-center py-4 px-6 border border-transparent rounded-2xl shadow-2xl shadow-purple-500/30 text-sm font-bold text-white bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:from-purple-700 hover:via-indigo-700 hover:to-cyan-700 focus:outline-none focus:ring-4 focus:ring-purple-500/30 disabled:opacity-50 transform hover:scale-[1.02] hover:shadow-3xl hover:shadow-purple-500/40 transition-all duration-300"
              >
                {isLoading ? (
                  <div className="flex items-center space-x-2">
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    <span>Resetting password...</span>
                  </div>
                ) : (
                  'Reset Password'
                )}
              </button>
            </form>
          </div>

          <div className="text-center">
            <Link
              to="/login"
              className="text-sm text-purple-200 hover:text-purple-100 font-medium transition-colors duration-300 hover:underline"
            >
              Back to Login
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;
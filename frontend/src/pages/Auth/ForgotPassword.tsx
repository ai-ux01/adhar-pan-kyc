import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { EnvelopeIcon, SparklesIcon, ArrowLeftIcon } from '@heroicons/react/24/outline';
import api from '../../services/api';

interface ForgotPasswordFormData {
  email: string;
}

const schema = yup.object({
  email: yup.string().email('Please enter a valid email').required('Email is required'),
}).required();

const ForgotPassword: React.FC = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [error, setError] = useState<string>('');

  const { register, handleSubmit, formState: { errors } } = useForm<ForgotPasswordFormData>({
    resolver: yupResolver(schema)
  });

  const onSubmit = async (data: ForgotPasswordFormData) => {
    setIsLoading(true);
    setError('');
    try {
      await api.post('/auth/forgot-password', { email: data.email });
      setIsSubmitted(true);
    } catch (error: any) {
      console.error('Forgot password error:', error);
      if (error.response?.data?.message) {
        setError(error.response.data.message);
      } else if (error.message) {
        setError(error.message);
      } else {
        setError('Failed to send reset email. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  if (isSubmitted) {
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
          
          {/* Large Nebula Effect */}
          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
        </div>
        
        {/* Centered Content */}
        <div className="min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12 relative z-10">
          <div className="max-w-md w-full space-y-8">
            {/* Success Message */}
            <div className="text-center">
              <div className="mx-auto h-24 w-24 bg-gradient-to-br from-green-500 via-emerald-500 to-teal-400 rounded-[2rem] flex items-center justify-center shadow-2xl shadow-green-500/30 transform hover:scale-110 transition-transform duration-300">
                <SparklesIcon className="h-12 w-12 text-white drop-shadow-lg" />
              </div>
              <h2 className="mt-8 text-4xl font-black text-white tracking-tight drop-shadow-2xl">
                Check your email
              </h2>
              <p className="mt-4 text-lg text-purple-100 font-medium drop-shadow-lg">
                We've sent a password reset link to your email address
              </p>
            </div>

            {/* Success Container */}
            <div className="bg-white/95 backdrop-blur-2xl rounded-[2rem] p-10 shadow-2xl shadow-green-500/20 border border-white/50">
              <div className="text-center space-y-6">
                <div className="bg-green-50 border-2 border-green-200 rounded-2xl p-6">
                  <div className="flex items-center justify-center mb-4">
                    <svg className="h-12 w-12 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <p className="text-sm font-medium text-green-800">
                    Password reset instructions have been sent to your email address. 
                    Please check your inbox and follow the link to reset your password.
                  </p>
                </div>
                
                <div className="space-y-4">
                  <Link
                    to="/login"
                    className="w-full flex justify-center items-center py-4 px-6 border border-transparent rounded-2xl shadow-2xl shadow-purple-500/30 text-sm font-bold text-white bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:from-purple-700 hover:via-indigo-700 hover:to-cyan-700 focus:outline-none focus:ring-4 focus:ring-purple-500/30 transform hover:scale-[1.02] hover:shadow-3xl hover:shadow-purple-500/40 transition-all duration-300"
                  >
                    <ArrowLeftIcon className="h-5 w-5 mr-2" />
                    Back to Login
                  </Link>
                  
                  <button
                    onClick={() => setIsSubmitted(false)}
                    className="w-full text-sm text-purple-600 hover:text-purple-700 font-medium transition-colors duration-300 hover:underline"
                  >
                    Didn't receive the email? Try again
                  </button>
                </div>
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
        {/* Floating Stars */}
        <div className="absolute top-20 left-20 w-3 h-3 bg-white rounded-full animate-pulse opacity-80 shadow-lg shadow-white/50"></div>
        <div className="absolute top-40 right-32 w-2 h-2 bg-blue-300 rounded-full animate-pulse opacity-90 shadow-lg shadow-blue-300/50"></div>
        <div className="absolute bottom-32 left-32 w-2.5 h-2.5 bg-purple-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-purple-300/50"></div>
        <div className="absolute top-1/2 left-1/4 w-1.5 h-1.5 bg-cyan-300 rounded-full animate-pulse opacity-70 shadow-lg shadow-cyan-300/50"></div>
        <div className="absolute top-1/3 right-1/4 w-2 h-2 bg-pink-300 rounded-full animate-pulse opacity-80 shadow-lg shadow-pink-300/50"></div>
        
        {/* Large Nebula Effect */}
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
      </div>
      
      {/* Centered Form */}
      <div className="min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12 relative z-10">
        <div className="max-w-md w-full space-y-8">
          {/* Enhanced Header */}
          <div className="text-center">
            <div className="mx-auto h-24 w-24 bg-gradient-to-br from-purple-500 via-indigo-500 to-cyan-400 rounded-[2rem] flex items-center justify-center shadow-2xl shadow-purple-500/30 transform hover:scale-110 transition-transform duration-300">
              <SparklesIcon className="h-12 w-12 text-white drop-shadow-lg" />
            </div>
            <h2 className="mt-8 text-4xl font-black text-white tracking-tight drop-shadow-2xl">
              Forgot Password
            </h2>
            <p className="mt-4 text-lg text-purple-100 font-medium drop-shadow-lg">
              Enter your email address and we'll send you a reset link
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
                    className="block w-full pl-12 pr-4 py-4 border-2 border-gray-200 rounded-2xl focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/80 backdrop-blur-sm hover:bg-white/90"
                    placeholder="Enter your email"
                  />
                </div>
                {errors.email && (
                  <p className="text-sm text-red-600 mt-2 ml-1">{errors.email.message}</p>
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
                    <span>Sending reset link...</span>
                  </div>
                ) : (
                  'Send Reset Link'
                )}
              </button>
            </form>
          </div>

          {/* Enhanced Footer */}
          <div className="text-center space-y-4">
            <Link
              to="/login"
              className="inline-flex items-center text-sm text-purple-200 hover:text-purple-100 font-medium transition-colors duration-300 hover:underline"
            >
              <ArrowLeftIcon className="h-4 w-4 mr-2" />
              Back to Login
            </Link>
            
            <p className="text-sm text-purple-100 drop-shadow-lg">
              Remember your password?{' '}
              <Link to="/login" className="text-purple-200 hover:text-purple-100 font-medium transition-colors duration-300 hover:underline">
                Sign in here
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;
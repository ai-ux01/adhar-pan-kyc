import React, { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { usePartnerAuth } from '../../contexts/PartnerAuthContext';
import { EyeIcon, EyeSlashIcon, BuildingOffice2Icon } from '@heroicons/react/24/outline';

const PartnerLogin: React.FC = () => {
  const { login, isAuthenticated, loading } = usePartnerAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!loading && isAuthenticated) {
    return <Navigate to="/partner/dashboard" replace />;
  }

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError('');
    try {
      await login(email.trim(), password, rememberMe);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Login failed. Check your credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="mx-auto h-16 w-16 bg-indigo-500/20 border border-indigo-400/30 rounded-2xl flex items-center justify-center">
            <BuildingOffice2Icon className="h-8 w-8 text-indigo-300" />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-white">Partner Portal</h1>
          <p className="text-indigo-200/80 text-sm mt-2">Sign in to run Aadhaar verification APIs</p>
        </div>

        <form onSubmit={onSubmit} className="bg-white/10 backdrop-blur border border-white/10 rounded-2xl p-6 shadow-xl">
          {error && (
            <div className="mb-4 text-sm text-red-200 bg-red-500/20 border border-red-400/30 rounded-lg p-3">
              {error}
            </div>
          )}

          <label className="block text-sm text-indigo-100 mb-1">Portal email</label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full mb-4 px-3 py-2 rounded-lg bg-slate-950/50 border border-white/10 text-white"
            placeholder="partner@company.com"
          />

          <label className="block text-sm text-indigo-100 mb-1">Password</label>
          <div className="relative mb-4">
            <input
              type={showPassword ? 'text' : 'password'}
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 pr-10 rounded-lg bg-slate-950/50 border border-white/10 text-white"
              placeholder="••••••••"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-indigo-200"
            >
              {showPassword ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
            </button>
          </div>

          <label className="flex items-center gap-2 text-sm text-indigo-100 mb-6">
            <input
              type="checkbox"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              className="rounded"
            />
            Remember me
          </label>

          <button
            type="submit"
            disabled={isSubmitting || loading}
            className="w-full py-2.5 rounded-lg bg-indigo-500 hover:bg-indigo-400 text-white font-semibold disabled:opacity-50"
          >
            {isSubmitting ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <p className="text-center text-sm text-indigo-200/70 mt-6">
          Admin user?{' '}
          <Link to="/login" className="text-indigo-300 hover:text-white underline">
            Main app login
          </Link>
        </p>
      </div>
    </div>
  );
};

export default PartnerLogin;

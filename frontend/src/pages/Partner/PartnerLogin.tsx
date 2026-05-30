import React, { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { usePartnerAuth } from '../../contexts/PartnerAuthContext';
import { EyeIcon, EyeSlashIcon, BuildingOffice2Icon, KeyIcon } from '@heroicons/react/24/outline';

type LoginMode = 'portal' | 'apiKey';

const PartnerLogin: React.FC = () => {
  const { login, loginWithApiKey, isAuthenticated, loading } = usePartnerAuth();
  const [mode, setMode] = useState<LoginMode>('apiKey');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [showSecret, setShowSecret] = useState(false);
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
      if (mode === 'apiKey') {
        await loginWithApiKey(apiKey, rememberMe);
      } else {
        await login(email.trim(), password, rememberMe);
      }
    } catch (err: any) {
      setError(err.response?.data?.message || err.message || 'Login failed.');
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
          <h1 className="mt-4 text-2xl font-bold text-white">Partner Test Portal</h1>
          <p className="text-indigo-200/80 text-sm mt-2">Test the full Aadhaar API flow in the browser</p>
        </div>

        <div className="flex rounded-xl bg-white/10 p-1 mb-4 border border-white/10">
          <button
            type="button"
            onClick={() => setMode('apiKey')}
            className={`flex-1 py-2 text-sm font-medium rounded-lg transition-colors ${
              mode === 'apiKey' ? 'bg-indigo-500 text-white' : 'text-indigo-200 hover:text-white'
            }`}
          >
            API Key
          </button>
          <button
            type="button"
            onClick={() => setMode('portal')}
            className={`flex-1 py-2 text-sm font-medium rounded-lg transition-colors ${
              mode === 'portal' ? 'bg-indigo-500 text-white' : 'text-indigo-200 hover:text-white'
            }`}
          >
            Portal login
          </button>
        </div>

        <form onSubmit={onSubmit} className="bg-white/10 backdrop-blur border border-white/10 rounded-2xl p-6 shadow-xl">
          {error && (
            <div className="mb-4 text-sm text-red-200 bg-red-500/20 border border-red-400/30 rounded-lg p-3">
              {error}
            </div>
          )}

          {mode === 'apiKey' ? (
            <>
              <p className="text-xs text-indigo-200/80 mb-3">
                Paste the <strong>ak_live_...</strong> key from Admin → Partners → Create Tenant.
              </p>
              <label className="block text-sm text-indigo-100 mb-1">Partner API key</label>
              <div className="relative mb-4">
                <input
                  type={showSecret ? 'text' : 'password'}
                  required
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="w-full px-3 py-2 pr-10 rounded-lg bg-slate-950/50 border border-white/10 text-white font-mono text-sm"
                  placeholder="ak_live_tenant_..."
                  autoComplete="off"
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-indigo-200"
                >
                  {showSecret ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
                </button>
              </div>
            </>
          ) : (
            <>
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
                  type={showSecret ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2 pr-10 rounded-lg bg-slate-950/50 border border-white/10 text-white"
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-indigo-200"
                >
                  {showSecret ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
                </button>
              </div>
            </>
          )}

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
            className="w-full py-2.5 rounded-lg bg-indigo-500 hover:bg-indigo-400 text-white font-semibold disabled:opacity-50 inline-flex items-center justify-center gap-2"
          >
            {mode === 'apiKey' ? <KeyIcon className="h-5 w-5" /> : null}
            {isSubmitting ? 'Connecting...' : mode === 'apiKey' ? 'Connect with API key' : 'Sign in'}
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

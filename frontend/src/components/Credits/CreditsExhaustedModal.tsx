import React from 'react';
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline';

interface CreditsExhaustedModalProps {
  open: boolean;
  onClose: () => void;
}

const CreditsExhaustedModal: React.FC<CreditsExhaustedModalProps> = ({ open, onClose }) => {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl border border-amber-100">
        <div className="flex items-start gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-amber-100">
            <ExclamationTriangleIcon className="h-6 w-6 text-amber-600" />
          </div>
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-slate-900">Credits exhausted</h3>
            <p className="mt-2 text-sm text-slate-600 leading-relaxed">
              Your verification credits have run out. Please contact your admin to add more credits before continuing.
            </p>
          </div>
        </div>
        <div className="mt-6 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700 transition-colors"
          >
            OK
          </button>
        </div>
      </div>
    </div>
  );
};

export default CreditsExhaustedModal;

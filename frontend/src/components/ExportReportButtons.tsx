import React from 'react';
import { ArrowDownTrayIcon } from '@heroicons/react/24/outline';
import type { ReportExportFormat } from '../utils/exportReport';

interface ExportReportButtonsProps {
  exporting: boolean;
  onExport: (format: ReportExportFormat) => void;
  variant?: 'light' | 'dark';
  className?: string;
}

/**
 * CSV, Excel (.xls SpreadsheetML), and JSON export triggers.
 */
const ExportReportButtons: React.FC<ExportReportButtonsProps> = ({
  exporting,
  onExport,
  variant = 'light',
  className = ''
}) => {
  const base =
    variant === 'light'
      ? 'inline-flex items-center justify-center px-3 py-2 text-sm font-semibold rounded-xl border border-white/40 bg-white/15 hover:bg-white/25 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all'
      : 'inline-flex items-center justify-center px-3 py-2 text-sm font-semibold rounded-xl border border-gray-300 bg-white text-gray-800 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-all';

  return (
    <div className={`flex flex-wrap items-center gap-2 ${className}`}>
      <span className={`text-xs font-medium ${variant === 'light' ? 'text-white/80' : 'text-gray-600'} mr-1`}>
        Export:
      </span>
      <button type="button" disabled={exporting} className={base} onClick={() => onExport('csv')}>
        CSV
      </button>
      <button type="button" disabled={exporting} className={base} onClick={() => onExport('xls')}>
        Excel
      </button>
      <button type="button" disabled={exporting} className={base} onClick={() => onExport('json')}>
        JSON
      </button>
      {exporting && (
        <span className={`text-xs ${variant === 'light' ? 'text-white/90' : 'text-gray-600'} flex items-center gap-1`}>
          <ArrowDownTrayIcon className="h-4 w-4 animate-pulse" />
          Preparing…
        </span>
      )}
    </div>
  );
};

export default ExportReportButtons;

import React from 'react';

export type DateFilterPreset = 'all' | 'today' | 'week' | 'month';

export interface RecordDateRangeFiltersProps {
  dateFilter: string;
  onDateFilterChange: (value: DateFilterPreset) => void;
  dateFrom: string;
  dateTo: string;
  onDateFromChange: (value: string) => void;
  onDateToChange: (value: string) => void;
  onClear?: () => void;
  /** Tailwind focus ring color token, e.g. blue, emerald, indigo */
  accent?: 'blue' | 'emerald' | 'indigo';
  className?: string;
}

const accentRing: Record<NonNullable<RecordDateRangeFiltersProps['accent']>, string> = {
  blue: 'focus:ring-blue-500 focus:border-blue-500',
  emerald: 'focus:ring-emerald-500 focus:border-emerald-500',
  indigo: 'focus:ring-indigo-500 focus:border-indigo-500'
};

const RecordDateRangeFilters: React.FC<RecordDateRangeFiltersProps> = ({
  dateFilter,
  onDateFilterChange,
  dateFrom,
  dateTo,
  onDateFromChange,
  onDateToChange,
  onClear,
  accent = 'blue',
  className = ''
}) => {
  const ring = accentRing[accent];
  const inputClass = `w-full px-3 py-3 border border-gray-200 rounded-xl focus:ring-2 ${ring} transition-all duration-200 text-sm`;
  const hasCustomRange = Boolean(dateFrom || dateTo);

  const handlePresetChange = (value: string) => {
    onDateFilterChange(value as DateFilterPreset);
    if (value !== 'all') {
      onDateFromChange('');
      onDateToChange('');
    }
  };

  const handleFromChange = (value: string) => {
    onDateFromChange(value);
    if (value) onDateFilterChange('all');
  };

  const handleToChange = (value: string) => {
    onDateToChange(value);
    if (value) onDateFilterChange('all');
  };

  return (
    <div className={`flex flex-col sm:flex-row flex-wrap gap-3 ${className}`}>
      <div className="sm:w-40 min-w-[8rem]">
        <label className="block text-xs font-medium text-gray-600 mb-1">Period</label>
        <select
          value={dateFilter}
          onChange={(e) => handlePresetChange(e.target.value)}
          disabled={hasCustomRange}
          className={`${inputClass} disabled:bg-gray-50 disabled:text-gray-500`}
          title={hasCustomRange ? 'Clear custom dates to use quick period' : undefined}
        >
          <option value="all">All time</option>
          <option value="today">Today</option>
          <option value="week">This week</option>
          <option value="month">This month</option>
        </select>
      </div>
      <div className="sm:w-40 min-w-[8rem]">
        <label className="block text-xs font-medium text-gray-600 mb-1">From</label>
        <input
          type="date"
          value={dateFrom}
          onChange={(e) => handleFromChange(e.target.value)}
          max={dateTo || undefined}
          className={inputClass}
        />
      </div>
      <div className="sm:w-40 min-w-[8rem]">
        <label className="block text-xs font-medium text-gray-600 mb-1">To</label>
        <input
          type="date"
          value={dateTo}
          onChange={(e) => handleToChange(e.target.value)}
          min={dateFrom || undefined}
          className={inputClass}
        />
      </div>
      {(hasCustomRange || dateFilter !== 'all') && onClear && (
        <div className="flex items-end">
          <button
            type="button"
            onClick={onClear}
            className="px-4 py-3 text-sm font-medium text-gray-700 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors"
          >
            Clear dates
          </button>
        </div>
      )}
    </div>
  );
};

export default RecordDateRangeFilters;

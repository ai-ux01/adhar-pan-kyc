import React from 'react';

export type DateFilterPreset = 'all' | 'today' | 'week' | 'month';

export interface RecordDateRangeFiltersProps {
  dateFilter: string;
  dateFrom: string;
  dateTo: string;
  onChange: (values: { dateFilter: DateFilterPreset; dateFrom: string; dateTo: string }) => void;
  onClear?: () => void;
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
  dateFrom,
  dateTo,
  onChange,
  onClear,
  accent = 'blue',
  className = ''
}) => {
  const ring = accentRing[accent];
  const inputClass = `w-full min-w-0 px-3 py-2.5 border border-gray-200 rounded-xl focus:ring-2 ${ring} transition-all duration-200 text-sm`;
  const hasCustomRange = Boolean(dateFrom || dateTo);
  const showClear = (hasCustomRange || dateFilter !== 'all') && onClear;

  const handlePresetChange = (value: string) => {
    onChange({
      dateFilter: value as DateFilterPreset,
      dateFrom: '',
      dateTo: ''
    });
  };

  const handleFromChange = (value: string) => {
    onChange({
      dateFilter: 'all',
      dateFrom: value,
      dateTo: dateTo
    });
  };

  const handleToChange = (value: string) => {
    onChange({
      dateFilter: 'all',
      dateFrom: dateFrom,
      dateTo: value
    });
  };

  return (
    <div className={`flex flex-col gap-3 w-full ${className}`}>
      {/* Row 1: quick period */}
      <div className="w-full sm:max-w-[11rem]">
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

      {/* Row 2: custom date range */}
      <div
        className={`grid w-full gap-3 items-end ${
          showClear ? 'grid-cols-2 sm:grid-cols-3' : 'grid-cols-2'
        }`}
      >
        <div className="min-w-0">
          <label className="block text-xs font-medium text-gray-600 mb-1">From</label>
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => handleFromChange(e.target.value)}
            max={dateTo || undefined}
            className={inputClass}
          />
        </div>
        <div className="min-w-0">
          <label className="block text-xs font-medium text-gray-600 mb-1">To</label>
          <input
            type="date"
            value={dateTo}
            onChange={(e) => handleToChange(e.target.value)}
            min={dateFrom || undefined}
            className={inputClass}
          />
        </div>
        {showClear && (
          <div className="min-w-0 col-span-2 sm:col-span-1">
            <button
              type="button"
              onClick={onClear}
              className="w-full whitespace-nowrap px-3 py-2.5 text-sm font-medium text-gray-700 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors"
            >
              Clear dates
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default RecordDateRangeFilters;

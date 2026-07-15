/**
 * Apply createdAt filters from preset (today/week/month) or custom dateFrom/dateTo (YYYY-MM-DD).
 * Custom range takes precedence over preset when either date is set.
 */
function applyCreatedAtDateFilter(match, { dateFilter = 'all', dateFrom = '', dateTo = '', timezoneOffset = '0' } = {}) {
  const fromStr = String(dateFrom || '').trim();
  const toStr = String(dateTo || '').trim();
  const offsetMin = parseInt(timezoneOffset || '0', 10);

  if (fromStr || toStr) {
    match.createdAt = {};
    if (fromStr) {
      const parts = fromStr.split('-');
      if (parts.length === 3) {
        const year = parseInt(parts[0], 10);
        const month = parseInt(parts[1], 10) - 1;
        const day = parseInt(parts[2], 10);
        // Start of day in client local time
        const localFrom = new Date(Date.UTC(year, month, day, 0, 0, 0, 0));
        // Convert client local time to UTC: UTC = local + offset
        const fromUtc = new Date(localFrom.getTime() + (offsetMin * 60 * 1000));
        if (!Number.isNaN(fromUtc.getTime())) {
          match.createdAt.$gte = fromUtc;
        }
      }
    }
    if (toStr) {
      const parts = toStr.split('-');
      if (parts.length === 3) {
        const year = parseInt(parts[0], 10);
        const month = parseInt(parts[1], 10) - 1;
        const day = parseInt(parts[2], 10);
        // End of day in client local time
        const localTo = new Date(Date.UTC(year, month, day, 23, 59, 59, 999));
        // Convert to UTC
        const toUtc = new Date(localTo.getTime() + (offsetMin * 60 * 1000));
        if (!Number.isNaN(toUtc.getTime())) {
          match.createdAt.$lte = toUtc;
        }
      }
    }
    return match;
  }

  if (!dateFilter || dateFilter === 'all') {
    return match;
  }

  // Calculate client local now
  const nowUtc = new Date();
  const clientLocalNow = new Date(nowUtc.getTime() - (offsetMin * 60 * 1000));

  // Client local today start (00:00:00)
  const clientLocalTodayStart = new Date(clientLocalNow);
  clientLocalTodayStart.setUTCHours(0, 0, 0, 0);

  // Convert client local start back to UTC
  const startOfTodayUtc = new Date(clientLocalTodayStart.getTime() + (offsetMin * 60 * 1000));

  if (dateFilter === 'today') {
    match.createdAt = { $gte: startOfTodayUtc, $lte: nowUtc };
  } else if (dateFilter === 'week') {
    const clientLocalWeekStart = new Date(clientLocalTodayStart);
    clientLocalWeekStart.setUTCDate(clientLocalWeekStart.getUTCDate() - 7);
    const startOfWeekUtc = new Date(clientLocalWeekStart.getTime() + (offsetMin * 60 * 1000));
    match.createdAt = { $gte: startOfWeekUtc, $lte: nowUtc };
  } else if (dateFilter === 'month') {
    const clientLocalMonthStart = new Date(clientLocalTodayStart);
    clientLocalMonthStart.setUTCMonth(clientLocalMonthStart.getUTCMonth() - 1);
    const startOfMonthUtc = new Date(clientLocalMonthStart.getTime() + (offsetMin * 60 * 1000));
    match.createdAt = { $gte: startOfMonthUtc, $lte: nowUtc };
  }

  return match;
}

module.exports = { applyCreatedAtDateFilter };

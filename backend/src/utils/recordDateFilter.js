/**
 * Apply createdAt filters from preset (today/week/month) or custom dateFrom/dateTo (YYYY-MM-DD).
 * Custom range takes precedence over preset when either date is set.
 */
function applyCreatedAtDateFilter(match, { dateFilter = 'all', dateFrom = '', dateTo = '' } = {}) {
  const fromStr = String(dateFrom || '').trim();
  const toStr = String(dateTo || '').trim();

  if (fromStr || toStr) {
    match.createdAt = {};
    if (fromStr) {
      const from = new Date(fromStr);
      if (!Number.isNaN(from.getTime())) {
        from.setHours(0, 0, 0, 0);
        match.createdAt.$gte = from;
      }
    }
    if (toStr) {
      const to = new Date(toStr);
      if (!Number.isNaN(to.getTime())) {
        to.setHours(23, 59, 59, 999);
        match.createdAt.$lte = to;
      }
    }
    return match;
  }

  if (!dateFilter || dateFilter === 'all') {
    return match;
  }

  const now = new Date();
  let from = new Date(now);
  from.setHours(0, 0, 0, 0);

  if (dateFilter === 'today') {
    match.createdAt = { $gte: from, $lte: now };
  } else if (dateFilter === 'week') {
    from.setDate(from.getDate() - 7);
    match.createdAt = { $gte: from, $lte: now };
  } else if (dateFilter === 'month') {
    from.setMonth(from.getMonth() - 1);
    match.createdAt = { $gte: from, $lte: now };
  }

  return match;
}

module.exports = { applyCreatedAtDateFilter };

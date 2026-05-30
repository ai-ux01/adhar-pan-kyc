export function extractCreditsRemaining(payload: unknown): number | undefined {
  if (!payload || typeof payload !== 'object') return undefined;

  const root = payload as Record<string, unknown>;

  if (typeof root.creditsRemaining === 'number') {
    return root.creditsRemaining;
  }

  const data = root.data;
  if (data && typeof data === 'object') {
    const dataObj = data as Record<string, unknown>;
    if (typeof dataObj.creditsRemaining === 'number') {
      return dataObj.creditsRemaining;
    }

    if (Array.isArray(dataObj.results)) {
      let last: number | undefined;
      for (const row of dataObj.results) {
        if (row && typeof row === 'object') {
          const remaining = (row as Record<string, unknown>).creditsRemaining;
          if (typeof remaining === 'number') {
            last = remaining;
          }
        }
      }
      if (last != null) return last;
    }
  }

  return undefined;
}

export function dispatchCreditsUpdate(credits: number) {
  window.dispatchEvent(
    new CustomEvent('credits-updated', { detail: { credits } })
  );
  if (credits <= 0) {
    window.dispatchEvent(new CustomEvent('credits-exhausted'));
  }
}

export function syncCreditsFromPayload(payload: unknown): number | undefined {
  const remaining = extractCreditsRemaining(payload);
  if (remaining != null && Number.isFinite(remaining)) {
    dispatchCreditsUpdate(remaining);
    return remaining;
  }
  return undefined;
}

export function handleCreditsHttpError(status: number, payload?: unknown): boolean {
  if (status === 402) {
    dispatchCreditsUpdate(0);
    return true;
  }
  if (payload) {
    syncCreditsFromPayload(payload);
  }
  return false;
}

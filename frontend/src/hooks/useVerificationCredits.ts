import { useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useCredits } from '../contexts/CreditsContext';
import { syncCreditsFromPayload } from '../utils/creditsSync';

export function useVerificationCredits() {
  const { user, refreshUserData } = useAuth();
  const { guardCredits } = useCredits();

  const credits = user?.role === 'admin' ? Number.MAX_SAFE_INTEGER : (user?.credits ?? 0);

  const guardBeforeVerify = useCallback((): boolean => {
    if (user?.role === 'admin') return true;
    return guardCredits(user?.credits ?? 0);
  }, [user?.role, user?.credits, guardCredits]);

  const syncCreditsAfterVerify = useCallback(
    async (payload?: unknown) => {
      const synced = syncCreditsFromPayload(payload);
      if (synced != null) return synced;

      const fresh = await refreshUserData();
      if (fresh && fresh.role !== 'admin' && (fresh.credits ?? 0) <= 0) {
        window.dispatchEvent(new CustomEvent('credits-exhausted'));
      }
      return fresh?.credits;
    },
    [refreshUserData]
  );

  return {
    credits,
    isAdmin: user?.role === 'admin',
    guardBeforeVerify,
    syncCreditsAfterVerify,
  };
}

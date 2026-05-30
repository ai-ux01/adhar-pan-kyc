import React, { createContext, useCallback, useContext, useState } from 'react';
import CreditsExhaustedModal from '../components/Credits/CreditsExhaustedModal';

interface CreditsContextType {
  showCreditsExhausted: () => void;
  hideCreditsExhausted: () => void;
  hasCredits: (credits?: number) => boolean;
  guardCredits: (credits?: number) => boolean;
}

const CreditsContext = createContext<CreditsContextType | undefined>(undefined);

export const CreditsProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [modalOpen, setModalOpen] = useState(false);

  const showCreditsExhausted = useCallback(() => setModalOpen(true), []);
  const hideCreditsExhausted = useCallback(() => setModalOpen(false), []);

  React.useEffect(() => {
    const onCreditsExhausted = () => showCreditsExhausted();
    window.addEventListener('credits-exhausted', onCreditsExhausted);
    return () => window.removeEventListener('credits-exhausted', onCreditsExhausted);
  }, [showCreditsExhausted]);

  const hasCredits = useCallback((credits?: number) => (credits ?? 0) > 0, []);

  const guardCredits = useCallback(
    (credits?: number) => {
      if (hasCredits(credits)) return true;
      showCreditsExhausted();
      return false;
    },
    [hasCredits, showCreditsExhausted]
  );

  return (
    <CreditsContext.Provider
      value={{ showCreditsExhausted, hideCreditsExhausted, hasCredits, guardCredits }}
    >
      {children}
      <CreditsExhaustedModal open={modalOpen} onClose={hideCreditsExhausted} />
    </CreditsContext.Provider>
  );
};

export const useCredits = (): CreditsContextType => {
  const context = useContext(CreditsContext);
  if (!context) {
    throw new Error('useCredits must be used within a CreditsProvider');
  }
  return context;
};

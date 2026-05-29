import api from '../services/api';

export interface UserLogoMeta {
  filename?: string;
  uploadedAt?: string | Date;
}

/** Build logo URL against the configured API base (works on localhost and production). */
export function getUserLogoUrl(
  userId: string | undefined,
  logo?: UserLogoMeta | null
): string | null {
  if (!userId || !logo?.filename) return null;

  const base = (api.defaults.baseURL || '').replace(/\/$/, '');
  const cacheKey = logo.uploadedAt
    ? new Date(logo.uploadedAt).getTime()
    : encodeURIComponent(logo.filename);

  return `${base}/admin/users/${userId}/logo?v=${cacheKey}`;
}

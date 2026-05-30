const crypto = require('crypto');

function getAadhaarHashPepper() {
  const pepper = process.env.PARTNER_AADHAAR_HASH_PEPPER || process.env.ENCRYPTION_KEY;
  if (!pepper) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('PARTNER_AADHAAR_HASH_PEPPER or ENCRYPTION_KEY is required in production');
    }
    return 'dev-only-partner-aadhaar-pepper';
  }
  if (
    process.env.NODE_ENV === 'production' &&
    pepper === 'change-this-to-a-long-random-string'
  ) {
    throw new Error('Set a strong PARTNER_AADHAAR_HASH_PEPPER in production');
  }
  return pepper;
}

function normalizeAadhaar(aadhaarNumber) {
  return String(aadhaarNumber || '').replace(/\s/g, '');
}

function hashAadhaar(aadhaarNumber) {
  const normalized = normalizeAadhaar(aadhaarNumber);
  return crypto
    .createHmac('sha256', getAadhaarHashPepper())
    .update(normalized)
    .digest('hex');
}

function maskAadhaar(aadhaarNumber) {
  const n = normalizeAadhaar(aadhaarNumber);
  if (n.length !== 12) return '************';
  return `XXXX-XXXX-${n.slice(-4)}`;
}

function isValidAadhaar(aadhaarNumber) {
  return /^\d{12}$/.test(normalizeAadhaar(aadhaarNumber));
}

module.exports = {
  normalizeAadhaar,
  hashAadhaar,
  maskAadhaar,
  isValidAadhaar
};

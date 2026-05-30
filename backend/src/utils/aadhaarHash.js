const crypto = require('crypto');

function getAadhaarHashPepper() {
  return process.env.PARTNER_AADHAAR_HASH_PEPPER || process.env.ENCRYPTION_KEY || 'partner-aadhaar-pepper-change-me';
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

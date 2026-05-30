const crypto = require('crypto');
const logger = require('../utils/logger');

const CASHFREE_BASE_URL =
  process.env.CASHFREE_BASE_URL || 'https://sandbox.cashfree.com';

function getCashfreeCredentials() {
  const clientId = process.env.CASHFREE_CLIENT_ID;
  const clientSecret = process.env.CASHFREE_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error(
      'Cashfree credentials not configured. Set CASHFREE_CLIENT_ID and CASHFREE_CLIENT_SECRET.'
    );
  }

  return { clientId, clientSecret };
}

function generateVerificationId() {
  return `udyam_${crypto.randomBytes(12).toString('hex')}`;
}

function normalizeUdyamNumber(value) {
  return String(value || '')
    .trim()
    .toUpperCase()
    .replace(/\s+/g, '');
}

function isValidUdyamFormat(udyam) {
  return /^UDYAM-[A-Z]{2}-\d{2}-\d{7}$/.test(normalizeUdyamNumber(udyam));
}

async function verifyUdyamRegistration(udyamNumber, verificationId) {
  const { clientId, clientSecret } = getCashfreeCredentials();
  const udyam = normalizeUdyamNumber(udyamNumber);
  const id = verificationId || generateVerificationId();

  const url = `${CASHFREE_BASE_URL.replace(/\/$/, '')}/verification/udyam`;

  logger.info('Calling Cashfree Udyam verification API', { udyam, verificationId: id });

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-client-id': clientId,
      'x-client-secret': clientSecret,
    },
    body: JSON.stringify({
      verification_id: id,
      udyam,
    }),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      data?.message ||
      data?.error?.message ||
      data?.error ||
      `Cashfree API error (${response.status})`;
    const err = new Error(message);
    err.statusCode = response.status >= 400 && response.status < 500 ? 400 : 502;
    err.cashfreeResponse = data;
    throw err;
  }

  const status = String(data?.status || '').toUpperCase();
  const valid = status === 'SUCCESS';

  return {
    valid,
    message: valid
      ? 'Udyam registration verified successfully'
      : data?.message || 'Udyam verification failed',
    verificationId: id,
    details: {
      apiResponse: data,
      source: 'cashfree',
      referenceId: data?.reference_id,
      enterpriseName: data?.enterprise_name,
      ownerName: data?.owner_name,
      organizationType: data?.organization_type,
      enterpriseType: data?.enterprise_type,
      majorActivity: data?.major_activity,
      dateOfUdyamRegistration: data?.date_of_udyam_registration,
    },
  };
}

module.exports = {
  generateVerificationId,
  normalizeUdyamNumber,
  isValidUdyamFormat,
  verifyUdyamRegistration,
};

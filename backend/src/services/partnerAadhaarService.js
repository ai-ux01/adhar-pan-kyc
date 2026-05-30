const TenantAadhaarVerification = require('../models/TenantAadhaarVerification');
const TenantOtpSession = require('../models/TenantOtpSession');
const {
  sendAadhaarOTP,
  verifyAadhaarOTP,
  extractOtpReferenceIdFromSendResponse
} = require('./aadhaarVerificationService');
const { normalizeAadhaar, hashAadhaar, maskAadhaar } = require('../utils/aadhaarHash');
const logger = require('../utils/logger');

const OTP_SESSION_TTL_MS =
  (parseInt(process.env.PARTNER_OTP_SESSION_TTL_MINUTES, 10) || 15) * 60 * 1000;

function parseSandboxKycPayload(otpResult) {
  return otpResult?.data?.data || otpResult?.data || {};
}

function formatVerificationResponse(record, { cached = false, source = 'sandbox_api' } = {}) {
  return {
    verificationId: record._id,
    tenantId: record.tenantSlug,
    aadhaarNumber: record.aadhaarNumber,
    aadhaarMasked: maskAadhaar(record.aadhaarNumber),
    externalReferenceId: record.externalReferenceId || '',
    name: record.name || '',
    dateOfBirth: record.dateOfBirth || '',
    gender: record.gender || '',
    address: record.address || '',
    pinCode: record.pinCode || '',
    state: record.state || '',
    district: record.district || '',
    careOf: record.careOf || '',
    photo: record.photo || '',
    status: record.status,
    source: cached ? 'tenant_cache' : source,
    cached,
    verifiedAt: record.verifiedAt || record.updatedAt,
    processingTime: record.processingTime || 0
  };
}

async function findCachedVerified(tenantObjectId, aadhaarNumber) {
  const aadhaarNumberHash = hashAadhaar(aadhaarNumber);
  return TenantAadhaarVerification.findOne({
    tenantId: tenantObjectId,
    aadhaarNumberHash,
    status: 'verified'
  })
    .sort({ verifiedAt: -1, createdAt: -1 })
    .lean();
}

async function partnerAadhaarEntry(tenant, body) {
  const { aadhaarNumber, consent, externalReferenceId = '' } = body;
  const normalized = normalizeAadhaar(aadhaarNumber);

  const cached = await findCachedVerified(tenant._id, normalized);
  if (cached) {
    return {
      success: true,
      cached: true,
      otpRequired: false,
      message: 'Aadhaar already verified for this tenant. Returning cached KYC data.',
      data: formatVerificationResponse(cached, { cached: true, source: 'tenant_cache' })
    };
  }

  return {
    success: true,
    cached: false,
    otpRequired: true,
    message: consent
      ? 'No verified record found. Proceed with OTP send.'
      : 'Consent required before OTP can be sent.',
    data: {
      tenantId: tenant.tenantId,
      aadhaarNumber: normalized,
      aadhaarMasked: maskAadhaar(normalized),
      externalReferenceId: String(externalReferenceId || '').trim()
    }
  };
}

async function partnerSendOtp(tenant, body) {
  const { aadhaarNumber, consent, externalReferenceId = '', reason = 'KYC Verification' } = body;
  const normalized = normalizeAadhaar(aadhaarNumber);

  if (!consent) {
    const err = new Error('Consent is required to send OTP');
    err.statusCode = 400;
    throw err;
  }

  const cached = await findCachedVerified(tenant._id, normalized);
  if (cached) {
    return {
      success: true,
      cached: true,
      otpSent: false,
      message: 'Verified record found. OTP not required.',
      data: formatVerificationResponse(cached, { cached: true, source: 'tenant_cache' })
    };
  }

  const startTime = Date.now();
  const otpResponse = await sendAadhaarOTP(normalized, reason);
  const transactionId = extractOtpReferenceIdFromSendResponse(otpResponse);

  if (!transactionId) {
    const err = new Error('Failed to obtain OTP reference from provider');
    err.statusCode = 502;
    throw err;
  }

  const expiresAt = new Date(Date.now() + OTP_SESSION_TTL_MS);
  await TenantOtpSession.create({
    tenantId: tenant._id,
    aadhaarNumberHash: hashAadhaar(normalized),
    transactionId: String(transactionId),
    externalReferenceId: String(externalReferenceId || '').trim(),
    expiresAt,
    status: 'otp_sent'
  });

  return {
    success: true,
    cached: false,
    otpSent: true,
    message: 'OTP sent successfully',
    data: {
      tenantId: tenant.tenantId,
      aadhaarNumber: normalized,
      aadhaarMasked: maskAadhaar(normalized),
      transactionId: String(transactionId),
      externalReferenceId: String(externalReferenceId || '').trim(),
      expiresAt,
      processingTime: Date.now() - startTime
    }
  };
}

async function partnerVerifyOtp(tenant, body) {
  const { aadhaarNumber, otp, transactionId, externalReferenceId = '' } = body;
  const normalized = normalizeAadhaar(aadhaarNumber);
  const referenceId = transactionId != null ? String(transactionId).trim() : '';

  const cached = await findCachedVerified(tenant._id, normalized);
  if (cached) {
    return {
      success: true,
      cached: true,
      message: 'Already verified for this tenant.',
      data: formatVerificationResponse(cached, { cached: true, source: 'tenant_cache' })
    };
  }

  const session = await TenantOtpSession.findOne({
    tenantId: tenant._id,
    transactionId: referenceId,
    aadhaarNumberHash: hashAadhaar(normalized),
    status: 'otp_sent',
    expiresAt: { $gt: new Date() }
  });

  if (!session) {
    const err = new Error('Invalid or expired OTP session. Send OTP again.');
    err.statusCode = 400;
    throw err;
  }

  const startTime = Date.now();
  let otpResult;
  try {
    otpResult = await verifyAadhaarOTP(referenceId, otp);
  } catch (error) {
    session.status = 'failed';
    await session.save();

    await TenantAadhaarVerification.create({
      tenantId: tenant._id,
      tenantSlug: tenant.tenantId,
      aadhaarNumberHash: hashAadhaar(normalized),
      aadhaarNumber: normalized,
      externalReferenceId: String(externalReferenceId || session.externalReferenceId || '').trim(),
      name: '',
      status: 'invalid',
      source: 'sandbox_api',
      verificationDetails: { error: error.message, transactionId: referenceId },
      processingTime: Date.now() - startTime
    });

    const err = new Error(error.message || 'OTP verification failed');
    err.statusCode = 400;
    throw err;
  }

  const apiData = parseSandboxKycPayload(otpResult);
  const addressData = apiData.address || {};
  const isVerified = apiData.status === 'VALID';
  const processingTime = Date.now() - startTime;

  const record = await TenantAadhaarVerification.create({
    tenantId: tenant._id,
    tenantSlug: tenant.tenantId,
    aadhaarNumberHash: hashAadhaar(normalized),
    aadhaarNumber: normalized,
    externalReferenceId: String(externalReferenceId || session.externalReferenceId || '').trim(),
    name: apiData.name || '',
    dateOfBirth: apiData.date_of_birth || apiData.dateOfBirth || '',
    gender: apiData.gender || '',
    address: apiData.full_address || addressData.full_address || '',
    pinCode:
      (addressData.pincode != null && String(addressData.pincode)) ||
      (addressData.pinCode != null && String(addressData.pinCode)) ||
      '',
    state: addressData.state || '',
    district: addressData.district || '',
    careOf: apiData.care_of || '',
    photo: apiData.photo || '',
    status: isVerified ? 'verified' : 'invalid',
    source: 'sandbox_api',
    verificationDetails: {
      apiResponse: otpResult,
      transactionId: referenceId,
      verifiedAt: new Date()
    },
    verifiedAt: isVerified ? new Date() : undefined,
    processingTime
  });

  session.status = isVerified ? 'verified' : 'failed';
  await session.save();

  return {
    success: isVerified,
    cached: false,
    message: isVerified
      ? 'Aadhaar verification completed successfully'
      : apiData.message || 'Invalid OTP. Verification rejected.',
    data: formatVerificationResponse(record, { cached: false, source: 'sandbox_api' })
  };
}

async function getVerificationById(tenant, verificationId) {
  const record = await TenantAadhaarVerification.findOne({
    _id: verificationId,
    tenantId: tenant._id
  }).lean();

  if (!record) {
    const err = new Error('Verification record not found');
    err.statusCode = 404;
    throw err;
  }

  return {
    success: true,
    data: formatVerificationResponse(record, {
      cached: record.source === 'tenant_cache',
      source: record.source
    })
  };
}

module.exports = {
  partnerAadhaarEntry,
  partnerSendOtp,
  partnerVerifyOtp,
  getVerificationById,
  formatVerificationResponse
};

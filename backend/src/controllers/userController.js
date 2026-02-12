const User = require('../models/User');
const PanKyc = require('../models/PanKyc');
const AadhaarPan = require('../models/AadhaarPan');
const AadhaarVerification = require('../models/AadhaarVerification');
const emailService = require('../services/emailService');
const logger = require('../utils/logger');

// @desc    Get user profile
// @route   GET /api/users/profile
// @access  Private
const getProfile = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    moduleAccess: user.moduleAccess,
    isEmailVerified: user.isEmailVerified,
    twoFactorEnabled: user.twoFactorEnabled,
    profile: user.profile,
    preferences: user.preferences,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin,
  };
};

// @desc    Update user profile
// @route   PUT /api/users/profile
// @access  Private
const updateProfile = async (userId, updateData) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  // Update allowed fields
  const allowedFields = ['name', 'profile'];
  const updates = {};

  allowedFields.forEach(field => {
    if (updateData[field]) {
      updates[field] = updateData[field];
    }
  });

  // Update user
  Object.assign(user, updates);
  await user.save();

  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    moduleAccess: user.moduleAccess,
    isEmailVerified: user.isEmailVerified,
    twoFactorEnabled: user.twoFactorEnabled,
    profile: user.profile,
    preferences: user.preferences,
  };
};

// @desc    Update user preferences
// @route   PUT /api/users/preferences
// @access  Private
const updatePreferences = async (userId, preferences) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  // Update preferences
  if (preferences.notifications) {
    user.preferences.notifications = {
      ...user.preferences.notifications,
      ...preferences.notifications,
    };
  }

  if (preferences.theme) {
    user.preferences.theme = preferences.theme;
  }

  await user.save();

  return user.preferences;
};

// @desc    Get user activity
// @route   GET /api/users/activity
// @access  Private
const getUserActivity = async (userId, days = 30) => {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  // Get user activity from audit logs
  const Audit = require('../models/Audit');
  const activity = await Audit.getUserActivity(userId, days);

  return activity;
};

// @desc    Get user statistics
// @route   GET /api/users/stats
// @access  Private
const getUserStats = async (userId, days = 30) => {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  // Get PAN KYC stats
  const panKycStats = await PanKyc.getUserStats(userId, days);

  // Get Aadhaar-PAN stats
  const aadhaarPanStats = await AadhaarPan.getUserStats(userId, days);

  // Get Aadhaar verification stats
  const aadhaarVerificationStats = await AadhaarVerification.getUserStats(userId, days);

  // Get audit activity summary
  const auditService = require('../services/auditService');
  const activitySummary = await auditService.getUserActivitySummary(userId, days);

  return {
    panKyc: panKycStats,
    aadhaarPan: aadhaarPanStats,
    aadhaarVerification: aadhaarVerificationStats,
    activity: activitySummary,
    period: {
      startDate,
      endDate: new Date(),
      days,
    },
  };
};

// @desc    Enable two-factor authentication
// @route   POST /api/users/two-factor/enable
// @access  Private
const enableTwoFactor = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  if (user.twoFactorEnabled) {
    throw new Error('Two-factor authentication is already enabled');
  }

  // Generate 2FA secret
  const secret = require('crypto').randomBytes(20).toString('hex');
  user.twoFactorSecret = secret;
  user.twoFactorEnabled = true;

  await user.save();

  return {
    twoFactorEnabled: true,
    secret: secret,
    qrCode: generateQRCode(secret, user.email), // You would implement this
  };
};

// @desc    Disable two-factor authentication
// @route   POST /api/users/two-factor/disable
// @access  Private
const disableTwoFactor = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  if (!user.twoFactorEnabled) {
    throw new Error('Two-factor authentication is not enabled');
  }

  user.twoFactorSecret = undefined;
  user.twoFactorEnabled = false;

  await user.save();

  return {
    twoFactorEnabled: false,
  };
};

// @desc    Verify two-factor authentication token
// @route   POST /api/users/two-factor/verify
// @access  Private
const verifyTwoFactor = async (userId, token) => {
  const user = await User.findById(userId).select('+twoFactorSecret');
  if (!user) {
    throw new Error('User not found');
  }

  if (!user.twoFactorEnabled) {
    throw new Error('Two-factor authentication is not enabled');
  }

  // Verify TOTP token (simplified implementation)
  // In production, use a proper TOTP library like 'speakeasy'
  const expectedToken = require('crypto')
    .createHmac('sha1', user.twoFactorSecret)
    .update(Math.floor(Date.now() / 30000).toString())
    .digest('hex')
    .substring(0, 6);

  if (token !== expectedToken) {
    throw new Error('Invalid two-factor authentication token');
  }

  return { success: true };
};

// @desc    Get active sessions
// @route   GET /api/users/sessions
// @access  Private
const getActiveSessions = async (userId) => {
  // This is a simplified implementation
  // In a real application, you would track sessions in a separate collection
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  // For now, return a mock session
  return [
    {
      sessionId: 'current-session',
      device: 'Web Browser',
      location: 'Unknown',
      lastActivity: user.lastLogin || new Date(),
      isCurrent: true,
    },
  ];
};

// @desc    Revoke session
// @route   DELETE /api/users/sessions/:sessionId
// @access  Private
const revokeSession = async (userId, sessionId) => {
  // This is a simplified implementation
  // In a real application, you would invalidate the session token
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  // For now, just log the revocation
  logger.info(`Session revoked for user ${userId}: ${sessionId}`);
};

// @desc    Send test notification
// @route   POST /api/users/notifications/test
// @access  Private
const sendTestNotification = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  if (!user.preferences.notifications.email) {
    throw new Error('Email notifications are disabled');
  }

  // Send test notification email
  await emailService.sendNotificationEmail(
    user.email,
    'Test Notification',
    '<p>This is a test notification from the KYC Aadhaar System.</p>',
    {
      details: {
        type: 'test',
        timestamp: new Date().toISOString(),
        userId: user._id,
      },
    }
  );
};

// Helper function to generate QR code for 2FA
const generateQRCode = (secret, email) => {
  // This is a placeholder implementation
  // In production, use a library like 'qrcode' to generate actual QR codes
  const otpauth = `otpauth://totp/KYC Aadhaar System:${email}?secret=${secret}&issuer=KYC Aadhaar System`;
  return otpauth;
};

module.exports = {
  getProfile,
  updateProfile,
  updatePreferences,
  getUserActivity,
  getUserStats,
  enableTwoFactor,
  disableTwoFactor,
  verifyTwoFactor,
  getActiveSessions,
  revokeSession,
  sendTestNotification,
};

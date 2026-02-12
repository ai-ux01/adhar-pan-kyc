const User = require('../models/User');
const emailService = require('../services/emailService');
const logger = require('../utils/logger');

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
const register = async (userData) => {
  const { name, email, password, confirmPassword } = userData;

  // Check if passwords match
  if (password !== confirmPassword) {
    throw new Error('Passwords do not match');
  }

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new Error('User already exists with this email');
  }

  // Create user
  const user = await User.create({
    name,
    email,
    password,
    role: 'user',
    moduleAccess: [], // Admin will assign module access
  });

  // Generate email verification token
  const verificationToken = user.getEmailVerificationToken();
  await user.save();

  // Send verification email
  try {
    await emailService.sendVerificationEmail(user.email, verificationToken);
  } catch (error) {
    logger.error('Failed to send verification email:', error);
    // Don't fail registration if email fails
  }

  // Generate session token for new user
  user.generateSessionToken();
  await user.save();

  // Generate JWT token
  const token = user.getSignedJwtToken();

  return {
    success: true,
    token,
    user: {
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      moduleAccess: user.moduleAccess,
      isEmailVerified: user.isEmailVerified,
      branding: user.branding,
    },
  };
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
const login = async (loginData) => {
  const { email, password, rememberMe } = loginData;

  // Check if user exists
  const user = await User.findOne({ email }).select('+password');
  if (!user) {
    throw new Error('Invalid credentials');
  }

  // Check if user is active
  if (!user.isActive) {
    throw new Error('Account is suspended. Please contact administrator.');
  }

  // Check if account is locked
  if (user.isLocked) {
    throw new Error('Account is temporarily locked due to multiple failed login attempts. Please try again later.');
  }

  // Check password
  const isMatch = await user.matchPassword(password);
  if (!isMatch) {
    // Increment login attempts
    await user.incLoginAttempts();
    throw new Error('Invalid credentials');
  }

  // Reset login attempts on successful login
  await user.resetLoginAttempts();

  // Generate new session token (this invalidates previous sessions)
  user.generateSessionToken();
  user.lastLogin = Date.now();
  await user.save();

  // Generate JWT token with appropriate expiration
  const token = user.getSignedJwtToken(rememberMe ? '30d' : '24h');

  return {
    success: true,
    token,
    user: {
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      moduleAccess: user.moduleAccess,
      isEmailVerified: user.isEmailVerified,
      twoFactorEnabled: user.twoFactorEnabled,
      profile: user.profile,
      branding: user.branding,
      preferences: user.preferences,
      customFields: user.customFields,
      enabledCustomFields: user.enabledCustomFields,
    },
  };
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
const getCurrentUser = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  console.log('🔍 getCurrentUser - user.branding:', JSON.stringify(user.branding, null, 2));

  return {
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    moduleAccess: user.moduleAccess,
    isEmailVerified: user.isEmailVerified,
    twoFactorEnabled: user.twoFactorEnabled,
    profile: user.profile,
    branding: user.branding,
    preferences: user.preferences,
    customFields: user.customFields,
    enabledCustomFields: user.enabledCustomFields,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin,
  };
};

// @desc    Forgot password
// @route   POST /api/auth/forgot-password
// @access  Public
const forgotPassword = async (email) => {
  const user = await User.findOne({ email });
  if (!user) {
    // Don't reveal if user exists or not for security
    return;
  }

  // Generate reset token
  const resetToken = user.getResetPasswordToken();
  await user.save();

  // Send reset email
  try {
    await emailService.sendPasswordResetEmail(user.email, resetToken);
  } catch (error) {
    logger.error('Failed to send password reset email:', error);
    throw new Error('Failed to send password reset email');
  }
};

// @desc    Validate reset token
// @route   GET /api/auth/validate-reset-token/:token
// @access  Public
const validateResetToken = async (token) => {
  // Get hashed token
  const resetPasswordToken = require('crypto')
    .createHash('sha256')
    .update(token)
    .digest('hex');

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) {
    throw new Error('Invalid or expired reset token');
  }

  return { success: true };
};

// @desc    Reset password
// @route   POST /api/auth/reset-password/:token
// @access  Public
const resetPassword = async (token, newPassword) => {
  // Get hashed token
  const resetPasswordToken = require('crypto')
    .createHash('sha256')
    .update(token)
    .digest('hex');

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) {
    throw new Error('Invalid or expired reset token');
  }

  // Set new password
  user.password = newPassword;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save();

  // Generate JWT token
  const jwtToken = user.getSignedJwtToken();

  return {
    success: true,
    token: jwtToken,
    user: {
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  };
};

// @desc    Change password
// @route   POST /api/auth/change-password
// @access  Private
const changePassword = async (userId, currentPassword, newPassword) => {
  const user = await User.findById(userId).select('+password');
  if (!user) {
    throw new Error('User not found');
  }

  // Check current password
  const isMatch = await user.matchPassword(currentPassword);
  if (!isMatch) {
    throw new Error('Current password is incorrect');
  }

  // Set new password
  user.password = newPassword;
  await user.save();
};

// @desc    Verify email
// @route   POST /api/auth/verify-email/:token
// @access  Public
const verifyEmail = async (token) => {
  // Get hashed token
  const emailVerificationToken = require('crypto')
    .createHash('sha256')
    .update(token)
    .digest('hex');

  const user = await User.findOne({
    emailVerificationToken,
    emailVerificationExpire: { $gt: Date.now() },
  });

  if (!user) {
    throw new Error('Invalid or expired verification token');
  }

  // Mark email as verified
  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpire = undefined;
  await user.save();

  // Generate JWT token
  const jwtToken = user.getSignedJwtToken();

  return {
    success: true,
    token: jwtToken,
    user: {
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
    },
  };
};

// @desc    Resend verification email
// @route   POST /api/auth/resend-verification
// @access  Private
const resendVerificationEmail = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  if (user.isEmailVerified) {
    throw new Error('Email is already verified');
  }

  // Generate new verification token
  const verificationToken = user.getEmailVerificationToken();
  await user.save();

  // Send verification email
  try {
    await emailService.sendVerificationEmail(user.email, verificationToken);
  } catch (error) {
    logger.error('Failed to send verification email:', error);
    throw new Error('Failed to send verification email');
  }
};

// @desc    Enable/disable 2FA
// @route   POST /api/auth/two-factor
// @access  Private
const toggleTwoFactor = async (userId, enable) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  if (enable) {
    // Generate 2FA secret
    const secret = require('crypto').randomBytes(20).toString('hex');
    user.twoFactorSecret = secret;
    user.twoFactorEnabled = true;
  } else {
    user.twoFactorSecret = undefined;
    user.twoFactorEnabled = false;
  }

  await user.save();

  return {
    twoFactorEnabled: user.twoFactorEnabled,
    secret: enable ? user.twoFactorSecret : undefined,
  };
};

// @desc    Verify 2FA token
// @route   POST /api/auth/verify-2fa
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

module.exports = {
  register,
  login,
  getCurrentUser,
  forgotPassword,
  validateResetToken,
  resetPassword,
  changePassword,
  verifyEmail,
  resendVerificationEmail,
  toggleTwoFactor,
  verifyTwoFactor,
};

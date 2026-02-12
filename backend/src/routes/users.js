const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const QRCode = require('qrcode');
const User = require('../models/User');

const { protect } = require('../middleware/auth');
const userController = require('../controllers/userController');
const auditService = require('../services/auditService');

// Validation middleware
const validateProfileUpdate = [
  body('name').optional().trim().isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
  body('profile.phone').optional().isMobilePhone().withMessage('Please enter a valid phone number'),
  body('profile.company').optional().trim().isLength({ max: 100 }).withMessage('Company name must be less than 100 characters'),
  body('profile.designation').optional().trim().isLength({ max: 100 }).withMessage('Designation must be less than 100 characters'),
  body('profile.address').optional().trim().isLength({ max: 500 }).withMessage('Address must be less than 500 characters'),
];

const validatePreferencesUpdate = [
  body('preferences.notifications.email').optional().isBoolean().withMessage('Email notification must be a boolean'),
  body('preferences.notifications.sms').optional().isBoolean().withMessage('SMS notification must be a boolean'),
  body('preferences.theme').optional().isIn(['light', 'dark']).withMessage('Theme must be either light or dark'),
];

// @route   GET /api/users/profile
// @desc    Get user profile
// @access  Private
router.get('/profile', protect, async (req, res) => {
  try {
    const profile = await userController.getProfile(req.user._id);
    res.json({
      success: true,
      data: profile,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   PUT /api/users/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', protect, validateProfileUpdate, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }

    const updatedProfile = await userController.updateProfile(req.user._id, req.body);
    
    // Log profile update
    await auditService.logEvent({
      userId: req.user._id,
      action: 'user_updated',
      module: 'user_management',
      resource: 'user',
      resourceId: req.user._id,
      details: { updatedFields: Object.keys(req.body) },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      data: updatedProfile,
      message: 'Profile updated successfully',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   PUT /api/users/preferences
// @desc    Update user preferences
// @access  Private
router.put('/preferences', protect, validatePreferencesUpdate, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }

    const updatedPreferences = await userController.updatePreferences(req.user._id, req.body.preferences);
    
    // Log preferences update
    await auditService.logEvent({
      userId: req.user._id,
      action: 'user_updated',
      module: 'user_management',
      resource: 'user',
      resourceId: req.user._id,
      details: { updatedPreferences: req.body.preferences },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      data: updatedPreferences,
      message: 'Preferences updated successfully',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   GET /api/users/activity
// @desc    Get user activity summary
// @access  Private
router.get('/activity', protect, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 30;
    const activity = await userController.getUserActivity(req.user._id, days);
    res.json({
      success: true,
      data: activity,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   GET /api/users/stats
// @desc    Get user statistics
// @access  Private
router.get('/stats', protect, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 30;
    const stats = await userController.getUserStats(req.user._id, days);
    res.json({
      success: true,
      data: stats,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/users/two-factor/enable
// @desc    Enable two-factor authentication
// @access  Private
router.post('/two-factor/enable', protect, async (req, res) => {
  try {
    const result = await userController.enableTwoFactor(req.user._id);
    
    // Log 2FA enable
    await auditService.logEvent({
      userId: req.user._id,
      action: 'two_factor_enabled',
      module: 'auth',
      resource: 'user',
      resourceId: req.user._id,
      details: { twoFactorEnabled: true },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      data: result,
      message: 'Two-factor authentication enabled successfully',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/users/two-factor/disable
// @desc    Disable two-factor authentication
// @access  Private
router.post('/two-factor/disable', protect, async (req, res) => {
  try {
    const result = await userController.disableTwoFactor(req.user._id);
    
    // Log 2FA disable
    await auditService.logEvent({
      userId: req.user._id,
      action: 'two_factor_disabled',
      module: 'auth',
      resource: 'user',
      resourceId: req.user._id,
      details: { twoFactorEnabled: false },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      data: result,
      message: 'Two-factor authentication disabled successfully',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/users/two-factor/verify
// @desc    Verify two-factor authentication token
// @access  Private
router.post('/two-factor/verify', protect, [
  body('token').isLength({ min: 6, max: 6 }).withMessage('Token must be 6 digits'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }

    const result = await userController.verifyTwoFactor(req.user._id, req.body.token);
    
    // Log 2FA verification
    await auditService.logEvent({
      userId: req.user._id,
      action: 'two_factor_verified',
      module: 'auth',
      resource: 'user',
      resourceId: req.user._id,
      details: { verificationSuccess: true },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      data: result,
      message: 'Two-factor authentication verified successfully',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   GET /api/users/sessions
// @desc    Get user active sessions
// @access  Private
router.get('/sessions', protect, async (req, res) => {
  try {
    const sessions = await userController.getActiveSessions(req.user._id);
    res.json({
      success: true,
      data: sessions,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   DELETE /api/users/sessions/:sessionId
// @desc    Revoke user session
// @access  Private
router.delete('/sessions/:sessionId', protect, async (req, res) => {
  try {
    await userController.revokeSession(req.user._id, req.params.sessionId);
    
    // Log session revocation
    await auditService.logEvent({
      userId: req.user._id,
      action: 'session_revoked',
      module: 'auth',
      resource: 'session',
      details: { sessionId: req.params.sessionId },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      message: 'Session revoked successfully',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/users/notifications/test
// @desc    Send test notification
// @access  Private
router.post('/notifications/test', protect, async (req, res) => {
  try {
    await userController.sendTestNotification(req.user._id);
    
    // Log test notification
    await auditService.logEvent({
      userId: req.user._id,
      action: 'test_notification_sent',
      module: 'user_management',
      resource: 'notification',
      details: { notificationType: 'test' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      message: 'Test notification sent successfully',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   GET /api/users/qr-code
// @desc    Get user's own QR code
// @access  Private
router.get('/qr-code', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if user has qr-code module access
    if (!user.moduleAccess || !user.moduleAccess.includes('qr-code')) {
      return res.status(403).json({
        success: false,
        message: 'QR code module is not enabled for your account'
      });
    }

    // Generate QR code if it doesn't exist
    if (!user.qrCode || !user.qrCode.code) {
      // Generate unique QR code
      const crypto = require('crypto');
      const qrCodeString = crypto.randomBytes(32).toString('hex');
      
      // Create QR code URL - use production URL in production, localhost in development
      // Priority: FRONTEND_URL env var > Custom domain > localhost
      const frontendUrl = process.env.FRONTEND_URL || 
        (process.env.NODE_ENV === 'production' 
          ? 'https://www.avihridsys.in' 
          : 'http://localhost:3000');
      const qrCodeUrl = `${frontendUrl}/verify/qr/${qrCodeString}`;

      // Generate QR code image
      const qrCodeDataUrl = await QRCode.toDataURL(qrCodeUrl, {
        errorCorrectionLevel: 'H',
        type: 'image/png',
        width: 300,
        margin: 1
      });

      // Update user with QR code
      user.qrCode = {
        code: qrCodeString,
        generatedAt: new Date(),
        isActive: true
      };
      await user.save();

      return res.json({
        success: true,
        data: {
          qrCode: qrCodeDataUrl,
          qrCodeUrl: qrCodeUrl,
          qrCodeString: qrCodeString
        }
      });
    }

    // Return existing QR code - use production URL in production, localhost in development
    // Priority: FRONTEND_URL env var > Amplify URL > Vercel URL > localhost
    const frontendUrl = process.env.FRONTEND_URL || 
      (process.env.NODE_ENV === 'production' 
        ? 'https://www.avihridsys.in' 
        : 'http://localhost:3000');
    const qrCodeUrl = `${frontendUrl}/verify/qr/${user.qrCode.code}`;
    const qrCodeDataUrl = await QRCode.toDataURL(qrCodeUrl, {
      errorCorrectionLevel: 'H',
      type: 'image/png',
      width: 300,
      margin: 1
    });

    res.json({
      success: true,
      data: {
        qrCode: qrCodeDataUrl,
        qrCodeUrl: qrCodeUrl,
        qrCodeString: user.qrCode.code
      }
    });
  } catch (error) {
    console.error('Error fetching QR code:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch QR code',
      error: error.message
    });
  }
});

module.exports = router;

const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();

const { protect } = require('../middleware/auth');
const authController = require('../controllers/authController');
const auditService = require('../services/auditService');

// Validation middleware
const validateLogin = [
  body('email').isEmail().withMessage('Please enter a valid email'),
  body('password').notEmpty().withMessage('Password is required'),
];

const validateRegister = [
  body('name').trim().isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
  body('email').isEmail().withMessage('Please enter a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Password confirmation does not match password');
    }
    return true;
  }),
];

const validatePasswordReset = [
  body('email').isEmail().withMessage('Please enter a valid email'),
];

const validatePasswordChange = [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.newPassword) {
      throw new Error('Password confirmation does not match new password');
    }
    return true;
  }),
];

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', validateRegister, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }

    const result = await authController.register(req.body);
    
    // Log audit event
    await auditService.logEvent({
      action: 'user_created',
      module: 'auth',
      resource: 'user',
      resourceId: result.user._id,
      details: { email: result.user.email, role: result.user.role },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', validateLogin, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }

    const result = await authController.login(req.body);
    
    // Log successful login
    await auditService.logEvent({
      userId: result.user._id,
      action: 'login',
      module: 'auth',
      resource: 'user',
      resourceId: result.user._id,
      details: { email: result.user.email },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.sessionID,
    });

    res.json(result);
  } catch (error) {
    // Log failed login attempt
    await auditService.logEvent({
      action: 'login_failed',
      module: 'auth',
      details: { email: req.body.email, error: error.message },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      status: 'failed',
      severity: 'medium',
    });

    res.status(401).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/auth/logout
// @desc    Logout user
// @access  Private
router.post('/logout', protect, async (req, res) => {
  try {
    // Log logout event
    await auditService.logEvent({
      userId: req.user._id,
      action: 'logout',
      module: 'auth',
      resource: 'user',
      resourceId: req.user._id,
      details: { email: req.user.email },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.sessionID,
    });

    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Logout failed',
    });
  }
});

// @route   GET /api/auth/me
// @desc    Get current user
// @access  Private
router.get('/me', protect, async (req, res) => {
  try {
    const user = await authController.getCurrentUser(req.user._id);
    
    // Add cache control headers to prevent caching
    res.set({
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    
    res.json({
      success: true,
      data: user,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/auth/forgot-password
// @desc    Forgot password
// @access  Public
router.post('/forgot-password', validatePasswordReset, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }

    await authController.forgotPassword(req.body.email);
    
    // Log password reset request
    await auditService.logEvent({
      action: 'password_reset',
      module: 'auth',
      details: { email: req.body.email },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      message: 'Password reset email sent',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   GET /api/auth/validate-reset-token/:token
// @desc    Validate reset token
// @access  Public
router.get('/validate-reset-token/:token', async (req, res) => {
  try {
    await authController.validateResetToken(req.params.token);
    
    res.json({
      success: true,
      message: 'Token is valid',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/auth/reset-password/:token
// @desc    Reset password
// @access  Public
router.post('/reset-password/:token', [
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Password confirmation does not match password');
    }
    return true;
  }),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }

    const result = await authController.resetPassword(req.params.token, req.body.password);
    
    // Log password reset completion
    await auditService.logEvent({
      userId: result.user._id,
      action: 'password_reset',
      module: 'auth',
      resource: 'user',
      resourceId: result.user._id,
      details: { email: result.user.email },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      message: 'Password reset successful',
      token: result.token,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/auth/change-password
// @desc    Change password
// @access  Private
router.post('/change-password', protect, validatePasswordChange, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }

    await authController.changePassword(req.user._id, req.body.currentPassword, req.body.newPassword);
    
    // Log password change
    await auditService.logEvent({
      userId: req.user._id,
      action: 'password_change',
      module: 'auth',
      resource: 'user',
      resourceId: req.user._id,
      details: { email: req.user.email },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      message: 'Password changed successfully',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/auth/verify-email/:token
// @desc    Verify email
// @access  Public
router.post('/verify-email/:token', async (req, res) => {
  try {
    const result = await authController.verifyEmail(req.params.token);
    
    // Log email verification
    await auditService.logEvent({
      userId: result.user._id,
      action: 'email_verification',
      module: 'auth',
      resource: 'user',
      resourceId: result.user._id,
      details: { email: result.user.email },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      message: 'Email verified successfully',
      token: result.token,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/auth/resend-verification
// @desc    Resend email verification
// @access  Private
router.post('/resend-verification', protect, async (req, res) => {
  try {
    await authController.resendVerificationEmail(req.user._id);
    
    // Log resend verification
    await auditService.logEvent({
      userId: req.user._id,
      action: 'email_verification',
      module: 'auth',
      resource: 'user',
      resourceId: req.user._id,
      details: { email: req.user.email, action: 'resend' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      success: true,
      message: 'Verification email sent',
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// @route   POST /api/auth/refresh
// @desc    Refresh JWT token
// @access  Private
router.post('/refresh', protect, async (req, res) => {
  try {
    // Generate new token
    const token = req.user.getSignedJwtToken();
    
    res.json({
      success: true,
      token,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

module.exports = router;

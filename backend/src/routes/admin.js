const express = require('express');
const router = express.Router();
const { protect, authorize } = require('../middleware/auth');
const User = require('../models/User');
const Audit = require('../models/Audit');
const PanKyc = require('../models/PanKyc');
const AadhaarPan = require('../models/AadhaarPan');
const { logEvent } = require('../services/auditService');
const logger = require('../utils/logger');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const crypto = require('crypto');
const { getAllowedOrigin } = require('../utils/corsHelper');

// Configure multer for logo uploads
// Use absolute path to ensure consistency
const logosDir = path.join(__dirname, '..', '..', 'uploads', 'logos');
// Ensure the directory exists
if (!fs.existsSync(logosDir)) {
  fs.mkdirSync(logosDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, logosDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'logo-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// Admin middleware - check if user is admin
const adminAuth = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Access denied. Admin privileges required.'
    });
  }
  next();
};

// Get all users (admin only)
router.get('/users', protect, authorize('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '', status = '' } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status) {
      query.status = status;
    }

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await User.countDocuments(query);

    res.json({
      success: true,
      data: {
        users,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    logger.error('Error fetching users:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
});

// Get user by ID (admin only)
router.get('/users/:id', protect, authorize('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    logger.error('Error fetching user:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user'
    });
  }
});

// Create new user (admin only)
router.post('/users', protect, authorize('admin'), async (req, res) => {
  try {
    const { name, email, password, role, moduleAccess, status, enabledCustomFields } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    const user = new User({
      name,
      email,
      password,
      role: role || 'user',
      moduleAccess: moduleAccess || [],
      status: status || 'active',
      enabledCustomFields: enabledCustomFields || []
    });

    await user.save();

    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'user_created',
      module: 'admin',
      resource: 'user',
      resourceId: user._id,
      details: {
        createdUserEmail: user.email,
        role: user.role,
        moduleAccess: user.moduleAccess
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        moduleAccess: user.moduleAccess,
        status: user.status
      }
    });
  } catch (error) {
    logger.error('Error creating user:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create user'
    });
  }
});

// Update user (admin only)
router.put('/users/:id', protect, authorize('admin'), async (req, res) => {
  try {
    const { name, email, role, moduleAccess, status, enabledCustomFields } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if email is being changed and if it's already taken
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Email already in use'
        });
      }
    }

    const oldData = {
      name: user.name,
      email: user.email,
      role: user.role,
      moduleAccess: user.moduleAccess,
      status: user.status,
      enabledCustomFields: user.enabledCustomFields
    };

    // Update user
    user.name = name || user.name;
    user.email = email || user.email;
    user.role = role || user.role;
    user.moduleAccess = moduleAccess || user.moduleAccess;
    user.status = status || user.status;
    if (enabledCustomFields !== undefined) {
      user.enabledCustomFields = enabledCustomFields;
    }

    await user.save();

    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'user_updated',
      module: 'admin',
      resource: 'user',
      resourceId: user._id,
      details: {
        oldData,
        newData: {
          name: user.name,
          email: user.email,
          role: user.role,
          moduleAccess: user.moduleAccess,
          status: user.status
        }
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'User updated successfully',
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        moduleAccess: user.moduleAccess,
        status: user.status
      }
    });
  } catch (error) {
    logger.error('Error updating user:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user'
    });
  }
});

// Delete user (admin only)
router.delete('/users/:id', protect, authorize('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Prevent admin from deleting themselves
    if (user._id.toString() === req.user.id) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete your own account'
      });
    }

    await User.findByIdAndDelete(req.params.id);

    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'user_deleted',
      module: 'admin',
      resource: 'user',
      resourceId: user._id,
      details: {
        deletedUserEmail: user.email,
        deletedUserName: user.name
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    logger.error('Error deleting user:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete user'
    });
  }
});

// Get audit logs (admin only)
router.get('/audit-logs', protect, authorize('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 50, module = '', action = '', userId = '', startDate = '', endDate = '' } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    
    if (module) query.module = module;
    if (action) query.action = action;
    if (userId) query.userId = userId;
    
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    const logs = await Audit.find(query)
      .populate('userId', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Audit.countDocuments(query);

    res.json({
      success: true,
      data: {
        logs,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  } catch (error) {
    logger.error('Error fetching audit logs:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch audit logs'
    });
  }
});

// Debug endpoint for user performance
router.get('/debug-user-performance', protect, authorize('admin'), async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // Test the topPerformers query
    const topPerformers = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
          userId: { $ne: null },
          action: { $in: ['pan_kyc_upload', 'aadhaar_pan_upload', 'file_uploaded'] }
        }
      },
      {
        $group: {
          _id: '$userId',
          count: { $sum: 1 },
          module: { $first: '$module' }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$_id',
          name: '$user.name',
          count: 1,
          module: 1
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    res.json({
      success: true,
      data: {
        topPerformers,
        debug: {
          startDate,
          days,
          totalAuditLogs: await Audit.countDocuments(),
          auditLogsWithUsers: await Audit.countDocuments({ userId: { $ne: null } })
        }
      }
    });
  } catch (error) {
    logger.error('Error in debug endpoint:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch debug data',
      error: error.message
    });
  }
});

// Get system statistics (admin only)
router.get('/stats', protect, authorize('admin'), async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // User statistics
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ status: 'active' });
    const newUsers = await User.countDocuments({ createdAt: { $gte: startDate } });

    // PAN KYC statistics
    const panKycStats = await PanKyc.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    // Aadhaar-PAN statistics
    const aadhaarPanStats = await AadhaarPan.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    // Activity statistics
    const activityStats = await Audit.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      {
        $group: {
          _id: '$action',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // Daily activity for the last 7 days
    const dailyActivity = await Audit.aggregate([
      {
        $match: {
          createdAt: {
            $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
          }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // User performance data
    const topPerformers = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
          userId: { $ne: null },
          action: { $in: ['pan_kyc_upload', 'aadhaar_pan_upload', 'file_uploaded'] }
        }
      },
      {
        $group: {
          _id: '$userId',
          count: { $sum: 1 },
          module: { $first: '$module' }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$_id',
          name: '$user.name',
          count: 1,
          module: 1
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // Recent user activity
    const recentActivity = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
          userId: { $ne: null }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'userId',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$userId',
          name: '$user.name',
          action: 1,
          timestamp: '$createdAt'
        }
      },
      { $sort: { timestamp: -1 } },
      { $limit: 10 }
    ]);

    // User engagement data
    const userEngagement = await Audit.aggregate([
      {
        $match: {
          action: 'login',
          userId: { $ne: null }
        }
      },
      {
        $group: {
          _id: '$userId',
          loginCount: { $sum: 1 },
          lastLogin: { $max: '$createdAt' }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$_id',
          name: '$user.name',
          loginCount: 1,
          lastLogin: 1
        }
      },
      { $sort: { loginCount: -1 } },
      { $limit: 10 }
    ]);

    // API usage data
    const apiUsage = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: null,
          totalHits: { $sum: 1 },
          uniqueUsers: { $addToSet: '$userId' }
        }
      },
      {
        $project: {
          totalHits: 1,
          uniqueUsers: { $size: '$uniqueUsers' }
        }
      }
    ]);

    const topApiEndpoints = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$module',
          hits: { $sum: 1 },
          users: { $addToSet: '$userId' }
        }
      },
      {
        $project: {
          endpoint: '$_id',
          hits: 1,
          users: { $size: '$users' }
        }
      },
      { $sort: { hits: -1 } },
      { $limit: 10 }
    ]);

    const userApiHits = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
          userId: { $ne: null }
        }
      },
      {
        $group: {
          _id: '$userId',
          totalHits: { $sum: 1 },
          endpoints: {
            $push: {
              endpoint: '$module',
              hits: 1,
              lastUsed: '$createdAt'
            }
          },
          modules: {
            $push: {
              module: '$module',
              hits: 1
            }
          },
          sandboxApiCalls: {
            $sum: {
              $cond: [
                { $in: ['$action', ['pan_kyc_api_call', 'aadhaar_pan_api_call']] },
                1,
                0
              ]
            }
          },
          successfulApiCalls: {
            $sum: {
              $cond: [
                { $and: [
                  { $in: ['$action', ['pan_kyc_api_call', 'aadhaar_pan_api_call']] },
                  { $eq: ['$status', 'success'] }
                ]},
                1,
                0
              ]
            }
          },
          failedApiCalls: {
            $sum: {
              $cond: [
                { $and: [
                  { $in: ['$action', ['pan_kyc_api_call', 'aadhaar_pan_api_call']] },
                  { $eq: ['$status', 'failed'] }
                ]},
                1,
                0
              ]
            }
          }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$_id',
          name: '$user.name',
          email: '$user.email',
          totalHits: 1,
          sandboxApiCalls: 1,
          successfulApiCalls: 1,
          failedApiCalls: 1,
          successRate: {
            $cond: [
              { $gt: ['$sandboxApiCalls', 0] },
              { $multiply: [{ $divide: ['$successfulApiCalls', '$sandboxApiCalls'] }, 100] },
              0
            ]
          },
          endpoints: 1,
          modules: 1,
          hourlyDistribution: [],
          dailyDistribution: []
        }
      },
      { $sort: { sandboxApiCalls: -1, totalHits: -1 } },
      { $limit: 10 }
    ]);

    const moduleUsage = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$module',
          totalHits: { $sum: 1 },
          uniqueUsers: { $addToSet: '$userId' }
        }
      },
      {
        $project: {
          module: '$_id',
          totalHits: 1,
          uniqueUsers: { $size: '$uniqueUsers' },
          avgHitsPerUser: {
            $divide: ['$totalHits', { $size: '$uniqueUsers' }]
          }
        }
      },
      { $sort: { totalHits: -1 } }
    ]);

    const peakUsageHours = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            hour: { $hour: '$createdAt' }
          },
          hits: { $sum: 1 },
          users: { $addToSet: '$userId' }
        }
      },
      {
        $project: {
          hour: '$_id.hour',
          hits: 1,
          users: { $size: '$users' }
        }
      },
      { $sort: { hits: -1 } },
      { $limit: 10 }
    ]);

    const apiPerformance = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$module',
          totalRequests: { $sum: 1 },
          successfulRequests: {
            $sum: {
              $cond: [{ $eq: ['$status', 'success'] }, 1, 0]
            }
          },
          failedRequests: {
            $sum: {
              $cond: [{ $eq: ['$status', 'failed'] }, 1, 0]
            }
          }
        }
      },
      {
        $project: {
          endpoint: '$_id',
          avgResponseTime: 1000, // Mock response time
          successRate: {
            $multiply: [
              { $divide: ['$successfulRequests', '$totalRequests'] },
              100
            ]
          },
          errorRate: {
            $multiply: [
              { $divide: ['$failedRequests', '$totalRequests'] },
              100
            ]
          }
        }
      },
      { $limit: 10 }
    ]);

    // PAN KYC user-wise data
    const panKycUserWise = await Audit.aggregate([
      {
        $match: {
          $or: [
            { action: 'pan_kyc_upload' },
            { action: 'pan_kyc_api_call' },
            { action: 'pan_kyc_verification' },
            { $and: [{ action: 'record_verified' }, { module: 'pan_kyc' }] },
            { $and: [{ action: 'record_rejected' }, { module: 'pan_kyc' }] }
          ],
          userId: { $ne: null }
        }
      },
      {
        $group: {
          _id: '$userId',
          totalActivities: { $sum: 1 },
          uploads: {
            $sum: { $cond: [{ $eq: ['$action', 'pan_kyc_upload'] }, 1, 0] }
          },
          apiCalls: {
            $sum: { 
              $cond: [
                { $and: [
                  { $or: [
                    { $eq: ['$action', 'pan_kyc_api_call'] },
                    { $eq: ['$action', 'pan_kyc_verification'] },
                    { $and: [
                      { $eq: ['$action', 'record_verified'] },
                      { $eq: ['$module', 'pan_kyc'] }
                    ]},
                    { $and: [
                      { $eq: ['$action', 'record_rejected'] },
                      { $eq: ['$module', 'pan_kyc'] }
                    ]}
                  ]},
                  { $ne: ['$action', 'pan_kyc_upload'] }
                ]}, 
                1, 
                0
              ]
            }
          },
          successfulApiCalls: {
            $sum: {
              $cond: [
                { $and: [
                  { $or: [
                    { $eq: ['$action', 'pan_kyc_api_call'] },
                    { $eq: ['$action', 'pan_kyc_verification'] },
                    { $and: [
                      { $eq: ['$action', 'record_verified'] },
                      { $eq: ['$module', 'pan_kyc'] }
                    ]}
                  ]},
                  { $ne: ['$action', 'pan_kyc_upload'] },
                  { $eq: ['$status', 'success'] }
                ]},
                1,
                0
              ]
            }
          },
          failedApiCalls: {
            $sum: {
              $cond: [
                { $and: [
                  { $or: [
                    { $eq: ['$action', 'pan_kyc_api_call'] },
                    { $eq: ['$action', 'pan_kyc_verification'] },
                    { $and: [
                      { $eq: ['$action', 'record_verified'] },
                      { $eq: ['$module', 'pan_kyc'] }
                    ]},
                    { $and: [
                      { $eq: ['$action', 'record_rejected'] },
                      { $eq: ['$module', 'pan_kyc'] }
                    ]}
                  ]},
                  { $ne: ['$action', 'pan_kyc_upload'] },
                  { $or: [
                    { $eq: ['$status', 'failed'] },
                    { $eq: ['$action', 'record_rejected'] }
                  ]}
                ]},
                1,
                0
              ]
            }
          }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$_id',
          name: '$user.name',
          email: '$user.email',
          totalActivities: 1,
          uploads: 1,
          apiCalls: 1,
          successfulApiCalls: 1,
          failedApiCalls: 1,
          successRate: {
            $cond: [
              { $gt: ['$apiCalls', 0] },
              { $multiply: [{ $divide: ['$successfulApiCalls', '$apiCalls'] }, 100] },
              0
            ]
          }
        }
      },
      { $sort: { totalActivities: -1 } },
      { $limit: 10 }
    ]);

    // Aadhaar PAN user-wise data
    const aadhaarPanUserWise = await Audit.aggregate([
      {
        $match: {
          $or: [
            { action: 'aadhaar_pan_upload' },
            { action: 'aadhaar_pan_api_call' },
            { $and: [{ action: 'record_verified' }, { module: 'aadhaar_pan' }] },
            { $and: [{ action: 'record_rejected' }, { module: 'aadhaar_pan' }] }
          ],
          userId: { $ne: null }
        }
      },
      {
        $group: {
          _id: '$userId',
          totalActivities: { $sum: 1 },
          uploads: {
            $sum: { $cond: [{ $eq: ['$action', 'aadhaar_pan_upload'] }, 1, 0] }
          },
          apiCalls: {
            $sum: { 
              $cond: [
                { $and: [
                  { $or: [
                    { $eq: ['$action', 'aadhaar_pan_api_call'] },
                    { $and: [
                      { $eq: ['$action', 'record_verified'] },
                      { $eq: ['$module', 'aadhaar_pan'] }
                    ]},
                    { $and: [
                      { $eq: ['$action', 'record_rejected'] },
                      { $eq: ['$module', 'aadhaar_pan'] }
                    ]}
                  ]},
                  { $ne: ['$action', 'aadhaar_pan_upload'] }
                ]}, 
                1, 
                0
              ]
            }
          },
          successfulApiCalls: {
            $sum: {
              $cond: [
                { $and: [
                  { $or: [
                    { $eq: ['$action', 'aadhaar_pan_api_call'] },
                    { $and: [
                      { $eq: ['$action', 'record_verified'] },
                      { $eq: ['$module', 'aadhaar_pan'] }
                    ]}
                  ]},
                  { $ne: ['$action', 'aadhaar_pan_upload'] },
                  { $eq: ['$status', 'success'] }
                ]},
                1,
                0
              ]
            }
          },
          failedApiCalls: {
            $sum: {
              $cond: [
                { $and: [
                  { $or: [
                    { $eq: ['$action', 'aadhaar_pan_api_call'] },
                    { $and: [
                      { $eq: ['$action', 'record_verified'] },
                      { $eq: ['$module', 'aadhaar_pan'] }
                    ]},
                    { $and: [
                      { $eq: ['$action', 'record_rejected'] },
                      { $eq: ['$module', 'aadhaar_pan'] }
                    ]}
                  ]},
                  { $ne: ['$action', 'aadhaar_pan_upload'] },
                  { $or: [
                    { $eq: ['$status', 'failed'] },
                    { $eq: ['$action', 'record_rejected'] }
                  ]}
                ]},
                1,
                0
              ]
            }
          }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$_id',
          name: '$user.name',
          email: '$user.email',
          totalActivities: 1,
          uploads: 1,
          apiCalls: 1,
          successfulApiCalls: 1,
          failedApiCalls: 1,
          successRate: {
            $cond: [
              { $gt: ['$apiCalls', 0] },
              { $multiply: [{ $divide: ['$successfulApiCalls', '$apiCalls'] }, 100] },
              0
            ]
          }
        }
      },
      { $sort: { totalActivities: -1 } },
      { $limit: 10 }
    ]);

    res.json({
      success: true,
      data: {
        users: {
          total: totalUsers,
          active: activeUsers,
          new: newUsers,
          inactive: totalUsers - activeUsers,
          suspended: await User.countDocuments({ status: 'suspended' }),
          premium: 0, // Mock data
          basic: totalUsers,
          lastActive: [],
          roleDistribution: await User.aggregate([
            { $group: { _id: '$role', count: { $sum: 1 } } }
          ]),
          moduleAccessStats: []
        },
        panKyc: panKycStats,
        aadhaarPan: aadhaarPanStats,
        activity: activityStats,
        dailyActivity,
        userPerformance: {
          topPerformers,
          recentActivity,
          userEngagement
        },
        apiUsage: {
          totalHits: apiUsage[0]?.totalHits || 0,
          uniqueUsers: apiUsage[0]?.uniqueUsers || 0,
          topApiEndpoints,
          userApiHits,
          moduleUsage,
          peakUsageHours,
          apiPerformance,
          panKycUserWise,
          aadhaarPanUserWise
        }
      }
    });
  } catch (error) {
    logger.error('Error fetching system stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch system statistics'
    });
  }
});

// Get user statistics (admin only)
router.get('/user-stats', protect, authorize('admin'), async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // User registration stats
    const userRegistrationStats = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // User role distribution
    const roleDistribution = await User.aggregate([
      {
        $group: {
          _id: '$role',
          count: { $sum: 1 }
        }
      }
    ]);

    // User status distribution
    const statusDistribution = await User.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    // Recent user activity
    const recentUserActivity = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
          module: { $in: ['auth', 'user_management'] }
        }
      },
      {
        $group: {
          _id: {
            action: '$action',
            date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.date': -1, count: -1 } },
      { $limit: 20 }
    ]);

    res.json({
      success: true,
      data: {
        userRegistration: userRegistrationStats,
        roleDistribution,
        statusDistribution,
        recentActivity: recentUserActivity
      }
    });
  } catch (error) {
    logger.error('Error fetching user stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user statistics'
    });
  }
});

// Get API usage statistics (admin only)
router.get('/api-usage-stats', protect, authorize('admin'), async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // API endpoint usage
    const apiUsage = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
          module: { $ne: null }
        }
      },
      {
        $group: {
          _id: {
            module: '$module',
            action: '$action'
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Daily API usage
    const dailyApiUsage = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // Hourly API usage for today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const hourlyApiUsage = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: today }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%H:00", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // Top users by API usage
    const topUsersByUsage = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
          userId: { $ne: null }
        }
      },
      {
        $group: {
          _id: '$userId',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$_id',
          email: '$user.email',
          name: '$user.name',
          count: 1
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        apiUsage,
        dailyUsage: dailyApiUsage,
        hourlyUsage: hourlyApiUsage,
        topUsers: topUsersByUsage
      }
    });
  } catch (error) {
    logger.error('Error fetching API usage stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch API usage statistics'
    });
  }
});

// Get system health (admin only)
router.get('/health', protect, authorize('admin'), async (req, res) => {
  try {
    const health = {
      status: 'healthy',
      timestamp: new Date(),
      services: {
        database: 'connected',
        fileSystem: 'accessible',
        memory: process.memoryUsage(),
        uptime: process.uptime()
      }
    };

    // Check database connection
    try {
      await User.findOne().limit(1);
      health.services.database = 'connected';
    } catch (error) {
      health.services.database = 'disconnected';
      health.status = 'degraded';
    }

    // Check file system
    try {
      const fs = require('fs');
      const path = require('path');
      const uploadDir = path.join(__dirname, '../../uploads');
      fs.accessSync(uploadDir, fs.constants.W_OK);
      health.services.fileSystem = 'accessible';
    } catch (error) {
      health.services.fileSystem = 'inaccessible';
      health.status = 'degraded';
    }

    res.json({
      success: true,
      data: health
    });
  } catch (error) {
    logger.error('Error checking system health:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check system health'
    });
  }
});

// Get system settings (admin only)
router.get('/settings', protect, authorize('admin'), async (req, res) => {
  try {
    const settings = {
      environment: process.env.NODE_ENV,
      apiVersion: '1.0.0',
      features: {
        panKyc: true,
        aadhaarPan: true,
        auditLogging: true,
        fileUpload: true,
        emailNotifications: !!process.env.EMAIL_SERVICE,
        twoFactorAuth: true
      },
      limits: {
        maxFileSize: '10MB',
        maxRecordsPerBatch: 1000,
        apiRateLimit: '100 requests per minute'
      }
    };

    res.json({
      success: true,
      data: settings
    });
  } catch (error) {
    logger.error('Error fetching system settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch system settings'
    });
  }
});

// Update user module access (admin only)
router.patch('/users/:id/module-access', protect, authorize('admin'), async (req, res) => {
  try {
    const { moduleAccess } = req.body;
    
    if (!moduleAccess || !Array.isArray(moduleAccess)) {
      return res.status(400).json({
        success: false,
        message: 'moduleAccess must be an array'
      });
    }

    // Validate module names
    const validModules = ['pan-kyc', 'aadhaar-pan', 'aadhaar-verification', 'selfie-upload', 'qr-code'];
    const invalidModules = moduleAccess.filter(module => !validModules.includes(module));
    
    if (invalidModules.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Invalid modules: ${invalidModules.join(', ')}. Valid modules are: ${validModules.join(', ')}`
      });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Store old module access for audit
    const oldModuleAccess = user.moduleAccess;

    // Update module access
    user.moduleAccess = moduleAccess;
    await user.save();

    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'module_access_updated',
      module: 'admin',
      resource: 'user',
      resourceId: user._id,
      details: {
        targetUserEmail: user.email,
        oldModuleAccess,
        newModuleAccess: moduleAccess
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'User module access updated successfully',
      data: {
        id: user._id,
        email: user.email,
        moduleAccess: user.moduleAccess
      }
    });
  } catch (error) {
    logger.error('Error updating user module access:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user module access'
    });
  }
});

// Get available modules (admin only)
router.get('/modules', protect, authorize('admin'), async (req, res) => {
  try {
    const modules = [
      {
        id: 'pan-kyc',
        name: 'PAN KYC',
        description: 'PAN verification and KYC processing',
        features: ['File upload', 'Batch processing', 'Verification', 'Reports']
      },
      {
        id: 'aadhaar-pan',
        name: 'Aadhaar-PAN Linking',
        description: 'Aadhaar and PAN number linking verification',
        features: ['File upload', 'Single verification', 'Batch processing', 'Reports']
      }
    ];

    res.json({
      success: true,
      data: modules
    });
  } catch (error) {
    logger.error('Error fetching modules:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch modules'
    });
  }
});

// Update user branding (admin only)
router.patch('/users/:id/branding', protect, authorize('admin'), async (req, res) => {
  try {
    const { companyName, displayName, address, gstNumber } = req.body;

    if (!companyName && !displayName && !address && !gstNumber) {
      return res.status(400).json({
        success: false,
        message: 'At least one branding field must be provided'
      });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Store old branding for audit
    const oldBranding = {
      companyName: user.branding?.companyName || '',
      displayName: user.branding?.displayName || '',
      address: user.branding?.address || '',
      gstNumber: user.branding?.gstNumber || ''
    };

    console.log('🔍 DEBUG: Request body:', JSON.stringify(req.body, null, 2));
    console.log('🔍 DEBUG: Original user.branding:', JSON.stringify(user.branding, null, 2));

    // Build update object
    const updateData = {};
    if (companyName !== undefined) updateData['branding.companyName'] = companyName;
    if (displayName !== undefined) updateData['branding.displayName'] = displayName;
    if (address !== undefined) updateData['branding.address'] = address;
    if (gstNumber !== undefined) updateData['branding.gstNumber'] = gstNumber;

    console.log('🔍 DEBUG: Update data:', JSON.stringify(updateData, null, 2));

    // Use findByIdAndUpdate for more reliable updates
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updateData },
      { new: true, runValidators: true }
    );

    console.log('🔍 DEBUG: Updated user.branding:', JSON.stringify(updatedUser.branding, null, 2));

    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'user_branding_updated',
      module: 'admin',
      resource: 'user',
      resourceId: user._id,
      details: {
        targetUserEmail: user.email,
        oldBranding,
        newBranding: {
          companyName: updatedUser.branding.companyName,
          displayName: updatedUser.branding.displayName,
          address: updatedUser.branding.address,
          gstNumber: updatedUser.branding.gstNumber
        }
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    console.log('🔍 DEBUG: Response branding:', JSON.stringify(updatedUser.branding, null, 2));
    
    res.json({
      success: true,
      message: 'User branding updated successfully',
      data: {
        id: updatedUser._id,
        email: updatedUser.email,
        branding: updatedUser.branding
      }
    });
  } catch (error) {
    logger.error('Error updating user branding:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user branding'
    });
  }
});

// Upload user logo (admin only)
router.post('/users/:id/logo', protect, authorize('admin'), upload.single('logo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No logo file provided'
      });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Store old logo info for audit
    const oldLogo = user.branding?.logo || null;

    // Update logo information
    // Store relative path from backend directory for consistency
    if (!user.branding) user.branding = {};
    const backendDir = path.join(__dirname, '..', '..');
    const relativePath = path.relative(backendDir, req.file.path);
    user.branding.logo = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      path: relativePath.replace(/\\/g, '/'), // Normalize path separators to forward slashes
      mimetype: req.file.mimetype,
      size: req.file.size
    };

    await user.save();

    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'user_logo_updated',
      module: 'admin',
      resource: 'user',
      resourceId: user._id,
      details: {
        targetUserEmail: user.email,
        oldLogo: oldLogo ? oldLogo.filename : null,
        newLogo: req.file.filename
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'User logo updated successfully',
      data: {
        id: user._id,
        email: user.email,
        logo: user.branding.logo
      }
    });
  } catch (error) {
    logger.error('Error updating user logo:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user logo'
      });
  }
});

// Test endpoint to check if branding fields can be saved
router.post('/test-branding/:id', protect, authorize('admin'), async (req, res) => {
  try {
    console.log('🧪 TEST: Testing branding save...');
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    console.log('🧪 TEST: Original branding:', JSON.stringify(user.branding, null, 2));

    // Try to save a simple test value
    const testResult = await User.findByIdAndUpdate(
      req.params.id,
      { 
        $set: { 
          'branding.testField': 'test-value',
          'branding.address': 'test address',
          'branding.gstNumber': 'test-gst'
        } 
      },
      { new: true, runValidators: true }
    );

    console.log('🧪 TEST: After update:', JSON.stringify(testResult.branding, null, 2));

    res.json({
      success: true,
      message: 'Test completed',
      data: {
        original: user.branding,
        updated: testResult.branding
      }
    });
  } catch (error) {
    console.error('🧪 TEST: Error:', error);
    res.status(500).json({
      success: false,
      message: 'Test failed',
      error: error.message
    });
  }
});

// Get user logo (public endpoint)
router.get('/users/:id/logo', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || !user.branding?.logo) {
      logger.warn(`Logo request for user ${req.params.id}: User or branding not found`);
      return res.status(404).json({
        success: false,
        message: 'Logo not found'
      });
    }

    const logoPath = user.branding.logo.path;
    logger.info(`Logo request for user ${req.params.id}: stored path = ${logoPath}, filename = ${user.branding.logo.filename}`);
    
    // Check if logo path exists
    if (!logoPath) {
      logger.warn(`Logo path not found for user ${req.params.id}`);
      return res.status(404).json({
        success: false,
        message: 'Logo path not found'
      });
    }
    
    // Resolve the absolute path - path is stored as relative like 'uploads/logos/logo-xxx.jpg'
    // Route file is at backend/src/routes/admin.js, so we need to go up 2 levels to reach backend/
    // Normalize path separators first (handle both forward slashes and backslashes)
    const normalizedPath = logoPath.replace(/\\/g, '/');
    let absolutePath = path.resolve(__dirname, '..', '..', normalizedPath);
    logger.info(`Logo path resolution for user ${req.params.id}: normalized = ${normalizedPath}, absolute = ${absolutePath}`);
    
    // Check if file exists
    if (!fs.existsSync(absolutePath)) {
      logger.warn(`Logo file not found at primary path: ${absolutePath}`);
      // Fallback: Try to find the logo by filename if path doesn't work
      // This handles cases where the path format changed or files were moved
      const filename = user.branding.logo.filename;
      const logosDir = path.join(__dirname, '..', '..', 'uploads', 'logos');
      
      if (filename) {
        // First try exact filename match
        const fallbackPath = path.join(logosDir, filename);
        if (fs.existsSync(fallbackPath)) {
          logger.info(`Using fallback path for logo: ${fallbackPath} for user ${req.params.id}`);
          absolutePath = fallbackPath;
          // Update the stored path for future requests
          user.branding.logo.path = `uploads/logos/${filename}`;
          await user.save().catch(err => logger.error('Failed to update logo path:', err));
        } else {
          // Last resort: Try to find any logo file in the directory
          // This handles cases where the file was renamed or replaced
          try {
            if (fs.existsSync(logosDir)) {
              const files = fs.readdirSync(logosDir).filter(file => 
                file.toLowerCase().endsWith('.jpg') || 
                file.toLowerCase().endsWith('.jpeg') || 
                file.toLowerCase().endsWith('.png') ||
                file.toLowerCase().endsWith('.gif')
              );
              
              if (files.length > 0) {
                // Use the most recent logo file (by filename timestamp if available, or just the first one)
                const latestFile = files.sort().pop();
                const latestPath = path.join(logosDir, latestFile);
                logger.info(`Using alternative logo file: ${latestPath} for user ${req.params.id}`);
                absolutePath = latestPath;
                // Update the stored path and filename in database
                user.branding.logo.path = `uploads/logos/${latestFile}`;
                user.branding.logo.filename = latestFile;
                await user.save().catch(err => logger.error('Failed to update logo path:', err));
              } else {
                logger.warn(`No logo files found in ${logosDir} for user ${req.params.id}`);
                return res.status(404).json({
                  success: false,
                  message: 'Logo file not found on server'
                });
              }
            } else {
              logger.warn(`Logo directory does not exist: ${logosDir} for user ${req.params.id}`);
              return res.status(404).json({
                success: false,
                message: 'Logo file not found on server'
              });
            }
          } catch (err) {
            logger.error(`Error searching for logo files: ${err.message}`);
            return res.status(404).json({
              success: false,
              message: 'Logo file not found on server'
            });
          }
        }
      } else {
        logger.warn(`Logo file not found: ${absolutePath} for user ${req.params.id}`);
        return res.status(404).json({
          success: false,
          message: 'Logo file not found on server'
        });
      }
    }
    
    // Set CORS headers for image serving
    res.set({
      'Access-Control-Allow-Origin': getAllowedOrigin(req.headers.origin),
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'GET',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Cross-Origin-Embedder-Policy': 'unsafe-none'
    });
    
    res.sendFile(absolutePath);
  } catch (error) {
    logger.error('Error serving user logo:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to serve logo'
    });
  }
});

// ==================== ARCHIVAL MANAGEMENT ROUTES ====================

// Get archival configuration
router.get('/archival/config', protect, authorize('admin'), async (req, res) => {
  try {
    const archivalService = require('../services/archivalService');
    const config = await archivalService.getArchivalStats();
    
    res.json({
      success: true,
      data: config
    });
  } catch (error) {
    logger.error('Error getting archival config:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get archival configuration',
      error: error.message
    });
  }
});

// Update archival configuration
router.put('/archival/config', protect, authorize('admin'), async (req, res) => {
  try {
    const { globalSettings, moduleSettings } = req.body;
    const ArchivalConfig = require('../models/ArchivalConfig');
    
    const config = await ArchivalConfig.getConfig();
    
    if (globalSettings) {
      config.globalSettings = { ...config.globalSettings, ...globalSettings };
    }
    
    if (moduleSettings) {
      if (moduleSettings.panKyc) {
        config.moduleSettings.panKyc = { ...config.moduleSettings.panKyc, ...moduleSettings.panKyc };
      }
      if (moduleSettings.aadhaarPan) {
        config.moduleSettings.aadhaarPan = { ...config.moduleSettings.aadhaarPan, ...moduleSettings.aadhaarPan };
      }
    }
    
    config.updatedBy = req.user.id;
    await config.save();
    
    logger.info(`Archival configuration updated by admin ${req.user.id}`);
    
    res.json({
      success: true,
      message: 'Archival configuration updated successfully',
      data: config
    });
  } catch (error) {
    logger.error('Error updating archival config:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update archival configuration',
      error: error.message
    });
  }
});

// Get archival statistics
router.get('/archival/stats', protect, authorize('admin'), async (req, res) => {
  try {
    const archivalService = require('../services/archivalService');
    const stats = await archivalService.getArchivalStats();
    
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Error getting archival stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get archival statistics',
      error: error.message
    });
  }
});

// Manually trigger archival process
router.post('/archival/trigger', protect, authorize('admin'), async (req, res) => {
  try {
    const archivalService = require('../services/archivalService');
    
    // Run archival process in background
    archivalService.runArchivalProcess().catch(error => {
      logger.error('Background archival process failed:', error);
    });
    
    logger.info(`Archival process manually triggered by admin ${req.user.id}`);
    
    res.json({
      success: true,
      message: 'Archival process triggered successfully'
    });
  } catch (error) {
    logger.error('Error triggering archival process:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to trigger archival process',
      error: error.message
    });
  }
});

// Get records marked for deletion
router.get('/archival/records/marked-for-deletion', protect, authorize('admin'), async (req, res) => {
  try {
    const { module, page = 1, limit = 20, userId } = req.query;
    const PanKyc = require('../models/PanKyc');
    const AadhaarPan = require('../models/AadhaarPan');
    
    const Model = module === 'aadhaarPan' ? AadhaarPan : PanKyc;
    const skip = (page - 1) * limit;
    
    const query = {
      'archival.isMarkedForDeletion': true,
      'archival.actualDeletionDate': { $exists: false }
    };
    
    if (userId) {
      query.userId = userId;
    }
    
    const records = await Model.find(query)
      .populate('userId', 'email firstName lastName')
      .sort({ 'archival.scheduledDeletionDate': 1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Model.countDocuments(query);
    
    res.json({
      success: true,
      data: {
        records,
        pagination: {
          current: parseInt(page),
          pages: Math.ceil(total / limit),
          total,
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    logger.error('Error getting records marked for deletion:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get records marked for deletion',
      error: error.message
    });
  }
});

// Manually delete a record
router.delete('/archival/records/:recordId', protect, authorize('admin'), async (req, res) => {
  try {
    const { recordId } = req.params;
    const { module, reason = 'manual' } = req.body;
    
    if (!module || !['panKyc', 'aadhaarPan'].includes(module)) {
      return res.status(400).json({
        success: false,
        message: 'Module must be specified and be either panKyc or aadhaarPan'
      });
    }
    
    const archivalService = require('../services/archivalService');
    const result = await archivalService.manualDeleteRecord(recordId, req.user.id, module, reason);
    
    logger.info(`Record ${recordId} manually deleted by admin ${req.user.id}`);
    
    res.json({
      success: true,
      message: result.message
    });
  } catch (error) {
    logger.error('Error manually deleting record:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete record',
      error: error.message
    });
  }
});

// ==================== USER-SPECIFIC ARCHIVAL MANAGEMENT ====================

// Get user-specific archival settings
router.get('/archival/users/:userId/settings', protect, authorize('admin'), async (req, res) => {
  try {
    const { userId } = req.params;
    const archivalService = require('../services/archivalService');
    
    const settings = await archivalService.getUserArchivalSettings(userId);
    
    res.json({
      success: true,
      data: settings
    });
  } catch (error) {
    logger.error('Error getting user archival settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user archival settings',
      error: error.message
    });
  }
});

// Set user-specific archival settings
router.put('/archival/users/:userId/settings', protect, authorize('admin'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { module, settings } = req.body;
    
    if (!module || !['panKyc', 'aadhaarPan'].includes(module)) {
      return res.status(400).json({
        success: false,
        message: 'Module must be specified and be either panKyc or aadhaarPan'
      });
    }
    
    const archivalService = require('../services/archivalService');
    const result = await archivalService.setUserArchivalSettings(userId, module, settings, req.user.id);
    
    logger.info(`User archival settings updated for user ${userId} by admin ${req.user.id}`);
    
    res.json({
      success: true,
      message: result.message
    });
  } catch (error) {
    logger.error('Error setting user archival settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to set user archival settings',
      error: error.message
    });
  }
});

// Remove user-specific archival settings
router.delete('/archival/users/:userId/settings', protect, authorize('admin'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { module } = req.body;
    
    if (!module || !['panKyc', 'aadhaarPan'].includes(module)) {
      return res.status(400).json({
        success: false,
        message: 'Module must be specified and be either panKyc or aadhaarPan'
      });
    }
    
    const archivalService = require('../services/archivalService');
    const result = await archivalService.removeUserArchivalSettings(userId, module, req.user.id);
    
    logger.info(`User archival settings removed for user ${userId} by admin ${req.user.id}`);
    
    res.json({
      success: true,
      message: result.message
    });
  } catch (error) {
    logger.error('Error removing user archival settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove user archival settings',
      error: error.message
    });
  }
});

// Get user's records marked for deletion
router.get('/archival/users/:userId/records', protect, authorize('admin'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { module, page = 1, limit = 20 } = req.query;
    
    if (!module || !['panKyc', 'aadhaarPan'].includes(module)) {
      return res.status(400).json({
        success: false,
        message: 'Module must be specified and be either panKyc or aadhaarPan'
      });
    }
    
    const archivalService = require('../services/archivalService');
    const result = await archivalService.getUserRecordsMarkedForDeletion(userId, module, page, limit);
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    logger.error('Error getting user records marked for deletion:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user records marked for deletion',
      error: error.message
    });
  }
});

// Get all users with their archival settings
router.get('/archival/users', protect, authorize('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 20, search } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    
    const users = await User.find(query)
      .select('_id email name firstName lastName createdAt')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await User.countDocuments(query);
    
    // Get archival settings for each user
    const archivalService = require('../services/archivalService');
    const usersWithSettings = await Promise.all(
      users.map(async (user) => {
        try {
          const settings = await archivalService.getUserArchivalSettings(user._id);
          return {
            ...user.toObject(),
            archivalSettings: settings
          };
        } catch (error) {
          logger.error(`Error getting archival settings for user ${user._id}:`, error);
          return {
            ...user.toObject(),
            archivalSettings: null
          };
        }
      })
    );
    
    res.json({
      success: true,
      data: {
        users: usersWithSettings,
        pagination: {
          current: parseInt(page),
          pages: Math.ceil(total / limit),
          total,
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    logger.error('Error getting users with archival settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get users with archival settings',
      error: error.message
    });
  }
});

// ==================== SCHEDULER MANAGEMENT ====================

// Get scheduler status
router.get('/archival/scheduler/status', protect, authorize('admin'), async (req, res) => {
  try {
    const schedulerService = require('../services/schedulerService');
    const status = await schedulerService.getStatus();
    
    res.json({
      success: true,
      data: status
    });
  } catch (error) {
    logger.error('Error getting scheduler status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get scheduler status',
      error: error.message
    });
  }
});

// Start/stop scheduler jobs
router.post('/archival/scheduler/:action/:jobName', protect, authorize('admin'), async (req, res) => {
  try {
    const { action, jobName } = req.params;
    const schedulerService = require('../services/schedulerService');
    
    if (!['start', 'stop', 'restart'].includes(action)) {
      return res.status(400).json({
        success: false,
        message: 'Action must be start, stop, or restart'
      });
    }
    
    let result;
    switch (action) {
      case 'start':
        result = await schedulerService.startJob(jobName);
        break;
      case 'stop':
        result = await schedulerService.stopJob(jobName);
        break;
      case 'restart':
        result = await schedulerService.restartJob(jobName);
        break;
    }
    
    logger.info(`Scheduler job ${jobName} ${action}ed by admin ${req.user.id}`);
    
    res.json({
      success: true,
      message: result.message,
      data: result
    });
  } catch (error) {
    logger.error('Error managing scheduler job:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to manage scheduler job',
      error: error.message
    });
  }
});

// Generate or get QR code for a user (admin only)
router.get('/users/:id/qr-code', protect, authorize('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
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
        message: 'QR code module is not enabled for this user'
      });
    }

    // Generate QR code if it doesn't exist or regenerate if requested
    if (!user.qrCode || !user.qrCode.code || req.query.regenerate === 'true') {
      // Generate unique QR code
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

      await logEvent({
        userId: req.user.id,
        action: 'qr_code_generated',
        module: 'admin',
        resource: 'user',
        resourceId: user._id,
        details: `Generated QR code for user: ${user.email}`,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      return res.json({
        success: true,
        data: {
          qrCode: qrCodeDataUrl,
          qrCodeUrl: qrCodeUrl,
          qrCodeString: qrCodeString,
          user: {
            id: user._id,
            email: user.email,
            name: user.name
          }
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
        qrCodeString: user.qrCode.code,
        user: {
          id: user._id,
          email: user.email,
          name: user.name
        }
      }
    });
  } catch (error) {
    logger.error('Error generating QR code:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate QR code',
      error: error.message
    });
  }
});

// Get user by QR code (public endpoint for verification)
router.get('/qr/:code', async (req, res) => {
  try {
    const user = await User.findOne({ 'qrCode.code': req.params.code, 'qrCode.isActive': true });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Invalid or inactive QR code'
      });
    }

    // Check if user has qr-code module access
    if (!user.moduleAccess || !user.moduleAccess.includes('qr-code')) {
      return res.status(403).json({
        success: false,
        message: 'QR code module is not enabled for this user'
      });
    }

    res.json({
      success: true,
      data: {
        userId: user._id,
        userName: user.name,
        hasSelfieAccess: user.moduleAccess && user.moduleAccess.includes('selfie-upload')
      }
    });
  } catch (error) {
    logger.error('Error validating QR code:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to validate QR code',
      error: error.message
    });
  }
});

module.exports = router;

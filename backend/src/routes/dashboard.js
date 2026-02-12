const express = require('express');
const router = express.Router();

const { protect } = require('../middleware/auth');
const dashboardController = require('../controllers/dashboardController');

// @route   GET /api/dashboard/stats
// @desc    Get dashboard statistics
// @access  Private
router.get('/stats', protect, dashboardController.getDashboardStats);

// @route   GET /api/dashboard/stats/:module
// @desc    Get module-specific statistics
// @access  Private
router.get('/stats/:module', protect, dashboardController.getModuleStats);

// @route   GET /api/dashboard/recent-activity
// @desc    Get recent activity only
// @access  Private
router.get('/recent-activity', protect, dashboardController.getRecentActivity);

module.exports = router;

const PanKyc = require('../models/PanKyc');
const AadhaarPan = require('../models/AadhaarPan');
const ArchivalConfig = require('../models/ArchivalConfig');
const User = require('../models/User');
const Audit = require('../models/Audit');
const { sendNotificationEmail } = require('./emailService');
const logger = require('../utils/logger');

class ArchivalService {
  constructor() {
    this.isRunning = false;
  }

  /**
   * Run the complete archival process for all modules
   */
  async runArchivalProcess() {
    if (this.isRunning) {
      logger.warn('Archival process is already running, skipping...');
      return;
    }

    this.isRunning = true;
    logger.info('Starting archival process for all modules...');

    try {
      const config = await ArchivalConfig.getConfig();
      
      if (!config.globalSettings.isEnabled) {
        logger.info('Global archival process is disabled, skipping...');
        return;
      }

      const overallStats = {
        panKyc: {
          recordsProcessed: 0,
          warningsSent: 0,
          recordsDeleted: 0,
          errors: 0,
        },
        aadhaarPan: {
          recordsProcessed: 0,
          warningsSent: 0,
          recordsDeleted: 0,
          errors: 0,
        },
      };

      // Process PAN KYC module
      if (config.moduleSettings.panKyc.isEnabled) {
        logger.info('Processing PAN KYC archival...');
        await this.processModuleArchival(config, 'panKyc', PanKyc, overallStats.panKyc);
      } else {
        logger.info('PAN KYC archival is disabled, skipping...');
      }

      // Process Aadhaar-PAN module
      if (config.moduleSettings.aadhaarPan.isEnabled) {
        logger.info('Processing Aadhaar-PAN archival...');
        await this.processModuleArchival(config, 'aadhaarPan', AadhaarPan, overallStats.aadhaarPan);
      } else {
        logger.info('Aadhaar-PAN archival is disabled, skipping...');
      }
      
      // Update configuration with new stats
      await this.updateConfigStats(config, overallStats);
      
      logger.info('Archival process completed successfully', overallStats);
      
      // Log audit event
      await this.logArchivalEvent('archival_process_completed', overallStats);
      
    } catch (error) {
      logger.error('Error in archival process:', error);
      await this.logArchivalEvent('archival_process_failed', { error: error.message });
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Process archival for a specific module
   */
  async processModuleArchival(config, moduleName, Model, stats) {
    try {
      // Step 1: Mark records for deletion and send warnings
      await this.markRecordsForDeletion(config, moduleName, Model, stats);
      
      // Step 2: Delete records that have passed the retention period
      await this.deleteExpiredRecords(config, moduleName, Model, stats);
      
      logger.info(`${moduleName} archival processing completed`, stats);
    } catch (error) {
      logger.error(`Error processing ${moduleName} archival:`, error);
      stats.errors++;
    }
  }

  /**
   * Mark records for deletion and send warning emails for a specific module
   */
  async markRecordsForDeletion(config, moduleName, Model, stats) {
    logger.info(`Marking ${moduleName} records for deletion and sending warnings...`);

    // Get all records that haven't been warned yet
    const recordsToWarn = await Model.find({
      'archival.deletionWarningSent': false,
      'archival.isMarkedForDeletion': false,
    }).populate('userId', 'email firstName lastName');

    logger.info(`Found ${recordsToWarn.length} ${moduleName} records to check for warnings`);

    for (const record of recordsToWarn) {
      try {
        // Check if this record should be warned based on user-specific settings
        const shouldWarn = config.shouldWarn(record.createdAt, record.userId._id, moduleName);
        
        if (shouldWarn) {
          // Mark for deletion
          const deletionDate = config.getDeletionDate(record.createdAt, record.userId._id, moduleName);
          
          await Model.findByIdAndUpdate(record._id, {
            'archival.isMarkedForDeletion': true,
            'archival.scheduledDeletionDate': deletionDate,
            'archival.deletionWarningSent': true,
            'archival.warningSentAt': new Date(),
          });

          // Get user-specific settings for email notifications
          const userSettings = config.getUserModuleSettings(record.userId._id, moduleName);
          
          // Send warning email to user
          if (userSettings.sendEmailNotifications && record.userId && record.userId.email) {
            await this.sendDeletionWarningEmail(record, deletionDate, moduleName);
            stats.warningsSent++;
          }
          
          // Send notification emails to module-specific admin emails
          if (userSettings.sendEmailNotifications && userSettings.notificationEmails && userSettings.notificationEmails.length > 0) {
            await this.sendModuleNotificationEmails(record, deletionDate, moduleName, userSettings.notificationEmails);
            stats.warningsSent += userSettings.notificationEmails.length;
          }

          stats.recordsProcessed++;
          
          // Log individual record warning
          await this.logArchivalEvent('record_marked_for_deletion', {
            recordId: record._id,
            userId: record.userId._id,
            module: moduleName,
            scheduledDeletionDate: deletionDate,
          });
        }

      } catch (error) {
        logger.error(`Error processing ${moduleName} record ${record._id}:`, error);
        stats.errors++;
      }
    }
  }

  /**
   * Delete records that have passed the retention period for a specific module
   */
  async deleteExpiredRecords(config, moduleName, Model, stats) {
    logger.info(`Deleting expired ${moduleName} records...`);

    const now = new Date();
    const recordsToDelete = await Model.find({
      'archival.isMarkedForDeletion': true,
      'archival.scheduledDeletionDate': { $lte: now },
      'archival.actualDeletionDate': { $exists: false }
    }).populate('userId', 'email firstName lastName');

    logger.info(`Found ${recordsToDelete.length} ${moduleName} records to delete`);

    for (const record of recordsToDelete) {
      try {
        // Double-check if record should be deleted based on user-specific settings
        const shouldDelete = config.shouldDelete(record.createdAt, record.userId._id, moduleName);
        
        if (shouldDelete) {
          // Log the deletion before actually deleting
          const userSettings = config.getUserModuleSettings(record.userId._id, moduleName);
          
          await this.logArchivalEvent('record_deleted', {
            recordId: record._id,
            userId: record.userId._id,
            module: moduleName,
            batchId: record.batchId,
            deletionReason: 'retention_policy',
            retentionPeriod: userSettings.retentionPeriodDays,
          });

          // Delete the record
          await Model.findByIdAndDelete(record._id);
          stats.recordsDeleted++;

          // Send deletion confirmation email
          if (userSettings.sendEmailNotifications && record.userId && record.userId.email) {
            await this.sendDeletionConfirmationEmail(record, moduleName);
          }
        } else {
          // Record shouldn't be deleted, unmark it
          await Model.findByIdAndUpdate(record._id, {
            'archival.isMarkedForDeletion': false,
            'archival.scheduledDeletionDate': null,
          });
          
          logger.info(`Unmarked ${moduleName} record ${record._id} - no longer eligible for deletion`);
        }

      } catch (error) {
        logger.error(`Error deleting ${moduleName} record ${record._id}:`, error);
        stats.errors++;
      }
    }
  }

  /**
   * Send deletion warning email to user
   */
  async sendDeletionWarningEmail(record, deletionDate, moduleName) {
    try {
      const user = record.userId;
      const daysUntilDeletion = Math.ceil((deletionDate - new Date()) / (1000 * 60 * 60 * 24));
      
      const moduleDisplayName = moduleName === 'panKyc' ? 'PAN KYC' : 'Aadhaar-PAN';
      const moduleUrl = moduleName === 'panKyc' ? 'pan-kyc' : 'aadhaar-pan';
      
      const subject = `⚠️ Data Deletion Warning - ${moduleDisplayName} Record #${record._id}`;
      const message = `
        <p>Dear ${user.firstName || 'User'},</p>
        
        <p>This is to inform you that your ${moduleDisplayName} verification record will be automatically deleted from our system in <strong>${daysUntilDeletion} days</strong> (on ${deletionDate.toLocaleDateString()}) as per our data retention policy.</p>
        
        <p><strong>Record Details:</strong></p>
        <ul>
          <li>Record ID: ${record._id}</li>
          <li>Batch ID: ${record.batchId}</li>
          <li>Status: ${record.status}</li>
          <li>Created: ${record.createdAt.toLocaleDateString()}</li>
          <li>Scheduled Deletion: ${deletionDate.toLocaleDateString()}</li>
          <li>Module: ${moduleDisplayName}</li>
        </ul>
        
        <p>If you need to retain this data, please download or export it before the deletion date. After deletion, this data cannot be recovered.</p>
        
        <p>This is an automated notification as part of our data retention policy to ensure compliance with data protection regulations.</p>
        
        <p>If you have any questions, please contact our support team.</p>
      `;

      await sendNotificationEmail(user.email, subject, message, {
        actionUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/${moduleUrl}`,
        actionText: `View ${moduleDisplayName} Records`,
        details: {
          recordId: record._id,
          batchId: record.batchId,
          deletionDate: deletionDate.toISOString(),
          daysUntilDeletion,
          module: moduleName
        }
      });

      logger.info(`Deletion warning email sent to ${user.email} for ${moduleName} record ${record._id}`);
    } catch (error) {
      logger.error(`Failed to send deletion warning email for ${moduleName} record ${record._id}:`, error);
    }
  }

  /**
   * Send notification emails to module-specific admin emails
   */
  async sendModuleNotificationEmails(record, deletionDate, moduleName, notificationEmails) {
    try {
      const user = record.userId;
      const daysUntilDeletion = Math.ceil((deletionDate - new Date()) / (1000 * 60 * 60 * 24));
      
      const moduleDisplayName = moduleName === 'panKyc' ? 'PAN KYC' : 'Aadhaar-PAN';
      const moduleUrl = moduleName === 'panKyc' ? 'pan-kyc' : 'aadhaar-pan';
      
      const subject = `📧 Admin Notification - ${moduleDisplayName} Record Scheduled for Deletion`;
      const message = `
        <p>Dear Admin,</p>
        
        <p>This is to notify you that a ${moduleDisplayName} verification record is scheduled for automatic deletion from our system in <strong>${daysUntilDeletion} days</strong> (on ${deletionDate.toLocaleDateString()}) as per our data retention policy.</p>
        
        <p><strong>Record Details:</strong></p>
        <ul>
          <li>Record ID: ${record._id}</li>
          <li>User: ${user.firstName || 'N/A'} ${user.lastName || ''} (${user.email})</li>
          <li>Batch ID: ${record.batchId}</li>
          <li>Status: ${record.status}</li>
          <li>Created: ${record.createdAt.toLocaleDateString()}</li>
          <li>Scheduled Deletion: ${deletionDate.toLocaleDateString()}</li>
          <li>Module: ${moduleDisplayName}</li>
        </ul>
        
        <p>This is an automated notification as part of our data retention policy to ensure compliance with data protection regulations.</p>
        
        <p>If you need to take any action regarding this record, please do so before the deletion date.</p>
      `;

      // Send emails to all notification addresses
      for (const email of notificationEmails) {
        await sendNotificationEmail(email, subject, message, {
          actionUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/admin/archival`,
          actionText: `View Archival Dashboard`,
          details: {
            recordId: record._id,
            userId: user._id,
            userEmail: user.email,
            batchId: record.batchId,
            deletionDate: deletionDate.toISOString(),
            daysUntilDeletion,
            module: moduleName
          }
        });
      }

      logger.info(`Module notification emails sent to ${notificationEmails.length} addresses for ${moduleName} record ${record._id}`);
    } catch (error) {
      logger.error(`Failed to send module notification emails for ${moduleName} record ${record._id}:`, error);
    }
  }

  /**
   * Send deletion confirmation email to user
   */
  async sendDeletionConfirmationEmail(record, moduleName) {
    try {
      const user = record.userId;
      
      const moduleDisplayName = moduleName === 'panKyc' ? 'PAN KYC' : 'Aadhaar-PAN';
      const moduleUrl = moduleName === 'panKyc' ? 'pan-kyc' : 'aadhaar-pan';
      
      const subject = `✅ Data Deleted - ${moduleDisplayName} Record #${record._id}`;
      const message = `
        <p>Dear ${user.firstName || 'User'},</p>
        
        <p>This is to confirm that your ${moduleDisplayName} verification record has been automatically deleted from our system as per our data retention policy.</p>
        
        <p><strong>Deleted Record Details:</strong></p>
        <ul>
          <li>Record ID: ${record._id}</li>
          <li>Batch ID: ${record.batchId}</li>
          <li>Status: ${record.status}</li>
          <li>Created: ${record.createdAt.toLocaleDateString()}</li>
          <li>Deleted: ${new Date().toLocaleDateString()}</li>
          <li>Module: ${moduleDisplayName}</li>
        </ul>
        
        <p>This deletion was performed automatically as part of our data retention policy to ensure compliance with data protection regulations.</p>
        
        <p>If you have any questions, please contact our support team.</p>
      `;

      await sendNotificationEmail(user.email, subject, message, {
        actionUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/${moduleUrl}`,
        actionText: `View ${moduleDisplayName} Records`
      });

      logger.info(`Deletion confirmation email sent to ${user.email} for ${moduleName} record ${record._id}`);
    } catch (error) {
      logger.error(`Failed to send deletion confirmation email for ${moduleName} record ${record._id}:`, error);
    }
  }

  /**
   * Update configuration statistics
   */
  async updateConfigStats(config, overallStats) {
    const updateData = {
      lastArchivalRun: new Date(),
      nextArchivalRun: new Date(Date.now() + 24 * 60 * 60 * 1000), // Next day
    };

    // Update PAN KYC stats
    updateData['stats.panKyc.totalRecordsProcessed'] = config.stats.panKyc.totalRecordsProcessed + overallStats.panKyc.recordsProcessed;
    updateData['stats.panKyc.totalRecordsDeleted'] = config.stats.panKyc.totalRecordsDeleted + overallStats.panKyc.recordsDeleted;
    updateData['stats.panKyc.totalEmailsSent'] = config.stats.panKyc.totalEmailsSent + overallStats.panKyc.warningsSent;
    updateData['stats.panKyc.lastProcessedDate'] = new Date();

    // Update Aadhaar-PAN stats
    updateData['stats.aadhaarPan.totalRecordsProcessed'] = config.stats.aadhaarPan.totalRecordsProcessed + overallStats.aadhaarPan.recordsProcessed;
    updateData['stats.aadhaarPan.totalRecordsDeleted'] = config.stats.aadhaarPan.totalRecordsDeleted + overallStats.aadhaarPan.recordsDeleted;
    updateData['stats.aadhaarPan.totalEmailsSent'] = config.stats.aadhaarPan.totalEmailsSent + overallStats.aadhaarPan.warningsSent;
    updateData['stats.aadhaarPan.lastProcessedDate'] = new Date();

    await ArchivalConfig.findByIdAndUpdate(config._id, updateData);
  }

  /**
   * Log archival events for audit trail
   */
  async logArchivalEvent(action, details) {
    try {
      await Audit.create({
        userId: null, // System event
        action: action,
        module: 'archival',
        resource: 'pan_kyc',
        details: details,
        ipAddress: '127.0.0.1', // System process
        userAgent: 'ArchivalService/1.0',
      });
    } catch (error) {
      logger.error('Failed to log archival event:', error);
    }
  }

  /**
   * Get archival statistics for all modules
   */
  async getArchivalStats() {
    const config = await ArchivalConfig.getConfig();
    
    // Get PAN KYC statistics - only count current records in database
    const panKycStats = await PanKyc.aggregate([
      {
        $group: {
          _id: null,
          totalRecords: { $sum: 1 },
          markedForDeletion: {
            $sum: { $cond: [{ $eq: ['$archival.isMarkedForDeletion', true] }, 1, 0] }
          },
          warningSent: {
            $sum: { $cond: [{ $eq: ['$archival.deletionWarningSent', true] }, 1, 0] }
          }
        }
      }
    ]);

    // Get Aadhaar-PAN statistics - only count current records in database
    const aadhaarPanStats = await AadhaarPan.aggregate([
      {
        $group: {
          _id: null,
          totalRecords: { $sum: 1 },
          markedForDeletion: {
            $sum: { $cond: [{ $eq: ['$archival.isMarkedForDeletion', true] }, 1, 0] }
          },
          warningSent: {
            $sum: { $cond: [{ $eq: ['$archival.deletionWarningSent', true] }, 1, 0] }
          }
        }
      }
    ]);

    return {
      config: {
        globalSettings: config.globalSettings,
        moduleSettings: config.moduleSettings,
        lastArchivalRun: config.lastArchivalRun,
        nextArchivalRun: config.nextArchivalRun,
      },
      stats: {
        panKyc: {
          totalRecords: panKycStats[0]?.totalRecords || 0,
          markedForDeletion: panKycStats[0]?.markedForDeletion || 0,
          warningSent: panKycStats[0]?.warningSent || 0,
          deleted: config.stats.panKyc.totalRecordsDeleted, // Use historical count from config
        },
        aadhaarPan: {
          totalRecords: aadhaarPanStats[0]?.totalRecords || 0,
          markedForDeletion: aadhaarPanStats[0]?.markedForDeletion || 0,
          warningSent: aadhaarPanStats[0]?.warningSent || 0,
          deleted: config.stats.aadhaarPan.totalRecordsDeleted, // Use historical count from config
        },
      },
      configStats: config.stats,
    };
  }

  /**
   * Manually delete a specific record (admin function)
   */
  async manualDeleteRecord(recordId, adminUserId, moduleName, reason = 'manual') {
    try {
      const Model = moduleName === 'panKyc' ? PanKyc : AadhaarPan;
      const record = await Model.findById(recordId).populate('userId', 'email firstName lastName');
      
      if (!record) {
        throw new Error(`${moduleName} record not found`);
      }

      // Log the manual deletion
      await this.logArchivalEvent('record_manually_deleted', {
        recordId: record._id,
        userId: record.userId._id,
        module: moduleName,
        adminUserId: adminUserId,
        deletionReason: reason,
        batchId: record.batchId,
      });

      // Send notification email if user exists
      if (record.userId && record.userId.email) {
        await this.sendManualDeletionEmail(record, moduleName, reason);
      }

      // Delete the record
      await Model.findByIdAndDelete(recordId);
      
      logger.info(`${moduleName} record ${recordId} manually deleted by admin ${adminUserId}`);
      return { success: true, message: `${moduleName} record deleted successfully` };
    } catch (error) {
      logger.error(`Error in manual deletion of ${moduleName} record ${recordId}:`, error);
      throw error;
    }
  }

  /**
   * Send manual deletion notification email
   */
  async sendManualDeletionEmail(record, moduleName, reason) {
    try {
      const user = record.userId;
      
      const moduleDisplayName = moduleName === 'panKyc' ? 'PAN KYC' : 'Aadhaar-PAN';
      const moduleUrl = moduleName === 'panKyc' ? 'pan-kyc' : 'aadhaar-pan';
      
      const subject = `🗑️ Data Deleted - ${moduleDisplayName} Record #${record._id}`;
      const message = `
        <p>Dear ${user.firstName || 'User'},</p>
        
        <p>This is to inform you that your ${moduleDisplayName} verification record has been deleted from our system by an administrator.</p>
        
        <p><strong>Deleted Record Details:</strong></p>
        <ul>
          <li>Record ID: ${record._id}</li>
          <li>Batch ID: ${record.batchId}</li>
          <li>Status: ${record.status}</li>
          <li>Created: ${record.createdAt.toLocaleDateString()}</li>
          <li>Deleted: ${new Date().toLocaleDateString()}</li>
          <li>Module: ${moduleDisplayName}</li>
          <li>Reason: ${reason}</li>
        </ul>
        
        <p>If you have any questions about this deletion, please contact our support team.</p>
      `;

      await sendNotificationEmail(user.email, subject, message, {
        actionUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/${moduleUrl}`,
        actionText: `View ${moduleDisplayName} Records`
      });

      logger.info(`Manual deletion email sent to ${user.email} for ${moduleName} record ${record._id}`);
    } catch (error) {
      logger.error(`Failed to send manual deletion email for ${moduleName} record ${record._id}:`, error);
    }
  }

  /**
   * Get user-specific archival settings
   */
  async getUserArchivalSettings(userId) {
    try {
      const config = await ArchivalConfig.getConfig();
      
      const userOverride = config.userOverrides.find(override => 
        override.userId.toString() === userId.toString()
      );

      const result = {
        panKyc: config.getUserModuleSettings(userId, 'panKyc'),
        aadhaarPan: config.getUserModuleSettings(userId, 'aadhaarPan'),
        hasOverrides: !!userOverride,
        overrides: userOverride ? userOverride.moduleSettings : null,
      };

      return result;
    } catch (error) {
      logger.error(`Error getting user archival settings for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Set user-specific archival settings
   */
  async setUserArchivalSettings(userId, moduleName, settings, adminUserId) {
    try {
      const config = await ArchivalConfig.getConfig();
      
      // Validate settings
      if (settings.retentionPeriodDays && (settings.retentionPeriodDays < 30 || settings.retentionPeriodDays > 2555)) {
        throw new Error('Retention period must be between 30 and 2555 days');
      }
      
      if (settings.warningPeriodDays && (settings.warningPeriodDays < 1 || settings.warningPeriodDays > 30)) {
        throw new Error('Warning period must be between 1 and 30 days');
      }

      await config.setUserOverride(userId, moduleName, settings, adminUserId);
      
      logger.info(`User archival settings updated for user ${userId}, module ${moduleName}`);
      return { success: true, message: 'User archival settings updated successfully' };
    } catch (error) {
      logger.error(`Error setting user archival settings for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Remove user-specific archival settings
   */
  async removeUserArchivalSettings(userId, moduleName, adminUserId) {
    try {
      const config = await ArchivalConfig.getConfig();
      
      await config.removeUserOverride(userId, moduleName);
      
      logger.info(`User archival settings removed for user ${userId}, module ${moduleName}`);
      return { success: true, message: 'User archival settings removed successfully' };
    } catch (error) {
      logger.error(`Error removing user archival settings for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * Get records marked for deletion for a specific user and module
   */
  async getUserRecordsMarkedForDeletion(userId, moduleName, page = 1, limit = 20) {
    try {
      const Model = moduleName === 'panKyc' ? PanKyc : AadhaarPan;
      const skip = (page - 1) * limit;
      
      const records = await Model.find({
        userId: userId,
        'archival.isMarkedForDeletion': true,
        'archival.actualDeletionDate': { $exists: false }
      })
      .sort({ 'archival.scheduledDeletionDate': 1 })
      .skip(skip)
      .limit(parseInt(limit));

      const total = await Model.countDocuments({
        userId: userId,
        'archival.isMarkedForDeletion': true,
        'archival.actualDeletionDate': { $exists: false }
      });

      return {
        records,
        pagination: {
          current: parseInt(page),
          pages: Math.ceil(total / limit),
          total,
          limit: parseInt(limit)
        }
      };
    } catch (error) {
      logger.error(`Error getting user records marked for deletion:`, error);
      throw error;
    }
  }
}

module.exports = new ArchivalService();

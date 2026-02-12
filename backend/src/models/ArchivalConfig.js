const mongoose = require('mongoose');

const ArchivalConfigSchema = new mongoose.Schema({
  // Global archival settings
  globalSettings: {
    // Whether global archival process is enabled
    isEnabled: {
      type: Boolean,
      default: true,
    },
    
    // Whether to send email notifications globally
    sendEmailNotifications: {
      type: Boolean,
      default: true,
    },
    
    // Email addresses to notify (admin emails)
    notificationEmails: [{
      type: String,
      validate: {
        validator: function(email) {
          return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
        },
        message: 'Invalid email address format'
      }
    }],
  },
  
  // Module-specific archival settings
  moduleSettings: {
    panKyc: {
      // Data retention period in days (default: 365 days = 1 year)
      retentionPeriodDays: {
        type: Number,
        default: 365,
        min: [30, 'Minimum retention period is 30 days'],
        max: [2555, 'Maximum retention period is 7 years (2555 days)'],
      },
      
      // Warning period in days before deletion (default: 7 days)
      warningPeriodDays: {
        type: Number,
        default: 7,
        min: [1, 'Minimum warning period is 1 day'],
        max: [30, 'Maximum warning period is 30 days'],
      },
      
      // Whether PAN KYC archival is enabled
      isEnabled: {
        type: Boolean,
        default: true,
      },
      
      // Whether to send email notifications for PAN KYC module
      sendEmailNotifications: {
        type: Boolean,
        default: true,
      },
      
      // Module-specific notification emails
      notificationEmails: [{
        type: String,
        validate: {
          validator: function(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); },
          message: 'Invalid email address format'
        }
      }],
    },
    
    aadhaarPan: {
      // Data retention period in days (default: 365 days = 1 year)
      retentionPeriodDays: {
        type: Number,
        default: 365,
        min: [30, 'Minimum retention period is 30 days'],
        max: [2555, 'Maximum retention period is 7 years (2555 days)'],
      },
      
      // Warning period in days before deletion (default: 7 days)
      warningPeriodDays: {
        type: Number,
        default: 7,
        min: [1, 'Minimum warning period is 1 day'],
        max: [30, 'Maximum warning period is 30 days'],
      },
      
      // Whether Aadhaar-PAN archival is enabled
      isEnabled: {
        type: Boolean,
        default: true,
      },
      
      // Whether to send email notifications for Aadhaar-PAN module
      sendEmailNotifications: {
        type: Boolean,
        default: true,
      },
      
      // Module-specific notification emails
      notificationEmails: [{
        type: String,
        validate: {
          validator: function(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); },
          message: 'Invalid email address format'
        }
      }],
    },
  },
  
  // User-specific archival overrides
  userOverrides: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    
    // User-specific module settings
    moduleSettings: {
      panKyc: {
        retentionPeriodDays: {
          type: Number,
          min: [30, 'Minimum retention period is 30 days'],
          max: [2555, 'Maximum retention period is 7 years (2555 days)'],
        },
        warningPeriodDays: {
          type: Number,
          min: [1, 'Minimum warning period is 1 day'],
          max: [30, 'Maximum warning period is 30 days'],
        },
        isEnabled: {
          type: Boolean,
        },
        // User-specific email notifications
        sendEmailNotifications: {
          type: Boolean,
        },
        notificationEmails: [{
          type: String,
          validate: {
            validator: function(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); },
            message: 'Invalid email address format'
          }
        }],
      },
      
      aadhaarPan: {
        retentionPeriodDays: {
          type: Number,
          min: [30, 'Minimum retention period is 30 days'],
          max: [2555, 'Maximum retention period is 7 years (2555 days)'],
        },
        warningPeriodDays: {
          type: Number,
          min: [1, 'Minimum warning period is 1 day'],
          max: [30, 'Maximum warning period is 30 days'],
        },
        isEnabled: {
          type: Boolean,
        },
        // User-specific email notifications
        sendEmailNotifications: {
          type: Boolean,
        },
        notificationEmails: [{
          type: String,
          validate: {
            validator: function(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); },
            message: 'Invalid email address format'
          }
        }],
      },
    },
    
    // When this override was created/updated
    createdAt: {
      type: Date,
      default: Date.now,
    },
    
    updatedAt: {
      type: Date,
      default: Date.now,
    },
    
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
  }],
  
  // Last archival run date
  lastArchivalRun: {
    type: Date,
    default: null,
  },
  
  // Next scheduled archival run
  nextArchivalRun: {
    type: Date,
    default: null,
  },
  
  // Archival statistics by module
  stats: {
    panKyc: {
      totalRecordsProcessed: {
        type: Number,
        default: 0,
      },
      totalRecordsDeleted: {
        type: Number,
        default: 0,
      },
      totalEmailsSent: {
        type: Number,
        default: 0,
      },
      lastProcessedDate: {
        type: Date,
        default: null,
      },
    },
    aadhaarPan: {
      totalRecordsProcessed: {
        type: Number,
        default: 0,
      },
      totalRecordsDeleted: {
        type: Number,
        default: 0,
      },
      totalEmailsSent: {
        type: Number,
        default: 0,
      },
      lastProcessedDate: {
        type: Date,
        default: null,
      },
    },
  },
  
  // Configuration metadata
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false,
  },
  
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false,
  },
}, {
  timestamps: true,
});

// Ensure only one configuration document exists
ArchivalConfigSchema.index({}, { unique: true });

// Static method to get or create configuration
ArchivalConfigSchema.statics.getConfig = async function() {
  let config = await this.findOne();
  if (!config) {
    // Create default configuration if none exists
    config = new this({
      globalSettings: {
        isEnabled: true,
        sendEmailNotifications: true,
        notificationEmails: [],
      },
      moduleSettings: {
        panKyc: {
          retentionPeriodDays: 365,
          warningPeriodDays: 7,
          isEnabled: true,
          sendEmailNotifications: true,
          notificationEmails: [],
        },
        aadhaarPan: {
          retentionPeriodDays: 365,
          warningPeriodDays: 7,
          isEnabled: true,
          sendEmailNotifications: true,
          notificationEmails: [],
        },
      },
      userOverrides: [],
      stats: {
        panKyc: {
          totalRecordsProcessed: 0,
          totalRecordsDeleted: 0,
          totalEmailsSent: 0,
          lastProcessedDate: null,
        },
        aadhaarPan: {
          totalRecordsProcessed: 0,
          totalRecordsDeleted: 0,
          totalEmailsSent: 0,
          lastProcessedDate: null,
        },
      },
      createdBy: null, // Will be set when first admin configures
      updatedBy: null,
    });
    await config.save();
  }
  return config;
};

// Method to get user-specific settings for a module
ArchivalConfigSchema.methods.getUserModuleSettings = function(userId, module) {
  // Check if user has specific overrides
  const userOverride = this.userOverrides.find(override => 
    override.userId.toString() === userId.toString()
  );
  
  if (userOverride && userOverride.moduleSettings[module]) {
    // Return user-specific settings merged with module defaults
    const moduleDefaults = this.moduleSettings[module];
    const userSettings = userOverride.moduleSettings[module];
    
    return {
      retentionPeriodDays: userSettings.retentionPeriodDays || moduleDefaults.retentionPeriodDays,
      warningPeriodDays: userSettings.warningPeriodDays || moduleDefaults.warningPeriodDays,
      isEnabled: userSettings.isEnabled !== undefined ? userSettings.isEnabled : moduleDefaults.isEnabled,
      sendEmailNotifications: userSettings.sendEmailNotifications !== undefined ? userSettings.sendEmailNotifications : moduleDefaults.sendEmailNotifications,
      notificationEmails: userSettings.notificationEmails && userSettings.notificationEmails.length > 0 ? userSettings.notificationEmails : moduleDefaults.notificationEmails,
    };
  }
  
  // Return module default settings
  return {
    retentionPeriodDays: this.moduleSettings[module].retentionPeriodDays,
    warningPeriodDays: this.moduleSettings[module].warningPeriodDays,
    isEnabled: this.moduleSettings[module].isEnabled,
    sendEmailNotifications: this.moduleSettings[module].sendEmailNotifications,
    notificationEmails: this.moduleSettings[module].notificationEmails,
  };
};

// Method to calculate deletion date for a given creation date, user, and module
ArchivalConfigSchema.methods.getDeletionDate = function(createdDate, userId, module) {
  if (!this.globalSettings.isEnabled) return null;
  
  const settings = this.getUserModuleSettings(userId, module);
  if (!settings.isEnabled) return null;
  
  const deletionDate = new Date(createdDate);
  deletionDate.setDate(deletionDate.getDate() + settings.retentionPeriodDays);
  return deletionDate;
};

// Method to calculate warning date for a given creation date, user, and module
ArchivalConfigSchema.methods.getWarningDate = function(createdDate, userId, module) {
  if (!this.globalSettings.isEnabled) return null;
  
  const settings = this.getUserModuleSettings(userId, module);
  if (!settings.isEnabled) return null;
  
  const warningDate = new Date(createdDate);
  warningDate.setDate(warningDate.getDate() + settings.retentionPeriodDays - settings.warningPeriodDays);
  return warningDate;
};

// Method to check if a record should be warned about deletion
ArchivalConfigSchema.methods.shouldWarn = function(createdDate, userId, module) {
  if (!this.globalSettings.isEnabled) return false;
  
  const settings = this.getUserModuleSettings(userId, module);
  if (!settings.isEnabled) return false;
  
  const warningDate = this.getWarningDate(createdDate, userId, module);
  if (!warningDate) return false;
  
  const now = new Date();
  return now >= warningDate;
};

// Method to check if a record should be deleted
ArchivalConfigSchema.methods.shouldDelete = function(createdDate, userId, module) {
  if (!this.globalSettings.isEnabled) return false;
  
  const settings = this.getUserModuleSettings(userId, module);
  if (!settings.isEnabled) return false;
  
  const deletionDate = this.getDeletionDate(createdDate, userId, module);
  if (!deletionDate) return false;
  
  const now = new Date();
  return now >= deletionDate;
};

// Method to add or update user override
ArchivalConfigSchema.methods.setUserOverride = function(userId, module, settings, adminUserId) {
  const existingOverrideIndex = this.userOverrides.findIndex(override => 
    override.userId.toString() === userId.toString()
  );
  
  const overrideData = {
    userId,
    moduleSettings: {
      [module]: {
        ...settings,
        updatedAt: new Date(),
      }
    },
    createdBy: adminUserId,
    updatedAt: new Date(),
  };
  
  if (existingOverrideIndex >= 0) {
    // Update existing override
    this.userOverrides[existingOverrideIndex].moduleSettings[module] = {
      ...this.userOverrides[existingOverrideIndex].moduleSettings[module],
      ...settings,
    };
    this.userOverrides[existingOverrideIndex].updatedAt = new Date();
  } else {
    // Add new override
    overrideData.createdAt = new Date();
    this.userOverrides.push(overrideData);
  }
  
  return this.save();
};

// Method to remove user override
ArchivalConfigSchema.methods.removeUserOverride = function(userId, module) {
  const overrideIndex = this.userOverrides.findIndex(override => 
    override.userId.toString() === userId.toString()
  );
  
  if (overrideIndex >= 0) {
    if (module) {
      // Remove specific module override
      delete this.userOverrides[overrideIndex].moduleSettings[module];
      
      // If no module settings left, remove the entire override
      if (Object.keys(this.userOverrides[overrideIndex].moduleSettings).length === 0) {
        this.userOverrides.splice(overrideIndex, 1);
      }
    } else {
      // Remove entire user override
      this.userOverrides.splice(overrideIndex, 1);
    }
  }
  
  return this.save();
};

module.exports = mongoose.model('ArchivalConfig', ArchivalConfigSchema);

const cron = require('node-cron');
const archivalService = require('./archivalService');
const logger = require('../utils/logger');

class SchedulerService {
  constructor() {
    this.jobs = new Map();
    this.isInitialized = false;
  }

  /**
   * Initialize all scheduled jobs
   */
  async initialize() {
    if (this.isInitialized) {
      logger.warn('Scheduler service already initialized');
      return;
    }

    try {
      // Schedule archival process to run daily at 2:00 AM
      this.scheduleArchivalProcess();
      
      // Schedule health check every hour
      this.scheduleHealthCheck();
      
      this.isInitialized = true;
      logger.info('Scheduler service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize scheduler service:', error);
      throw error;
    }
  }

  /**
   * Schedule the archival process
   */
  scheduleArchivalProcess() {
    // Run daily at 2:00 AM
    const cronExpression = '0 2 * * *';
    
    const job = cron.schedule(cronExpression, async () => {
      logger.info('Starting scheduled archival process...');
      try {
        await archivalService.runArchivalProcess();
        logger.info('Scheduled archival process completed successfully');
      } catch (error) {
        logger.error('Scheduled archival process failed:', error);
      }
    }, {
      scheduled: true,
      timezone: 'Asia/Kolkata' // Indian timezone
    });

    this.jobs.set('archival', job);
    logger.info(`Archival process scheduled with cron expression: ${cronExpression}`);
  }

  /**
   * Schedule health check
   */
  scheduleHealthCheck() {
    // Run every hour
    const cronExpression = '0 * * * *';
    
    const job = cron.schedule(cronExpression, async () => {
      logger.debug('Running scheduled health check...');
      try {
        await this.performHealthCheck();
      } catch (error) {
        logger.error('Health check failed:', error);
      }
    }, {
      scheduled: true,
      timezone: 'Asia/Kolkata'
    });

    this.jobs.set('healthCheck', job);
    logger.info(`Health check scheduled with cron expression: ${cronExpression}`);
  }

  /**
   * Perform system health check
   */
  async performHealthCheck() {
    try {
      // Check if archival service is responsive
      const stats = await archivalService.getArchivalStats();
      
      logger.debug('Health check completed', {
        archivalEnabled: stats.config.isEnabled,
        totalRecords: stats.stats.totalRecords,
        lastArchivalRun: stats.config.lastArchivalRun
      });
    } catch (error) {
      logger.error('Health check error:', error);
    }
  }

  /**
   * Manually trigger archival process
   */
  async triggerArchivalProcess() {
    logger.info('Manually triggering archival process...');
    try {
      await archivalService.runArchivalProcess();
      return { success: true, message: 'Archival process completed successfully' };
    } catch (error) {
      logger.error('Manual archival process failed:', error);
      throw error;
    }
  }

  /**
   * Get scheduler status
   */
  getStatus() {
    const status = {
      isInitialized: this.isInitialized,
      jobs: {}
    };

    for (const [name, job] of this.jobs) {
      status.jobs[name] = {
        running: job.running,
        scheduled: job.scheduled,
        lastExecution: job.lastExecution,
        nextExecution: job.nextExecution
      };
    }

    return status;
  }

  /**
   * Start a specific job
   */
  startJob(jobName) {
    const job = this.jobs.get(jobName);
    if (job) {
      job.start();
      logger.info(`Job '${jobName}' started`);
      return { success: true, message: `Job '${jobName}' started successfully` };
    } else {
      throw new Error(`Job '${jobName}' not found`);
    }
  }

  /**
   * Stop a specific job
   */
  stopJob(jobName) {
    const job = this.jobs.get(jobName);
    if (job) {
      job.stop();
      logger.info(`Job '${jobName}' stopped`);
      return { success: true, message: `Job '${jobName}' stopped successfully` };
    } else {
      throw new Error(`Job '${jobName}' not found`);
    }
  }

  /**
   * Restart a specific job
   */
  restartJob(jobName) {
    const job = this.jobs.get(jobName);
    if (job) {
      job.stop();
      job.start();
      logger.info(`Job '${jobName}' restarted`);
      return { success: true, message: `Job '${jobName}' restarted successfully` };
    } else {
      throw new Error(`Job '${jobName}' not found`);
    }
  }

  /**
   * Destroy all jobs and cleanup
   */
  destroy() {
    logger.info('Destroying scheduler service...');
    
    for (const [name, job] of this.jobs) {
      job.destroy();
      logger.info(`Job '${name}' destroyed`);
    }
    
    this.jobs.clear();
    this.isInitialized = false;
    logger.info('Scheduler service destroyed');
  }
}

module.exports = new SchedulerService();

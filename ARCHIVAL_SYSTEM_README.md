# PAN KYC Data Archival System

## Overview

The PAN KYC Data Archival System is a comprehensive solution for managing data retention and automatic deletion of PAN KYC verification records. It ensures compliance with data protection regulations while providing administrators with full control over the archival process.

## Features

### 🔧 **Configurable Data Retention**
- **Retention Period**: Configurable from 30 days to 7 years (2555 days)
- **Warning Period**: Configurable from 1 to 30 days before deletion
- **Admin Control**: Enable/disable archival process
- **Email Notifications**: Configurable email notifications for users and admins

### 📧 **Email Notifications**
- **Warning Emails**: Sent to users 7 days (configurable) before data deletion
- **Deletion Confirmation**: Sent to users after data is deleted
- **Admin Notifications**: Sent to configured admin emails for important events

### ⏰ **Automated Scheduling**
- **Daily Execution**: Runs automatically at 2:00 AM (Indian timezone)
- **Manual Trigger**: Admins can trigger archival process manually
- **Health Monitoring**: Built-in health checks and monitoring

### 📊 **Comprehensive Monitoring**
- **Real-time Statistics**: Track total records, marked for deletion, warnings sent, and deleted records
- **Audit Trail**: Complete audit logging of all archival activities
- **Admin Dashboard**: Full admin interface for configuration and monitoring

## Architecture

### Backend Components

#### 1. **ArchivalConfig Model** (`/backend/src/models/ArchivalConfig.js`)
- Stores archival configuration settings
- Manages retention and warning periods
- Tracks archival statistics and run history

#### 2. **ArchivalService** (`/backend/src/services/archivalService.js`)
- Core archival logic and business rules
- Email notification management
- Record marking and deletion processes
- Statistics and reporting

#### 3. **SchedulerService** (`/backend/src/services/schedulerService.js`)
- Cron job management using node-cron
- Automated archival process scheduling
- Health monitoring and job control

#### 4. **Admin Routes** (`/backend/src/routes/admin.js`)
- RESTful API endpoints for archival management
- Configuration CRUD operations
- Manual process triggering
- Statistics and monitoring endpoints

### Frontend Components

#### **Admin Dashboard** (`/frontend/src/pages/Admin/Admin.tsx`)
- Archival configuration interface
- Real-time statistics display
- Manual process triggering
- Email management

## Database Schema

### PAN KYC Model Updates
```javascript
archival: {
  isMarkedForDeletion: Boolean,
  deletionWarningSent: Boolean,
  warningSentAt: Date,
  scheduledDeletionDate: Date,
  actualDeletionDate: Date,
  deletionReason: String // 'retention_policy', 'manual', 'user_request'
}
```

### ArchivalConfig Model
```javascript
{
  retentionPeriodDays: Number, // 30-2555 days
  warningPeriodDays: Number,   // 1-30 days
  isEnabled: Boolean,
  sendEmailNotifications: Boolean,
  notificationEmails: [String],
  lastArchivalRun: Date,
  nextArchivalRun: Date,
  stats: {
    totalRecordsProcessed: Number,
    totalRecordsDeleted: Number,
    totalEmailsSent: Number,
    lastProcessedDate: Date
  }
}
```

## API Endpoints

### Configuration Management
- `GET /api/admin/archival/config` - Get archival configuration
- `PUT /api/admin/archival/config` - Update archival configuration

### Process Control
- `POST /api/admin/archival/trigger` - Manually trigger archival process
- `GET /api/admin/archival/scheduler/status` - Get scheduler status
- `POST /api/admin/archival/scheduler/:action/:jobName` - Start/stop scheduler jobs

### Statistics and Monitoring
- `GET /api/admin/archival/stats` - Get archival statistics
- `GET /api/admin/archival/records/marked-for-deletion` - Get records marked for deletion

### Record Management
- `DELETE /api/admin/archival/records/:recordId` - Manually delete a record

## Configuration

### Environment Variables
Ensure these are set in your `.env` file:
```env
# Email Configuration (required for notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/kyc-aadhaar-app

# Frontend URL (for email links)
FRONTEND_URL=http://localhost:3000
```

### Default Configuration
- **Retention Period**: 365 days (1 year)
- **Warning Period**: 7 days
- **Archival Process**: Enabled
- **Email Notifications**: Enabled
- **Scheduled Run**: Daily at 2:00 AM IST

## Usage

### 1. **Initial Setup**
```bash
# Install dependencies
cd backend
npm install node-cron

# Test the archival system
node test-archival.js
```

### 2. **Admin Configuration**
1. Login as admin user
2. Navigate to Admin Dashboard → Data Archival tab
3. Configure retention and warning periods
4. Add admin notification emails
5. Enable/disable archival process
6. Save configuration

### 3. **Monitoring**
- View real-time statistics in admin dashboard
- Monitor archival process logs
- Check email notification status
- Review audit trail

### 4. **Manual Operations**
- Trigger archival process manually
- Delete specific records
- Start/stop scheduler jobs
- View records marked for deletion

## Email Templates

### Warning Email
- **Subject**: `⚠️ Data Deletion Warning - PAN KYC Record #[ID]`
- **Content**: Informs user about upcoming deletion with record details
- **Action**: Link to view PAN KYC records

### Deletion Confirmation Email
- **Subject**: `✅ Data Deleted - PAN KYC Record #[ID]`
- **Content**: Confirms record deletion with details
- **Action**: Link to view remaining PAN KYC records

### Manual Deletion Email
- **Subject**: `🗑️ Data Deleted - PAN KYC Record #[ID]`
- **Content**: Notifies user of manual deletion by admin
- **Action**: Link to view PAN KYC records

## Security and Compliance

### Data Protection
- **Encrypted Storage**: All sensitive data remains encrypted
- **Audit Trail**: Complete logging of all archival activities
- **Access Control**: Admin-only access to archival functions
- **Secure Deletion**: Permanent removal from database

### Compliance Features
- **Configurable Retention**: Meet various regulatory requirements
- **User Notifications**: Transparent data handling
- **Admin Oversight**: Full control and monitoring
- **Audit Logging**: Complete activity tracking

## Monitoring and Logging

### Log Levels
- **INFO**: Normal archival operations
- **WARN**: Non-critical issues
- **ERROR**: Failed operations requiring attention

### Key Metrics
- Total records processed
- Records marked for deletion
- Warning emails sent
- Records successfully deleted
- Process execution time

### Health Checks
- Scheduler service status
- Database connectivity
- Email service availability
- Configuration validity

## Troubleshooting

### Common Issues

#### 1. **Archival Process Not Running**
- Check if archival is enabled in configuration
- Verify scheduler service is running
- Check server logs for errors

#### 2. **Email Notifications Not Sent**
- Verify SMTP configuration
- Check email service logs
- Ensure notification emails are configured

#### 3. **Records Not Being Deleted**
- Check retention period configuration
- Verify record creation dates
- Review archival process logs

### Debug Commands
```bash
# Test archival system
node test-archival.js

# Check scheduler status
curl -H "Authorization: Bearer <admin-token>" \
  http://localhost:3002/api/admin/archival/scheduler/status

# Get archival statistics
curl -H "Authorization: Bearer <admin-token>" \
  http://localhost:3002/api/admin/archival/stats
```

## Best Practices

### Configuration
- Set appropriate retention periods based on regulatory requirements
- Configure warning periods to give users adequate notice
- Add multiple admin notification emails for redundancy
- Test email notifications before production deployment

### Monitoring
- Regularly review archival statistics
- Monitor email delivery success rates
- Check audit logs for any anomalies
- Set up alerts for failed archival processes

### Maintenance
- Regularly backup archival configuration
- Monitor database growth and archival effectiveness
- Review and update retention policies as needed
- Test archival process in staging environment

## Future Enhancements

### Planned Features
- **Batch Export**: Export data before deletion
- **Advanced Scheduling**: More flexible scheduling options
- **Data Analytics**: Advanced reporting and analytics
- **API Integration**: External system integration
- **Multi-tenant Support**: Separate configurations per organization

### Integration Opportunities
- **External Archival Systems**: Integration with enterprise archival solutions
- **Compliance Tools**: Integration with compliance monitoring tools
- **Notification Services**: Integration with Slack, Teams, etc.
- **Backup Systems**: Integration with backup and recovery systems

## Support

For technical support or questions about the archival system:
1. Check the audit logs for detailed error information
2. Review the troubleshooting section above
3. Contact the development team with specific error messages
4. Provide relevant configuration and log details

---

**Note**: This archival system is designed to be compliant with data protection regulations. Always review and configure retention periods according to your specific regulatory requirements.

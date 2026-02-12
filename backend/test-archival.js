const mongoose = require('mongoose');
require('dotenv').config();

const ArchivalConfig = require('./src/models/ArchivalConfig');
const PanKyc = require('./src/models/PanKyc');
const archivalService = require('./src/services/archivalService');

async function testArchivalSystem() {
  try {
    console.log('🔗 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    console.log('\n📊 Testing Archival Configuration...');
    
    // Test 1: Get or create archival configuration
    const config = await ArchivalConfig.getConfig();
    console.log('✅ Archival configuration:', {
      retentionPeriodDays: config.retentionPeriodDays,
      warningPeriodDays: config.warningPeriodDays,
      isEnabled: config.isEnabled,
      sendEmailNotifications: config.sendEmailNotifications
    });

    // Test 2: Get archival statistics
    console.log('\n📈 Getting archival statistics...');
    const stats = await archivalService.getArchivalStats();
    console.log('✅ Archival statistics:', stats);

    // Test 3: Check if there are any PAN KYC records
    const totalRecords = await PanKyc.countDocuments();
    console.log(`\n📋 Total PAN KYC records in database: ${totalRecords}`);

    if (totalRecords > 0) {
      // Test 4: Check records marked for deletion
      const markedForDeletion = await PanKyc.countDocuments({
        'archival.isMarkedForDeletion': true
      });
      console.log(`📋 Records marked for deletion: ${markedForDeletion}`);

      // Test 5: Check records with warnings sent
      const warningsSent = await PanKyc.countDocuments({
        'archival.deletionWarningSent': true
      });
      console.log(`📋 Records with warnings sent: ${warningsSent}`);

      // Test 6: Find records that should be warned (if any)
      const warningDate = new Date();
      warningDate.setDate(warningDate.getDate() + config.warningPeriodDays);
      
      const recordsToWarn = await PanKyc.find({
        'archival.deletionWarningSent': false,
        'archival.isMarkedForDeletion': false,
        createdAt: {
          $lte: new Date(Date.now() - (config.retentionPeriodDays - config.warningPeriodDays) * 24 * 60 * 60 * 1000)
        }
      }).limit(5);

      console.log(`📋 Records that should be warned: ${recordsToWarn.length}`);
      if (recordsToWarn.length > 0) {
        console.log('   Sample records:', recordsToWarn.map(r => ({
          id: r._id,
          createdAt: r.createdAt,
          status: r.status
        })));
      }
    }

    console.log('\n✅ Archival system test completed successfully!');
    console.log('\n📝 Next steps:');
    console.log('1. Configure archival settings via admin panel');
    console.log('2. Test email notifications (ensure SMTP is configured)');
    console.log('3. Run manual archival process via admin panel');
    console.log('4. Monitor archival logs and statistics');

  } catch (error) {
    console.error('❌ Error testing archival system:', error);
  } finally {
    await mongoose.disconnect();
    console.log('\n🔌 Disconnected from MongoDB');
  }
}

// Run the test
testArchivalSystem();

const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function debugOldFormat() {
  try {
    console.log('🔍 Testing old format encryption...');
    
    // Find a record with old format (no colon)
    const record = await PanKyc.findOne({
      panNumber: { $regex: /^[0-9a-fA-F]+$/ },
      panNumber: { $not: { $regex: /:/ } }
    });
    
    if (!record) {
      console.log('❌ No old format records found');
      return;
    }
    
    console.log('Found old format record:', record._id);
    console.log('PAN:', record.panNumber);
    console.log('DOB:', record.dateOfBirth);
    
    const encryptionKey = process.env.ENCRYPTION_KEY;
    
    console.log('\n🔓 Testing decryption manually...');
    
    // Test PAN decryption (old format)
    const encryptedString = record.panNumber;
    console.log('Encrypted PAN:', encryptedString);
    
    try {
      console.log('Using old format (deprecated method)...');
      const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
      let decrypted = decipher.update(encryptedString, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      console.log('✅ Manual decryption successful:', decrypted);
    } catch (error) {
      console.log('❌ Manual decryption failed:', error.message);
      console.log('Error details:', error);
    }
    
    console.log('\n🔓 Testing with the model method...');
    
    try {
      const decryptedRecord = record.decryptData();
      console.log('Model decryption PAN result:', decryptedRecord.panNumber);
      console.log('Model decryption DOB result:', decryptedRecord.dateOfBirth);
    } catch (error) {
      console.log('❌ Model decryption failed:', error.message);
      console.log('Error details:', error);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

debugOldFormat();

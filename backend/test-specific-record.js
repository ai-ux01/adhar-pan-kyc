const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function testSpecificRecord() {
  try {
    console.log('🔍 Testing specific record from API response...');
    
    // Test the specific record ID from the API response
    const recordId = '68bf271f9291804651b02352';
    const record = await PanKyc.findById(recordId);
    
    if (!record) {
      console.log('❌ Record not found');
      return;
    }
    
    console.log('Record ID:', record._id);
    console.log('Original PAN:', record.panNumber);
    console.log('Original Name:', record.name);
    console.log('Original DOB:', record.dateOfBirth);
    
    // Test decryption
    console.log('\n--- Testing Decryption ---');
    try {
      const decryptedRecord = record.decryptData();
      console.log('Decrypted PAN:', decryptedRecord.panNumber);
      console.log('Decrypted Name:', decryptedRecord.name);
      console.log('Decrypted DOB:', decryptedRecord.dateOfBirth);
      
      // Check if still encrypted
      if (decryptedRecord.panNumber.includes(':')) {
        console.log('❌ PAN is still encrypted after decryption!');
        
        // Try manual decryption
        const encryptionKey = process.env.ENCRYPTION_KEY;
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync(encryptionKey, 'salt', 32);
        const [ivHex, encrypted] = decryptedRecord.panNumber.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let manualDecrypted = decipher.update(encrypted, 'hex', 'utf8');
        manualDecrypted += decipher.final('utf8');
        console.log('Manual decrypted PAN:', manualDecrypted);
      } else {
        console.log('✅ PAN is properly decrypted');
      }
    } catch (error) {
      console.log('❌ Decryption failed:', error.message);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

testSpecificRecord();

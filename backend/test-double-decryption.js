const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function testDoubleDecryption() {
  try {
    console.log('🔍 Testing double decryption...');
    
    const batchId = 'PAN aadhar KYC_1757357847231_kwb5r9';
    const record = await PanKyc.findOne({ batchId: batchId });
    
    if (!record) {
      console.log('❌ Record not found');
      return;
    }
    
    console.log('Original PAN:', record.panNumber);
    console.log('Original Name:', record.name);
    console.log('Original DOB:', record.dateOfBirth);
    
    const encryptionKey = process.env.ENCRYPTION_KEY;
    
    // Test first level decryption
    console.log('\n--- First Level Decryption ---');
    const firstDecrypted = record.decryptData();
    console.log('First decrypted PAN:', firstDecrypted.panNumber);
    console.log('First decrypted Name:', firstDecrypted.name);
    console.log('First decrypted DOB:', firstDecrypted.dateOfBirth);
    
    // Check if the result is still encrypted
    if (firstDecrypted.panNumber.includes(':')) {
      console.log('\n--- Second Level Decryption ---');
      
      // Try to decrypt the first decrypted result
      try {
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync(encryptionKey, 'salt', 32);
        const [ivHex, encrypted] = firstDecrypted.panNumber.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        console.log('Second decrypted PAN:', decrypted);
      } catch (error) {
        console.log('❌ Second level decryption failed:', error.message);
      }
    }
    
    // Test manual decryption of original data
    console.log('\n--- Manual Decryption of Original ---');
    try {
      const algorithm = 'aes-256-cbc';
      const key = crypto.scryptSync(encryptionKey, 'salt', 32);
      const [ivHex, encrypted] = record.panNumber.split(':');
      const iv = Buffer.from(ivHex, 'hex');
      const decipher = crypto.createDecipheriv(algorithm, key, iv);
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      console.log('Manual decrypted PAN:', decrypted);
    } catch (error) {
      console.log('❌ Manual decryption failed:', error.message);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

testDoubleDecryption();

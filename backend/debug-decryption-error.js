const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function debugDecryptionError() {
  try {
    console.log('🔍 Debugging decryption error...');
    
    // Find a record with encrypted data
    const record = await PanKyc.findOne({
      dateOfBirth: 'ed4413e0ae878777ccda86b5af2850e9:89b233861c80c657f17865b8f5394d91'
    });
    
    if (!record) {
      console.log('❌ Record not found');
      return;
    }
    
    console.log('Found record:', record._id);
    console.log('DOB:', record.dateOfBirth);
    
    const encryptionKey = process.env.ENCRYPTION_KEY;
    const encryptedString = record.dateOfBirth;
    
    console.log('\n🔓 Testing decryption manually...');
    
    try {
      if (encryptedString.includes(':')) {
        console.log('Using new format (IV-based)...');
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync(encryptionKey, 'salt', 32);
        const [ivHex, encrypted] = encryptedString.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        
        console.log('IV (hex):', ivHex);
        console.log('IV length:', iv.length);
        console.log('Encrypted part:', encrypted);
        console.log('Key length:', key.length);
        
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        console.log('✅ Manual decryption successful:', decrypted);
      }
    } catch (error) {
      console.log('❌ Manual decryption failed:', error.message);
      console.log('Error details:', error);
    }
    
    console.log('\n🔓 Testing with the model method...');
    
    try {
      const decryptedRecord = record.decryptData();
      console.log('Model decryption result:', decryptedRecord.dateOfBirth);
    } catch (error) {
      console.log('❌ Model decryption failed:', error.message);
      console.log('Error details:', error);
    }
    
    // Test the exact logic from the model
    console.log('\n🔓 Testing exact model logic...');
    
    const decrypted = record.toObject();
    const field = 'dateOfBirth';
    const encryptedField = decrypted[field];
    
    console.log('Field value:', encryptedField);
    console.log('Field type:', typeof encryptedField);
    
    if (encryptedField && typeof encryptedField === 'string') {
      try {
        if (encryptedField.includes(':')) {
          console.log('Using new format...');
          const algorithm = 'aes-256-cbc';
          const key = crypto.scryptSync(encryptionKey, 'salt', 32);
          const [ivHex, encrypted] = encryptedField.split(':');
          const iv = Buffer.from(ivHex, 'hex');
          const decipher = crypto.createDecipheriv(algorithm, key, iv);
          let decryptedField = decipher.update(encrypted, 'hex', 'utf8');
          decryptedField += decipher.final('utf8');
          console.log('✅ Exact logic decryption successful:', decryptedField);
        }
      } catch (error) {
        console.log('❌ Exact logic decryption failed:', error.message);
        console.log('Error details:', error);
      }
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

debugDecryptionError();

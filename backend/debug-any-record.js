const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function debugAnyRecord() {
  try {
    console.log('🔍 Finding any record with encrypted data...');
    
    // Find any record with encrypted data
    const record = await PanKyc.findOne({
      $or: [
        { panNumber: { $regex: /^[0-9a-fA-F]+:[0-9a-fA-F]+$/ } },
        { name: { $regex: /^[0-9a-fA-F]+:[0-9a-fA-F]+$/ } },
        { dateOfBirth: { $regex: /^[0-9a-fA-F]+:[0-9a-fA-F]+$/ } }
      ]
    });
    
    if (!record) {
      console.log('❌ No records with encrypted data found');
      return;
    }
    
    console.log('Found record:', record._id);
    console.log('PAN:', record.panNumber);
    console.log('Name:', record.name);
    console.log('DOB:', record.dateOfBirth);
    
    const encryptionKey = process.env.ENCRYPTION_KEY;
    
    console.log('\n🔓 Testing decryption manually...');
    
    // Test DOB decryption
    const encryptedString = record.dateOfBirth;
    console.log('Encrypted DOB:', encryptedString);
    
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
      console.log('Model decryption DOB result:', decryptedRecord.dateOfBirth);
      console.log('Model decryption PAN result:', decryptedRecord.panNumber);
      console.log('Model decryption Name result:', decryptedRecord.name);
    } catch (error) {
      console.log('❌ Model decryption failed:', error.message);
      console.log('Error details:', error);
    }
    
    // Test the exact logic from the model step by step
    console.log('\n🔓 Testing exact model logic step by step...');
    
    const decrypted = record.toObject();
    const fieldsToDecrypt = ['panNumber', 'name', 'dateOfBirth', 'fatherName'];
    
    fieldsToDecrypt.forEach(field => {
      console.log(`\n--- Testing ${field} ---`);
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
            console.log(`✅ ${field} decryption successful:`, decryptedField);
          }
        } catch (error) {
          console.log(`❌ ${field} decryption failed:`, error.message);
          console.log('Error details:', error);
        }
      }
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

debugAnyRecord();

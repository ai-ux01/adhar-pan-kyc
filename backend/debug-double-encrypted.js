const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function debugDoubleEncrypted() {
  try {
    console.log('🔍 Finding records that show encrypted data after decryption...');
    
    // Find the specific record that was showing encrypted data
    const record = await PanKyc.findById('68bf18efdf5f274b2f5622a8');
    
    if (!record) {
      console.log('❌ Record not found');
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
        
        // Check if the result is still encrypted
        if (decrypted.includes(':')) {
          console.log('⚠️  Result is still encrypted! Trying to decrypt again...');
          
          const [ivHex2, encrypted2] = decrypted.split(':');
          const iv2 = Buffer.from(ivHex2, 'hex');
          const decipher2 = crypto.createDecipheriv(algorithm, key, iv2);
          let decrypted2 = decipher2.update(encrypted2, 'hex', 'utf8');
          decrypted2 += decipher2.final('utf8');
          
          console.log('✅ Second decryption successful:', decrypted2);
        }
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
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

debugDoubleEncrypted();

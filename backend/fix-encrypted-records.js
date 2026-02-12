// Load environment variables
require('dotenv').config();

const mongoose = require('mongoose');
const PanKyc = require('./src/models/PanKyc');

async function fixEncryptedRecords() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    
    console.log('🔍 Finding records with encrypted empty dateOfBirth...');
    
    // Find all records
    const records = await PanKyc.find({});
    
    console.log(`Found ${records.length} records to check`);
    
    let fixedCount = 0;
    
    for (const record of records) {
      try {
        // Check if dateOfBirth is a hex string (encrypted)
        if (record.dateOfBirth && 
            typeof record.dateOfBirth === 'string' && 
            /^[0-9a-fA-F]+$/.test(record.dateOfBirth)) {
          
          console.log(`Checking record ${record._id}: ${record.dateOfBirth.substring(0, 20)}...`);
          
          // Try to decrypt it
          try {
            const decrypted = record.decryptData();
            if (decrypted.dateOfBirth === '[ENCRYPTED]' || decrypted.dateOfBirth === '') {
              // This was an encrypted empty string, set it to null
              record.dateOfBirth = null;
              await record.save();
              fixedCount++;
              console.log(`✅ Fixed record ${record._id} (was encrypted empty string)`);
            } else {
              console.log(`ℹ️  Record ${record._id} has valid encrypted data: ${decrypted.dateOfBirth}`);
            }
          } catch (decryptError) {
            // If decryption fails, it might be an encrypted empty string
            console.log(`⚠️  Decryption failed for record ${record._id}, checking if it's an empty string...`);
            
            // Try to decrypt with a simple approach to see if it's an empty string
            try {
              const crypto = require('crypto');
              const encryptionKey = process.env.ENCRYPTION_KEY;
              const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
              let decryptedField = decipher.update(record.dateOfBirth, 'hex', 'utf8');
              decryptedField += decipher.final('utf8');
              
              if (decryptedField === '') {
                record.dateOfBirth = null;
                await record.save();
                fixedCount++;
                console.log(`✅ Fixed record ${record._id} (was encrypted empty string)`);
              } else {
                console.log(`ℹ️  Record ${record._id} has valid encrypted data: ${decryptedField}`);
              }
            } catch (innerError) {
              console.log(`❌ Could not decrypt record ${record._id}: ${innerError.message}`);
            }
          }
        } else if (record.dateOfBirth === '') {
          // Already an empty string, convert to null
          record.dateOfBirth = null;
          await record.save();
          fixedCount++;
          console.log(`✅ Fixed record ${record._id} (converted empty string to null)`);
        }
      } catch (error) {
        console.error(`❌ Error fixing record ${record._id}:`, error.message);
      }
    }
    
    console.log(`🎉 Fixed ${fixedCount} records`);
    
    await mongoose.disconnect();
  } catch (error) {
    console.error('Error:', error.message);
  }
}

fixEncryptedRecords();

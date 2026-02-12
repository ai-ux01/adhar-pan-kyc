const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function testBasicFields() {
  try {
    console.log('🔍 Testing basic fields encryption/decryption...');
    
    // Find records that might have encrypted basic fields
    const records = await PanKyc.find({
      $or: [
        { panNumber: { $regex: /^[0-9a-fA-F]+:[0-9a-fA-F]+$/ } }, // IV:encrypted format
        { name: { $regex: /^[0-9a-fA-F]+:[0-9a-fA-F]+$/ } },
        { dateOfBirth: { $regex: /^[0-9a-fA-F]+:[0-9a-fA-F]+$/ } },
        { fatherName: { $regex: /^[0-9a-fA-F]+:[0-9a-fA-F]+$/ } }
      ]
    }).sort({ updatedAt: -1 }).limit(5);
    
    console.log('Found records with encrypted basic fields:', records.length);
    
    for (let i = 0; i < records.length; i++) {
      const record = records[i];
      console.log(`\n--- Record ${i + 1} ---`);
      console.log('ID:', record._id);
      console.log('PAN:', record.panNumber);
      console.log('Name:', record.name);
      console.log('DOB:', record.dateOfBirth);
      console.log('Father:', record.fatherName);
      
      // Try to decrypt this record
      try {
        const decryptedRecord = record.decryptData();
        console.log('Decrypted PAN:', decryptedRecord.panNumber);
        console.log('Decrypted Name:', decryptedRecord.name);
        console.log('Decrypted DOB:', decryptedRecord.dateOfBirth);
        console.log('Decrypted Father:', decryptedRecord.fatherName);
        
        // Check if any field is still encrypted
        const fields = ['panNumber', 'name', 'dateOfBirth', 'fatherName'];
        for (const field of fields) {
          if (typeof decryptedRecord[field] === 'string' && 
              decryptedRecord[field].includes(':')) {
            console.log(`❌ ${field} is still encrypted: ${decryptedRecord[field]}`);
          } else {
            console.log(`✅ ${field} is properly decrypted: ${decryptedRecord[field]}`);
          }
        }
      } catch (error) {
        console.log('❌ Record decryption failed:', error.message);
      }
    }
    
    // Also check the specific encrypted string the user mentioned
    console.log('\n🔍 Checking for the specific encrypted string...');
    const specificRecords = await PanKyc.find({
      $or: [
        { panNumber: 'ed4413e0ae878777ccda86b5af2850e9:89b233861c80c657f17865b8f5394d91' },
        { name: 'ed4413e0ae878777ccda86b5af2850e9:89b233861c80c657f17865b8f5394d91' },
        { dateOfBirth: 'ed4413e0ae878777ccda86b5af2850e9:89b233861c80c657f17865b8f5394d91' },
        { fatherName: 'ed4413e0ae878777ccda86b5af2850e9:89b233861c80c657f17865b8f5394d91' }
      ]
    });
    
    console.log('Found records with the specific encrypted string:', specificRecords.length);
    
    for (let i = 0; i < specificRecords.length; i++) {
      const record = specificRecords[i];
      console.log(`\n--- Specific Record ${i + 1} ---`);
      console.log('ID:', record._id);
      console.log('Status:', record.status);
      console.log('PAN:', record.panNumber);
      console.log('Name:', record.name);
      console.log('DOB:', record.dateOfBirth);
      console.log('Father:', record.fatherName);
      
      // Try to decrypt this record
      try {
        const decryptedRecord = record.decryptData();
        console.log('Decrypted PAN:', decryptedRecord.panNumber);
        console.log('Decrypted Name:', decryptedRecord.name);
        console.log('Decrypted DOB:', decryptedRecord.dateOfBirth);
        console.log('Decrypted Father:', decryptedRecord.fatherName);
      } catch (error) {
        console.log('❌ Record decryption failed:', error.message);
      }
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

testBasicFields();

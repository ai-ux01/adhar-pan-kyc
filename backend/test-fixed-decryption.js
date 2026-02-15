const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function testFixedDecryption() {
  try {
    console.log('🔍 Testing fixed decryption logic...');
    
    // Test with different types of records
    const records = await PanKyc.find({}).limit(5);
    
    console.log('Found records:', records.length);
    
    for (let i = 0; i < records.length; i++) {
      const record = records[i];
      console.log(`\n--- Record ${i + 1} ---`);
      console.log('ID:', record._id);
      console.log('Original PAN:', record.panNumber);
      console.log('Original Name:', record.name);
      console.log('Original DOB:', record.dateOfBirth);
      
      // Try to decrypt this record
      try {
        const decryptedRecord = record.decryptData();
        console.log('Decrypted PAN:', decryptedRecord.panNumber);
        console.log('Decrypted Name:', decryptedRecord.name);
        console.log('Decrypted DOB:', decryptedRecord.dateOfBirth);
        console.log('Decrypted Father:', decryptedRecord.fatherName);
        
        // Check if any field is still encrypted
        const fields = ['panNumber', 'name', 'dateOfBirth', 'fatherName'];
        let hasEncryptedFields = false;
        for (const field of fields) {
          if (typeof decryptedRecord[field] === 'string' && 
              (decryptedRecord[field].includes(':') || decryptedRecord[field] === '[ENCRYPTED]')) {
            console.log(`❌ ${field} is still encrypted: ${decryptedRecord[field]}`);
            hasEncryptedFields = true;
          } else {
            console.log(`✅ ${field} is properly decrypted: ${decryptedRecord[field]}`);
          }
        }
        
        if (!hasEncryptedFields) {
          console.log('✅ All fields properly decrypted!');
        }
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

testFixedDecryption();

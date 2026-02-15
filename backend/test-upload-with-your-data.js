const mongoose = require('mongoose');
const XLSX = require('xlsx');
const path = require('path');
const PanKyc = require('./src/models/PanKyc');
require('dotenv').config();

const testUploadWithYourData = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB');

    // Create test data with your exact format
    const testData = [
      {
        'Name': 'SANDEEP',
        'DOB': '7/5/77',
        'PAN No': 'BHRPS6510E',
        'AADHAAR': '618389305704'
      },
      {
        'Name': 'ADITYA RAJ',
        'DOB': '9/21/02',
        'PAN No': 'EXYPR1188H',
        'AADHAAR': '315624024362'
      },
      {
        'Name': 'ANKIT SHARMA',
        'DOB': '2/16/00',
        'PAN No': 'KNMPS0015N',
        'AADHAAR': '310140147068'
      }
    ];

    console.log('🔍 Testing with your exact data format...');
    console.log('📊 Test data:', testData.length, 'rows');
    console.log('');

    // Simulate the exact upload route logic
    const requiredColumns = ['panNumber', 'name'];
    const firstRow = testData[0];
    
    console.log('🔍 Column validation:');
    console.log('Found columns:', Object.keys(firstRow));
    console.log('Required columns:', requiredColumns);
    console.log('');
    
    const columnMapping = {
      'panNumber': ['panNumber', 'PAN No', 'PAN', 'pan', 'PANNumber', 'pan_number', 'PAN No.'],
      'name': ['name', 'Name', 'NAME', 'fullName', 'Full Name', 'full_name', 'FULL NAME']
    };
    
    const columnMap = {};
    const missingColumns = [];
    
    requiredColumns.forEach(requiredCol => {
      const possibleNames = columnMapping[requiredCol];
      let found = false;
      
      for (const possibleName of possibleNames) {
        if (firstRow.hasOwnProperty(possibleName)) {
          columnMap[requiredCol] = possibleName;
          found = true;
          console.log(`✅ Column ${requiredCol} found as: ${possibleName}`);
          break;
        }
      }
      
      if (!found) {
        missingColumns.push(requiredCol);
        console.log(`❌ Column ${requiredCol} not found`);
      }
    });
    
    if (missingColumns.length > 0) {
      console.log('❌ Missing columns:', missingColumns);
      return;
    }
    
    console.log('🗺️ Final column map:', columnMap);
    console.log('');
    
    // Process data (simulate the route logic)
    const batchId = `TEST_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const records = [];
    
    for (let i = 0; i < testData.length; i++) {
      const row = testData[i];
      
      console.log(`\n🔍 Processing row ${i + 1}:`);
      console.log('Raw row data:', row);
      
      const panNumberValue = row[columnMap.panNumber]?.toString().trim();
      const nameValue = row[columnMap.name]?.toString().trim();
      const dateOfBirthValue = row.dateOfBirth || row.DOB || row['Date of Birth'] || row['DOB']?.toString().trim();
      const fatherNameValue = row.fatherName || row['Father Name'] || row.father_name || '';
      
      console.log('Extracted values:');
      console.log('panNumber:', panNumberValue);
      console.log('name:', nameValue);
      console.log('dateOfBirth:', dateOfBirthValue);
      console.log('fatherName:', fatherNameValue);
      
      // Create PanKyc document
      const record = new PanKyc({
        userId: new mongoose.Types.ObjectId(), // Dummy user ID
        batchId: batchId,
        panNumber: panNumberValue,
        name: nameValue,
        dateOfBirth: dateOfBirthValue,
        fatherName: fatherNameValue,
        fileUpload: {
          originalName: 'test.xlsx',
          fileName: 'test.xlsx',
          fileSize: 1000,
          uploadDate: new Date()
        }
      });
      
      console.log('📝 Document created, checking fields:');
      console.log('panNumber:', record.panNumber);
      console.log('name:', record.name);
      console.log('dateOfBirth:', record.dateOfBirth);
      console.log('fatherName:', record.fatherName);
      
      // Check if fields are truthy
      console.log('Truthy check:');
      console.log('panNumber truthy:', !!record.panNumber);
      console.log('name truthy:', !!record.name);
      console.log('dateOfBirth truthy:', !!record.dateOfBirth);
      console.log('fatherName truthy:', !!record.fatherName);
      
      records.push(record);
    }
    
    // Save records individually
    console.log('\n💾 Saving records...');
    const savedRecords = [];
    
    for (let i = 0; i < records.length; i++) {
      try {
        console.log(`Saving record ${i + 1}...`);
        const savedRecord = await records[i].save();
        savedRecords.push(savedRecord);
        console.log(`✅ Record ${i + 1} saved successfully`);
      } catch (saveError) {
        console.log(`❌ Error saving record ${i + 1}:`, saveError.message);
        console.log('Error details:', saveError);
        throw saveError;
      }
    }
    
    console.log(`\n🎉 Successfully saved ${savedRecords.length} records!`);
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
};

testUploadWithYourData();

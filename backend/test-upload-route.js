const mongoose = require('mongoose');
const XLSX = require('xlsx');
const path = require('path');
const PanKyc = require('./src/models/PanKyc');
require('dotenv').config();

const testUploadRoute = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB');

    // Simulate the exact upload process
    console.log('🔍 Simulating upload process...');
    
    // 1. Read Excel file
    const filePath = path.join(__dirname, '../sample_pan_kyc.xlsx');
    const workbook = XLSX.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(worksheet);
    
    console.log('📊 Excel data loaded:', data.length, 'rows');
    
    // 2. Validate required columns (simulate the route logic)
    const requiredColumns = ['panNumber', 'name'];
    const firstRow = data[0];
    
    console.log('🔍 Column validation:');
    console.log('Found columns:', Object.keys(firstRow));
    console.log('Required columns:', requiredColumns);
    
    const columnMapping = {
      'panNumber': ['panNumber', 'PAN No', 'PAN', 'pan', 'PANNumber', 'pan_number'],
      'name': ['name', 'Name', 'NAME', 'fullName', 'Full Name', 'full_name']
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
    
    // 3. Process data (simulate the route logic)
    const batchId = `TEST_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const records = [];
    
    for (let i = 0; i < data.length; i++) {
      const row = data[i];
      
      const panNumberValue = row[columnMap.panNumber]?.toString().trim();
      const nameValue = row[columnMap.name]?.toString().trim();
      const dateOfBirthValue = row.dateOfBirth || row.DOB || row['Date of Birth']?.toString().trim();
      const fatherNameValue = row.fatherName || row['Father Name'] || row.father_name || '';
      
      console.log(`\n🔍 Row ${i + 1} data extraction:`);
      console.log('panNumber:', panNumberValue);
      console.log('name:', nameValue);
      console.log('dateOfBirth:', dateOfBirthValue);
      console.log('fatherName:', fatherNameValue);
      
      // 4. Create PanKyc document
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
      
      records.push(record);
    }
    
    // 5. Save records individually
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

testUploadRoute();

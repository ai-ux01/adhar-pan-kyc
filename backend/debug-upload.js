const XLSX = require('xlsx');
const path = require('path');

const debugUpload = async () => {
  try {
    console.log('🔍 Debugging Excel file upload process...');
    
    // Test with the sample file
    const filePath = path.join(__dirname, '../sample_pan_kyc.xlsx');
    console.log('📁 File path:', filePath);
    
    // Read the Excel file
    const workbook = XLSX.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(worksheet);
    
    console.log('📊 Excel file analysis:');
    console.log('Sheet Name:', sheetName);
    console.log('Number of rows:', data.length);
    console.log('');
    
    if (data.length > 0) {
      console.log('🔍 First row data:');
      console.log(JSON.stringify(data[0], null, 2));
      console.log('');
      
      console.log('📋 All column names:');
      console.log(Object.keys(data[0]));
      console.log('');
      
      // Test column mapping logic
      const requiredColumns = ['panNumber', 'name'];
      const firstRow = data[0];
      
      console.log('🔍 Column mapping test:');
      const columnMapping = {
        'panNumber': ['panNumber', 'PAN No', 'PAN', 'pan', 'PANNumber', 'pan_number'],
        'name': ['name', 'Name', 'NAME', 'fullName', 'Full Name', 'full_name']
      };
      
      const columnMap = {};
      
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
          console.log(`❌ Column ${requiredCol} not found`);
        }
      });
      
      console.log('');
      console.log('🗺️ Final column map:', columnMap);
      console.log('');
      
      // Test data extraction
      console.log('🔍 Data extraction test:');
      const panNumberValue = firstRow[columnMap.panNumber]?.toString().trim();
      const nameValue = firstRow[columnMap.name]?.toString().trim();
      const dateOfBirthValue = firstRow.dateOfBirth || firstRow.DOB || firstRow['Date of Birth']?.toString().trim();
      
      console.log('Extracted values:');
      console.log('panNumber:', panNumberValue);
      console.log('name:', nameValue);
      console.log('dateOfBirth:', dateOfBirthValue);
      console.log('');
      
      console.log('Value types:');
      console.log('panNumber type:', typeof panNumberValue);
      console.log('name type:', typeof nameValue);
      console.log('dateOfBirth type:', typeof dateOfBirthValue);
      console.log('');
      
      console.log('Value lengths:');
      console.log('panNumber length:', panNumberValue ? panNumberValue.length : 0);
      console.log('name length:', nameValue ? nameValue.length : 0);
      console.log('dateOfBirth length:', dateOfBirthValue ? dateOfBirthValue.length : 0);
      console.log('');
      
      // Test if values are truthy
      console.log('Truthy check:');
      console.log('panNumber truthy:', !!panNumberValue);
      console.log('name truthy:', !!nameValue);
      console.log('dateOfBirth truthy:', !!dateOfBirthValue);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  }
};

debugUpload();

const XLSX = require('xlsx');
const path = require('path');

const testYourFile = async () => {
  try {
    console.log('🔍 Testing your file format...');
    
    // Create a test Excel file with your data
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
    
    // Create Excel file
    const workbook = XLSX.utils.book_new();
    const worksheet = XLSX.utils.json_to_sheet(testData);
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Test Data');
    XLSX.writeFile(workbook, 'test_your_format.xlsx');
    
    console.log('📁 Created test file: test_your_format.xlsx');
    
    // Read the file back
    const readWorkbook = XLSX.readFile('test_your_format.xlsx');
    const sheetName = readWorkbook.SheetNames[0];
    const readWorksheet = readWorkbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(readWorksheet);
    
    console.log('📊 File analysis:');
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
      
      console.log('');
      console.log('🗺️ Final column map:', columnMap);
      console.log('');
      
      // Test data extraction
      console.log('🔍 Data extraction test:');
      const panNumberValue = firstRow[columnMap.panNumber]?.toString().trim();
      const nameValue = firstRow[columnMap.name]?.toString().trim();
      const dateOfBirthValue = firstRow.dateOfBirth || firstRow.DOB || firstRow['Date of Birth'] || firstRow['DOB']?.toString().trim();
      
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
      
      if (panNumberValue && nameValue) {
        console.log('\n✅ SUCCESS: Your file format will work!');
      } else {
        console.log('\n❌ ISSUE: Some required fields are missing');
      }
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  }
};

testYourFile();

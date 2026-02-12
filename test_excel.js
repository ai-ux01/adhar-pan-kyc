const XLSX = require('xlsx');

// Read the PAN KYC Excel file
const workbook = XLSX.readFile('sample_pan_kyc.xlsx');
const sheetName = workbook.SheetNames[0];
const worksheet = workbook.Sheets[sheetName];
const data = XLSX.utils.sheet_to_json(worksheet);

console.log('📊 Excel File Analysis:');
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
  
  console.log('✅ Required columns check:');
  const requiredColumns = ['panNumber', 'name', 'fatherName'];
  requiredColumns.forEach(col => {
    const hasColumn = data[0].hasOwnProperty(col);
    console.log(`${col}: ${hasColumn ? '✅' : '❌'}`);
  });
}

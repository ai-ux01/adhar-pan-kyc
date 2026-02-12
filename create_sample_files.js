const XLSX = require('xlsx');

// PAN KYC Sample Data
const panKycData = [
  {
    panNumber: 'ABCDE1234F',
    name: 'John Doe',
    fatherName: 'James Doe',
    dateOfBirth: '1990-01-01'
  },
  {
    panNumber: 'FGHIJ5678K',
    name: 'Jane Smith',
    fatherName: 'Robert Smith',
    dateOfBirth: '1985-05-15'
  },
  {
    panNumber: 'LMNOP9012Q',
    name: 'Mike Johnson',
    fatherName: 'David Johnson',
    dateOfBirth: '1988-12-25'
  },
  {
    panNumber: 'RSTUV3456W',
    name: 'Sarah Wilson',
    fatherName: 'Thomas Wilson',
    dateOfBirth: '1992-03-10'
  },
  {
    panNumber: 'XYZAB7890C',
    name: 'Alex Brown',
    fatherName: 'Michael Brown',
    dateOfBirth: '1987-07-20'
  }
];

// Aadhaar-PAN Sample Data
const aadhaarPanData = [
  {
    panNumber: 'ABCDE1234F',
    aadhaarNumber: '123456789012',
    name: 'John Doe',
    dateOfBirth: '1990-01-01',
    gender: 'M'
  },
  {
    panNumber: 'FGHIJ5678K',
    aadhaarNumber: '987654321098',
    name: 'Jane Smith',
    dateOfBirth: '1985-05-15',
    gender: 'F'
  },
  {
    panNumber: 'LMNOP9012Q',
    aadhaarNumber: '456789123456',
    name: 'Mike Johnson',
    dateOfBirth: '1988-12-25',
    gender: 'M'
  },
  {
    panNumber: 'RSTUV3456W',
    aadhaarNumber: '789123456789',
    name: 'Sarah Wilson',
    dateOfBirth: '1992-03-10',
    gender: 'F'
  },
  {
    panNumber: 'XYZAB7890C',
    aadhaarNumber: '321654987321',
    name: 'Alex Brown',
    dateOfBirth: '1987-07-20',
    gender: 'M'
  }
];

// Create PAN KYC Excel file
const panKycWorkbook = XLSX.utils.book_new();
const panKycWorksheet = XLSX.utils.json_to_sheet(panKycData);
XLSX.utils.book_append_sheet(panKycWorkbook, panKycWorksheet, 'PAN KYC Data');
XLSX.writeFile(panKycWorkbook, 'sample_pan_kyc.xlsx');

// Create Aadhaar-PAN Excel file
const aadhaarPanWorkbook = XLSX.utils.book_new();
const aadhaarPanWorksheet = XLSX.utils.json_to_sheet(aadhaarPanData);
XLSX.utils.book_append_sheet(aadhaarPanWorkbook, aadhaarPanWorksheet, 'Aadhaar-PAN Data');
XLSX.writeFile(aadhaarPanWorkbook, 'sample_aadhaar_pan.xlsx');

console.log('✅ Sample Excel files created successfully!');
console.log('📁 sample_pan_kyc.xlsx - For PAN KYC testing');
console.log('📁 sample_aadhaar_pan.xlsx - For Aadhaar-PAN testing');
console.log('');
console.log('📋 PAN KYC file contains: panNumber, name, fatherName, dateOfBirth');
console.log('📋 Aadhaar-PAN file contains: panNumber, aadhaarNumber, name, dateOfBirth, gender');

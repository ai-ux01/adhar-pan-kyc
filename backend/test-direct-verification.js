const axios = require('axios');

// Sandbox API credentials
const SANDBOX_API_KEY = 'key_live_6edea225e1354559b2422d3921c795cf';
const SANDBOX_API_SECRET = 'secret_live_03078556231c41879cd6ab46e1d6d6a07f';

// Test data that you confirmed is working
const testData = {
  pan: "CHIPK8864R",
  dob: "1990-03-01",
  name_as_per_pan: "Ashul Kumar",
  reason: "test"
};

// Format date from YYYY-MM-DD to DD/MM/YYYY
function formatDateToDDMMYYYY(dateStr) {
  const [year, month, day] = dateStr.split("-");
  return `${day}/${month}/${year}`;
}

async function testDirectVerification() {
  console.log('🧪 Testing Direct PAN Verification (No Authentication Step)...\n');
  console.log('API Key:', SANDBOX_API_KEY);
  console.log('API Secret:', SANDBOX_API_SECRET);
  console.log('Test Data:', testData);
  console.log('Formatted DOB:', formatDateToDDMMYYYY(testData.dob));
  console.log('');

  try {
    // Try direct PAN verification without authentication step
    console.log('🔍 Attempting Direct PAN Verification...');
    
    const verificationRequest = {
      "@entity": "in.co.sandbox.kyc.pan_verification.request",
      pan: testData.pan.toUpperCase(),
      name_as_per_pan: testData.name_as_per_pan.trim(),
      date_of_birth: formatDateToDDMMYYYY(testData.dob),
      consent: "Y",
      reason: testData.reason,
    };
    
    console.log('Verification request:', JSON.stringify(verificationRequest, null, 2));
    console.log('');

    const verifyResponse = await axios.post('https://api.sandbox.co.in/kyc/pan/verify', verificationRequest, {
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': SANDBOX_API_KEY,
        'x-api-secret': SANDBOX_API_SECRET,
        'x-accept-cache': 'true',
      }
    });

    console.log('✅ Direct PAN verification successful!');
    console.log('Response status:', verifyResponse.status);
    console.log('Response data:', JSON.stringify(verifyResponse.data, null, 2));

  } catch (error) {
    console.error('❌ Direct verification failed!');
    
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
      console.error('Response headers:', error.response.headers);
    } else if (error.request) {
      console.error('Request error:', error.request);
    } else {
      console.error('Error:', error.message);
    }
    
    console.error('Full error:', error);
  }
}

// Run the test
console.log('🚀 Starting Direct Verification Test...\n');
testDirectVerification();

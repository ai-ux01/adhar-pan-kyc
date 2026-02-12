const axios = require('axios');

// Sandbox API credentials
const SANDBOX_API_KEY = 'key_live_6edea225e1354559b2422d3921c795cf';
const SANDBOX_API_SECRET = 'secret_live_03078556231c41879cd6ab46e1d6d6a07f';

// Test data
const testData = {
  pan: 'ABCDE1234F',
  name: 'John Doe',
  dateOfBirth: '1990-05-15',
  reason: 'KYC Verification'
};

// Format date from YYYY-MM-DD to DD/MM/YYYY
function formatDateToDDMMYYYY(dateStr) {
  const [year, month, day] = dateStr.split("-");
  return `${day}/${month}/${year}`;
}

async function testSandboxAPI() {
  console.log('🧪 Testing Sandbox API Directly...\n');
  console.log('Test Data:', testData);
  console.log('Formatted DOB:', formatDateToDDMMYYYY(testData.dateOfBirth));
  console.log('');

  try {
    // Step 1: Authenticate
    console.log('🔐 Step 1: Authenticating with Sandbox API...');
    
    const authResponse = await axios.post('https://api.sandbox.co.in/authenticate', {}, {
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': SANDBOX_API_KEY,
        'x-api-secret': SANDBOX_API_SECRET,
      }
    });

    console.log('✅ Authentication successful!');
    console.log('Response status:', authResponse.status);
    console.log('Response data:', JSON.stringify(authResponse.data, null, 2));
    
    const accessToken = authResponse.data.access_token || authResponse.data.data?.access_token;
    
    if (!accessToken) {
      console.error('❌ No access token received!');
      return;
    }
    
    console.log('Access token received:', accessToken.substring(0, 20) + '...');
    console.log('');

    // Step 2: Verify PAN
    console.log('🔍 Step 2: Verifying PAN with Sandbox API...');
    
    const verificationRequest = {
      "@entity": "in.co.sandbox.kyc.pan_verification.request",
      pan: testData.pan.toUpperCase(),
      name_as_per_pan: testData.name.trim(),
      date_of_birth: formatDateToDDMMYYYY(testData.dateOfBirth),
      consent: "Y",
      reason: testData.reason,
    };
    
    console.log('Verification request:', JSON.stringify(verificationRequest, null, 2));
    console.log('');

    const verifyResponse = await axios.post('https://api.sandbox.co.in/kyc/pan/verify', verificationRequest, {
      headers: {
        'Content-Type': 'application/json',
        'authorization': accessToken,
        'x-api-key': SANDBOX_API_KEY,
        'x-accept-cache': 'true',
      }
    });

    console.log('✅ PAN verification successful!');
    console.log('Response status:', verifyResponse.status);
    console.log('Response data:', JSON.stringify(verifyResponse.data, null, 2));

  } catch (error) {
    console.error('❌ Test failed!');
    
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
console.log('🚀 Starting Sandbox API Test...\n');
testSandboxAPI();

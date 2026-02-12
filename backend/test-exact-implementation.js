const axios = require('axios');

// Sandbox API credentials (exact same as your working code)
const SANDBOX_API_KEY = 'key_live_6edea225e1354559b2422d3921c795cf';
const SANDBOX_API_SECRET = 'secret_live_03078556231c41879cd6ab46e1d6d6a07f';

// Test data (exact same as your working test)
const testData = {
  pan: "CHIPK8864R",
  dob: "1990-03-01",
  name_as_per_pan: "Ashul Kumar",
  reason: "test"
};

// Format date function (exact same as your working code)
function formatDateToDDMMYYYY(dateStr) {
  // dateStr expected in "yyyy-mm-dd"
  const [year, month, day] = dateStr.split("-");
  return `${day}/${month}/${year}`;
}

async function testExactImplementation() {
  console.log('🧪 Testing Exact Working Implementation...\n');
  console.log('API Key:', SANDBOX_API_KEY);
  console.log('API Secret:', SANDBOX_API_SECRET);
  console.log('Test Data:', testData);
  console.log('Formatted DOB:', formatDateToDDMMYYYY(testData.dob));
  console.log('');

  try {
    // 1️⃣ Authenticate (exact same as your working code)
    console.log('🔐 Step 1: Authenticating with Sandbox API...');
    
    const authRes = await axios.post("https://api.sandbox.co.in/authenticate", {}, {
      headers: {
        "Content-Type": "application/json",
        "x-api-key": SANDBOX_API_KEY,
        "x-api-secret": SANDBOX_API_SECRET,
      },
    });

    const authData = authRes.data;
    console.log("AUTH RESPONSE:", authData);
    
    if (authRes.status !== 200) {
      console.error("AUTH RESPONSE:", authData);
      throw new Error(`Authentication failed with status ${authRes.status}`);
    }

    const accessToken = authData.access_token || authData.data?.access_token;
    console.log("Access Token:", accessToken);
    
    if (!accessToken) {
      throw new Error('No access token received from Sandbox API');
    }

    const formattedDob = formatDateToDDMMYYYY(testData.dob);
    console.log("Formatted DOB:", formattedDob);
    console.log('');

    // 2️⃣ Verify PAN using access_token (exact same as your working code)
    console.log('🔍 Step 2: Verifying PAN with Sandbox API...');
    
    const verifyRes = await axios.post("https://api.sandbox.co.in/kyc/pan/verify", {
      "@entity": "in.co.sandbox.kyc.pan_verification.request",
      pan: testData.pan,
      name_as_per_pan: testData.name_as_per_pan,
      date_of_birth: formattedDob,
      consent: "Y",
      reason: testData.reason,
    }, {
      headers: {
        "Content-Type": "application/json",
        "authorization": accessToken,
        "x-api-key": SANDBOX_API_KEY,
        "x-accept-cache": "true",
      },
    });

    const verifyData = verifyRes.data;
    console.log("VERIFY RESPONSE:", verifyData);

    console.log('\n✅ SUCCESS! PAN verification completed!');
    console.log('Response status:', verifyRes.status);
    console.log('PAN Status:', verifyData.data?.status);
    console.log('Name Match:', verifyData.data?.name_as_per_pan_match);
    console.log('DOB Match:', verifyData.data?.date_of_birth_match);

  } catch (error) {
    console.error("❌ Test failed!");
    
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    } else {
      console.error('Error:', error.message);
    }
  }
}

// Run the test
console.log('🚀 Starting Exact Implementation Test...\n');
testExactImplementation();

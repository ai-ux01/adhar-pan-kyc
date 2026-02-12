const axios = require('axios');

// Test your working Next.js API endpoint
const WORKING_API_URL = 'http://192.168.31.82:3000/api/verify-pan';

// Test data (exact same as your working test)
const testData = {
  pan: "CHIPK8864R",
  dob: "1990-03-01",
  name_as_per_pan: "Ashul Kumar",
  reason: "test"
};

async function testYourWorkingAPI() {
  console.log('🧪 Testing Your Working Next.js API Endpoint...\n');
  console.log('API URL:', WORKING_API_URL);
  console.log('Test Data:', testData);
  console.log('');

  try {
    console.log('🔍 Calling your working API endpoint...');
    
    const response = await axios.post(WORKING_API_URL, testData, {
      headers: {
        'Content-Type': 'application/json',
      }
    });

    console.log('✅ SUCCESS! Your API is working!');
    console.log('Response status:', response.status);
    console.log('Response data:', JSON.stringify(response.data, null, 2));

    // Parse the response to show key details
    const data = response.data;
    if (data.data) {
      console.log('\n📊 Verification Details:');
      console.log('  PAN:', data.data.pan);
      console.log('  Status:', data.data.status);
      console.log('  Name Match:', data.data.name_as_per_pan_match);
      console.log('  DOB Match:', data.data.date_of_birth_match);
      console.log('  Category:', data.data.category);
      console.log('  Aadhaar Seeding:', data.data.aadhaar_seeding_status);
    }

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
console.log('🚀 Starting Your Working API Test...\n');
testYourWorkingAPI();

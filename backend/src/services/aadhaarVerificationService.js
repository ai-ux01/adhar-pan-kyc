const logger = require('../utils/logger');
const axios = require('axios');

// Sandbox API Configuration
const SANDBOX_API_KEY = process.env.SANDBOX_API_KEY || 'key_live_6edea225e1354559b2422d3921c795cf';
const SANDBOX_API_SECRET = process.env.SANDBOX_API_SECRET || 'secret_live_03078556231c41879cd6ab46e1d6d6a07f';
const SANDBOX_BASE_URL = 'https://api.sandbox.co.in';

// Format date to DD/MM/YYYY format for Sandbox API
function formatDateToDDMMYYYY(dateStr) {
  try {
    // Handle different date formats
    let date;
    if (dateStr.includes('-')) {
      // Format: YYYY-MM-DD
      const [year, month, day] = dateStr.split('-');
      date = new Date(year, month - 1, day);
    } else if (dateStr.includes('/')) {
      // Format: DD/MM/YYYY or MM/DD/YYYY
      const parts = dateStr.split('/');
      if (parts[0].length === 4) {
        // YYYY/MM/DD
        date = new Date(parts[0], parts[1] - 1, parts[2]);
      } else {
        // DD/MM/YYYY
        date = new Date(parts[2], parts[1] - 1, parts[0]);
      }
    } else {
      throw new Error('Unsupported date format');
    }
    
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    
    return `${day}/${month}/${year}`;
    } catch (error) {
    logger.error('Date formatting error:', error);
    throw new Error(`Invalid date format: ${dateStr}`);
  }
}

// Authenticate with Sandbox API
async function authenticateWithSandbox() {
  try {
    logger.info("Authenticating with Sandbox API for Aadhaar verification...");
    
    const response = await fetch(`${SANDBOX_BASE_URL}/authenticate`, {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'x-api-key': SANDBOX_API_KEY,
        'x-api-secret': SANDBOX_API_SECRET,
      },
    });

    if (!response.ok) {
      const errorData = await response.json();
      logger.error("Sandbox authentication failed:", {
        status: response.status,
        data: errorData
      });
      throw new Error(`Authentication failed: ${response.status} - ${JSON.stringify(errorData)}`);
    }

    const authData = await response.json();
    const accessToken = authData.access_token || authData.data?.access_token;
    
    if (!accessToken) {
      logger.error("No access token received from Sandbox API");
      throw new Error("No access token received from authentication");
    }
    
    logger.info("Sandbox authentication successful for Aadhaar verification");
    return accessToken;
    
    } catch (error) {
    logger.error("Sandbox authentication error for Aadhaar verification:", error);
    throw error;
  }
}

// Send OTP for Aadhaar verification with retry logic
async function sendAadhaarOTP(aadhaarNumber, reason = 'For KYC', retryCount = 0) {
  const maxRetries = 2;
  
  try {
    logger.info("Sending Aadhaar OTP...", { aadhaarNumber, retryCount });

    // Step 1: Authenticate first
    const accessToken = await authenticateWithSandbox();

    const requestData = {
      '@entity': 'in.co.sandbox.kyc.aadhaar.okyc.otp.request',
      aadhaar_number: aadhaarNumber.replace(/\s/g, ''),
      consent: 'y',
      reason: reason
    };

    logger.info("OTP Send request data:", {
      url: `${SANDBOX_BASE_URL}/kyc/aadhaar/okyc/otp`,
      data: requestData,
      hasAccessToken: !!accessToken,
      accessTokenLength: accessToken ? accessToken.length : 0
    });

    const options = {
      method: 'POST',
      url: `${SANDBOX_BASE_URL}/kyc/aadhaar/okyc/otp`,
      headers: {
        accept: 'application/json',
        'x-api-version': '2.0',
        'content-type': 'application/json',
        'x-api-key': SANDBOX_API_KEY,
        'authorization': accessToken
      },
      data: requestData
    };

    const response = await axios.request(options);
    
    logger.info("Aadhaar OTP sent successfully:", {
      status: response.status,
      data: response.data,
      headers: response.headers
    });
    
    // Log the transaction ID for debugging
    if (response.data) {
      logger.info("OTP Response transaction ID fields:", {
        transaction_id: response.data.transaction_id,
        txn_id: response.data.txn_id,
        reference_id: response.data.reference_id,
        ref_id: response.data.ref_id,
        id: response.data.id,
        fullResponse: response.data
      });
    }
    
    return response.data;

    } catch (error) {
    logger.error("Error sending Aadhaar OTP:", {
      message: error.message,
      status: error.response?.status,
      statusText: error.response?.statusText,
      data: error.response?.data,
      headers: error.response?.headers,
      config: {
        url: error.config?.url,
        method: error.config?.method,
        headers: error.config?.headers
      }
    });

    // Handle specific error cases
    if (error.response?.status === 500) {
      const errorMessage = error.response?.data?.message || 'Internal server error from Sandbox API';
      
      // Check if it's a rate limit error
      if (errorMessage.includes('45 seconds') || errorMessage.includes('rate limit')) {
        throw new Error(`Rate limit exceeded. Please wait 45 seconds before trying again.`);
      }
      
      // Retry logic for temporary 500 errors
      if (retryCount < maxRetries) {
        logger.info(`Retrying OTP send (attempt ${retryCount + 1}/${maxRetries})...`);
        await new Promise(resolve => setTimeout(resolve, 2000 * (retryCount + 1))); // Exponential backoff
        return sendAadhaarOTP(aadhaarNumber, reason, retryCount + 1);
      }
      
      throw new Error(`Sandbox API error: ${errorMessage}. Please try again later.`);
    }
    
    throw new Error(`Failed to send OTP: ${error.response?.data?.message || error.message}`);
  }
}

// Verify OTP for Aadhaar verification
async function verifyAadhaarOTP(referenceId, otp) {
  try {
    logger.info("Verifying Aadhaar OTP...", { 
      referenceId, 
      otp,
      referenceIdType: typeof referenceId,
      referenceIdLength: referenceId ? referenceId.length : 'null'
    });

    // Step 1: Authenticate first
    const accessToken = await authenticateWithSandbox();

    const requestData = {
      '@entity': 'in.co.sandbox.kyc.aadhaar.okyc.request',
      reference_id: String(referenceId), // Convert to string as required by API
      otp: otp
    };

    logger.info("OTP Verification request data:", requestData);

    const options = {
      method: 'POST',
      url: `${SANDBOX_BASE_URL}/kyc/aadhaar/okyc/otp/verify`,
      headers: {
        accept: 'application/json',
        'x-api-version': '2.0',
        'content-type': 'application/json',
        'x-api-key': SANDBOX_API_KEY,
        'authorization': accessToken
      },
      data: requestData
    };

    const response = await axios.request(options);
    
    logger.info("Aadhaar OTP verification successful:", response.data);
    return response.data;

    } catch (error) {
    logger.error("Error verifying Aadhaar OTP:", error.response?.data || error.message);
    throw new Error(`Failed to verify OTP: ${error.response?.data?.message || error.message}`);
  }
}

// Main Aadhaar verification function
async function verifyAadhaar(aadhaarNumber, location, dynamicFields = [], reason = "KYC Verification") {
  try {
    logger.info("Starting Aadhaar verification (OTP flow):", {
      aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
      location,
      dynamicFields,
      reason
    });
    
    // Validate Aadhaar number format
    const aadhaarRegex = /^\d{12}$/;
    if (!aadhaarRegex.test(aadhaarNumber.replace(/\s/g, ''))) {
      throw new Error('Invalid Aadhaar number format. Must be 12 digits.');
    }
    
    // Send OTP first
    const otpResponse = await sendAadhaarOTP(aadhaarNumber, reason);

    // Extract the correct reference ID
    // The reference_id might be in the data object or at root level
    const extractedReferenceId = otpResponse.data?.reference_id || otpResponse.reference_id || otpResponse.transaction_id || otpResponse.txn_id;
    
    logger.info("Extracting reference ID from OTP response:", {
      data_reference_id: otpResponse.data?.reference_id,
      root_reference_id: otpResponse.reference_id,
      transaction_id: otpResponse.transaction_id,
      txn_id: otpResponse.txn_id,
      extractedReferenceId: extractedReferenceId,
      extractedType: typeof extractedReferenceId,
      fullResponse: otpResponse
    });

    return {
      success: true,
      message: 'OTP sent successfully',
      details: {
        aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
        location: location.trim(),
        dynamicFields: dynamicFields,
        otpSent: true,
        transactionId: extractedReferenceId,
        apiResponse: otpResponse,
        source: 'sandbox_api'
      }
    };
    } catch (error) {
    logger.error("Aadhaar verification (OTP flow) failed:", {
      error: error.message,
      stack: error.stack,
      aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
      location,
      dynamicFields
    });
    
    throw new Error(`Aadhaar verification failed: ${error.message}`);
  }
}

// Simulate Aadhaar verification for testing/fallback
async function simulateAadhaarVerification(record) {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
  
  // Simulate verification logic
  const aadhaarNumber = record.aadhaarNumber;
  const name = record.name;
  const dateOfBirth = record.dateOfBirth;
  const gender = record.gender;
  
  // Simple validation simulation
  const isValidAadhaar = /^\d{12}$/.test(aadhaarNumber.replace(/\s/g, ''));
  const isValidName = name && name.length >= 2;
  const isValidDob = dateOfBirth && dateOfBirth.trim() !== '';
  const isValidGender = ['M', 'F', 'O'].includes(gender);
  
  let status = 'verified';
  let details = {
    message: 'Aadhaar verification successful',
    confidence: 95,
    dataMatch: true,
    nameMatch: true,
    dobMatch: true,
    genderMatch: true,
    addressMatch: true
  };
  
  if (!isValidAadhaar) {
    status = 'invalid';
    details = {
      message: 'Invalid Aadhaar number format',
      confidence: 0,
      dataMatch: false,
      nameMatch: false,
      dobMatch: false,
      genderMatch: false,
      addressMatch: false
    };
  } else if (!isValidName) {
    status = 'rejected';
    details = {
      message: 'Name mismatch',
      confidence: 30,
      dataMatch: false,
      nameMatch: false,
      dobMatch: true,
      genderMatch: true,
      addressMatch: true
    };
  } else if (!isValidDob) {
    status = 'rejected';
    details = {
      message: 'Date of birth mismatch',
      confidence: 30,
      dataMatch: false,
      nameMatch: true,
      dobMatch: false,
      genderMatch: true,
      addressMatch: true
    };
  } else if (!isValidGender) {
    status = 'rejected';
    details = {
      message: 'Gender mismatch',
      confidence: 30,
      dataMatch: false,
      nameMatch: true,
      dobMatch: true,
      genderMatch: false,
      addressMatch: true
    };
  } else {
    // Simulate random verification failures (10% chance)
    if (Math.random() < 0.1) {
      status = 'rejected';
      details = {
        message: 'Data mismatch detected',
        confidence: 30,
        dataMatch: false,
        nameMatch: Math.random() > 0.5,
        dobMatch: Math.random() > 0.5,
        genderMatch: Math.random() > 0.5,
        addressMatch: Math.random() > 0.5
      };
    }
  }
  
  return {
    status,
    details,
    processingTime: Math.floor(Math.random() * 2000) + 500
  };
}

module.exports = {
  verifyAadhaar,
  sendAadhaarOTP,
  verifyAadhaarOTP,
  authenticateWithSandbox,
  simulateAadhaarVerification
};
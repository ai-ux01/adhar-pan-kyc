const logger = require('../utils/logger');

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
    logger.info("Authenticating with Sandbox API...");
    
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
    
    logger.info("Sandbox authentication successful");
    return accessToken;
    
  } catch (error) {
    logger.error("Sandbox authentication error:", error);
    throw error;
  }
}

// Verify PAN with Sandbox API
async function verifyPANWithSandbox(pan, nameAsPerPan, dateOfBirth, reason) {
  try {
    logger.info("Starting Sandbox API verification...");
    
    // Step 1: Authenticate
    const accessToken = await authenticateWithSandbox();
    
    // Step 2: Format date
    const formattedDob = formatDateToDDMMYYYY(dateOfBirth);
    
    // Step 3: Verify PAN
    const verificationResponse = await fetch(`${SANDBOX_BASE_URL}/kyc/pan/verify`, {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'authorization': accessToken,
        'x-api-key': SANDBOX_API_KEY,
        'x-accept-cache': 'true',
      },
      body: JSON.stringify({
        "@entity": "in.co.sandbox.kyc.pan_verification.request",
        pan: pan.toUpperCase(),
        name_as_per_pan: nameAsPerPan.trim(),
        date_of_birth: formattedDob,
        consent: "Y",
        reason: reason || "KYC Verification",
      }),
    });

    if (!verificationResponse.ok) {
      const errorData = await verificationResponse.json();
      logger.error("Sandbox PAN verification failed:", {
        status: verificationResponse.status,
        data: errorData
      });
      throw new Error(`Verification failed: ${verificationResponse.status} - ${JSON.stringify(errorData)}`);
    }

    const verificationData = await verificationResponse.json();
    
    logger.info("Sandbox PAN verification successful:", {
      status: verificationResponse.status,
      data: verificationData
    });
    
    return verificationData;
    
  } catch (error) {
    logger.error("Sandbox PAN verification error:", error);
    throw error;
  }
}

// Main PAN verification function
async function verifyPAN(panNumber, name, dateOfBirth, reason = "KYC Verification") {
  try {
    logger.info("Starting PAN verification:", {
      panNumber,
      name,
      dateOfBirth,
      reason
    });
    
    // Use Sandbox API for verification
    const result = await verifyPANWithSandbox(panNumber, name, dateOfBirth, reason);
    
    // Process the response
    const verificationData = result.data || result;
    
    return {
      valid: verificationData.status === 'valid',
      message: 'PAN verification completed successfully',
      details: {
        panNumber: panNumber.toUpperCase(),
        name: name.trim(),
        dateOfBirth,
        verifiedAt: new Date(),
        source: 'sandbox_api',
        apiResponse: result,
        confidence: 95,
        dataMatch: verificationData.name_as_per_pan_match && verificationData.date_of_birth_match,
        nameMatch: verificationData.name_as_per_pan_match,
        dobMatch: verificationData.date_of_birth_match,
        category: verificationData.category,
        aadhaarSeedingStatus: verificationData.aadhaar_seeding_status,
        remarks: verificationData.remarks,
        transactionId: result.transaction_id
      }
    };
  } catch (error) {
    logger.error("PAN verification failed:", {
      error: error.message,
      stack: error.stack,
      panNumber,
      name,
      dateOfBirth
    });
    
    throw new Error(`PAN verification failed: ${error.message}`);
  }
}

module.exports = {
  verifyPAN,
  verifyPANWithSandbox,
  authenticateWithSandbox
};

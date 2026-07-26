const logger = require('../utils/logger');

const SANDBOX_API_KEY = process.env.SANDBOX_API_KEY || 'key_live_6edea225e1354559b2422d3921c795cf';
const SANDBOX_API_SECRET = process.env.SANDBOX_API_SECRET || 'secret_live_03078556231c41879cd6ab46e1d6d6a07f';
const SANDBOX_BASE_URL = 'https://api.sandbox.co.in';

// Authenticate with Sandbox API
async function authenticateWithSandbox() {
  try {
    logger.info("Authenticating with Sandbox API for Bank verification...");
    
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
      const errorData = await response.json().catch(() => ({}));
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
    
    logger.info("Sandbox authentication successful for Bank verification");
    return accessToken;
    
  } catch (error) {
    logger.error("Sandbox authentication error for Bank verification:", error);
    throw error;
  }
}

// Verify Bank Account
async function verifyBankAccount(ifsc, accountNumber) {
  try {
    logger.info("Verifying Bank Account...", { ifsc, accountNumber: accountNumber.substring(0, 4) + '...' });

    // Step 1: Authenticate first
    const accessToken = await authenticateWithSandbox();

    const normalizedIfsc = String(ifsc).trim().toUpperCase();
    const normalizedAccount = String(accountNumber).trim();

    const url = `${SANDBOX_BASE_URL}/bank/${normalizedIfsc}/accounts/${normalizedAccount}/penniless-verify`;

    logger.info("Calling Sandbox Bank Penny-Less verification API", { url });

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'accept': 'application/json',
        'x-api-version': '1.0',
        'x-api-key': SANDBOX_API_KEY,
        'authorization': accessToken
      }
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const message =
        data?.message ||
        data?.error?.message ||
        data?.error ||
        `Sandbox API error (${response.status})`;
      
      const err = new Error(message);
      err.statusCode = response.status >= 400 && response.status < 500 ? 400 : 502;
      err.sandboxResponse = data;
      throw err;
    }

    // Success response format:
    // {
    //   "account_exists": true,
    //   "name_at_bank": "JOHN DOE",
    //   "transaction_id": "..."
    // }
    const accountExists = data?.account_exists !== undefined ? data.account_exists : (data?.data?.account_exists || false);
    const nameAtBank = data?.name_at_bank || data?.data?.name_at_bank || '';
    const transactionId = data?.transaction_id || data?.data?.transaction_id || `txn_${Date.now()}`;

    return {
      valid: accountExists,
      message: accountExists ? 'Bank account verified successfully' : 'Bank account does not exist',
      verificationId: transactionId,
      details: {
        apiResponse: data,
        source: 'sandbox',
        accountExists,
        nameAtBank,
        transactionId
      }
    };

  } catch (error) {
    logger.error("Error in Bank verification service:", error);
    throw error;
  }
}

module.exports = {
  verifyBankAccount
};

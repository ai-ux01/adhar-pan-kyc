const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const XLSX = require('xlsx');
const { protect } = require('../middleware/auth');
const AadhaarPan = require('../models/AadhaarPan');
const { logAadhaarPanEvent } = require('../services/auditService');
const logger = require('../utils/logger');
const axios = require('axios');

// Function to check Aadhaar-PAN status with Sandbox API
async function checkAadhaarPANStatusWithSandbox(aadhaarNumber, panNumber, consent, reason) {
  try {
    logger.info('Starting Aadhaar-PAN status check:', {
      aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
      panNumber: panNumber.toUpperCase(),
      consent,
      reason
    });

    logger.info('Starting Sandbox API status check...');

    // 1. Authenticate with Sandbox API
    logger.info('Authenticating with Sandbox API...');
    const authResponse = await fetch("https://api.sandbox.co.in/authenticate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.SANDBOX_API_KEY,
        "x-api-secret": process.env.SANDBOX_API_SECRET,
      },
    });

    const authData = await authResponse.json();
    
    if (!authResponse.ok) {
      throw new Error('Authentication failed');
    }

    const accessToken = authData.access_token || authData.data?.access_token;
    if (!accessToken) {
      throw new Error('Failed to authenticate with Sandbox API');
    }
    
    logger.info('Sandbox authentication successful');

    // 2. Check Aadhaar-PAN status with Sandbox API
    logger.info('Calling Sandbox Aadhaar-PAN status API...');
    
    const verifyResponse = await fetch("https://api.sandbox.co.in/kyc/pan-aadhaar/status", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "authorization": accessToken,
        "x-api-key": process.env.SANDBOX_API_KEY,
        "x-accept-cache": "true",
      },
      body: JSON.stringify({
        "@entity": "in.co.sandbox.kyc.pan_aadhaar.status",
        aadhaar_number: aadhaarNumber.replace(/\s/g, ''),
        pan: panNumber.toUpperCase(),
        consent: "Y",
        reason: "KYC Verification",
      }),
    });

    const verifyData = await verifyResponse.json();

    logger.info('Sandbox Aadhaar-PAN status check successful:', {
      status: verifyResponse.status,
      data: verifyData,
      aadhaarSeedingStatus: verifyData.data?.aadhaar_seeding_status,
      isValid: verifyData.data?.aadhaar_seeding_status === 'y' || verifyData.data?.status === 'valid'
    });

    // Return status check result
    // Consider aadhaar_seeding_status = 'y' as success
    const isValid = verifyData.data?.aadhaar_seeding_status === 'y' || verifyData.data?.status === 'valid';
    return {
      valid: isValid,
      message: isValid ? 'Aadhaar-PAN status check successful' : 'Aadhaar-PAN status check failed',
      sandboxApiResponse: verifyData,
      source: 'sandbox_api'
    };

  } catch (error) {
    // Extract only the necessary error information to avoid circular references
    const errorInfo = {
      message: error.message,
      status: error.status,
      statusText: error.statusText,
      data: error.data
    };
    
    logger.error('Sandbox API verification failed:', errorInfo);
    
    // Create a more detailed error with Sandbox API response
    const detailedError = new Error(`Verification failed: ${error.message}`);
    detailedError.sandboxApiResponse = error.data;
    detailedError.sandboxApiStatus = error.status;
    
    throw detailedError;
  }
}

// Simulate Aadhaar-PAN linking verification function
const simulateAadhaarPanLinking = async (record) => {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
  
  // Simulate verification logic
  const aadhaarNumber = record.aadhaarNumber;
  const panNumber = record.panNumber;
  const name = record.name;
  
  // Simple validation simulation
  const isValidAadhaar = /^\d{12}$/.test(aadhaarNumber.replace(/\s/g, ''));
  const isValidPAN = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(panNumber);
  const isValidName = name && name.length >= 2;
  
  let status = 'linked';
  let details = {};
  
  if (!isValidAadhaar) {
    status = 'invalid';
    details = {
      message: 'Invalid Aadhaar number format'
    };
  } else if (!isValidPAN) {
    status = 'invalid';
    details = {
      message: 'Invalid PAN number format'
    };
  } else if (!isValidName) {
    status = 'invalid';
    details = {
      message: 'Invalid name format'
    };
  } else {
    // Simulate random verification failures (15% chance)
    if (Math.random() < 0.15) {
      status = 'not-linked';
      details = {
        message: 'Aadhaar and PAN are not linked in government records'
      };
    }
  }
  
  return {
    status,
    details,
    processingTime: Math.floor(Math.random() * 2000) + 500
  };
};

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads/aadhaar-pan');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: async (req, file, cb) => {
    // Use timestamp to ensure each upload creates a unique file
    const originalName = path.parse(file.originalname).name;
    const extension = path.extname(file.originalname);
    const timestamp = Date.now();
    const randomSuffix = Math.random().toString(36).substring(2, 8);
    
    cb(null, `${originalName}_${timestamp}_${randomSuffix}${extension}`);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.xlsx', '.xls'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only Excel files (.xlsx, .xls) are allowed'));
    }
  }
});

// Get all Aadhaar-PAN batches for the user
router.get('/batches', protect, async (req, res) => {
  try {
    // Debug: Check total records for this user
    const totalRecords = await AadhaarPan.countDocuments({ userId: req.user.id });
    logger.info(`Total Aadhaar-PAN records for user ${req.user.id}: ${totalRecords}`);
    
    // Debug: Check unique batchIds for this user
    const uniqueBatchIds = await AadhaarPan.distinct('batchId', { userId: req.user.id });
    logger.info(`Unique batch IDs for user ${req.user.id}:`, uniqueBatchIds);

    const batches = await AadhaarPan.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id) } },
      {
        $group: {
          _id: '$batchId',
          totalRecords: { $sum: 1 },
          pendingRecords: {
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          linkedRecords: {
            $sum: { $cond: [{ $eq: ['$status', 'linked'] }, 1, 0] }
          },
          notLinkedRecords: {
            $sum: { $cond: [{ $eq: ['$status', 'not-linked'] }, 1, 0] }
          },
          invalidRecords: {
            $sum: { $cond: [{ $eq: ['$status', 'invalid'] }, 1, 0] }
          },
          errorRecords: {
            $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] }
          },
          createdAt: { $first: '$createdAt' },
          updatedAt: { $first: '$updatedAt' }
        }
      },
      { $sort: { createdAt: -1 } }
    ]);

    logger.info(`Found ${batches.length} batches for user ${req.user.id}`);
    res.json({
      success: true,
      data: batches
    });
  } catch (error) {
    logger.error('Error fetching Aadhaar-PAN batches:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch batches'
    });
  }
});

// Get all records for a user
router.get('/records', protect, async (req, res) => {
  const startTime = Date.now();
  let requestTimeout;
  
  try {
    // Set a timeout to prevent hanging requests (30 seconds)
    requestTimeout = setTimeout(() => {
      if (!res.headersSent) {
        logger.warn('Request timeout for /aadhaar-pan/records');
        res.status(504).json({
          success: false,
          message: 'Request timeout. Please try again with pagination (use ?page=1&limit=50)',
          error: 'Request took too long to process'
        });
      }
    }, 30000); // 30 second timeout

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50; // Default to 50 for better performance
    const maxLimit = 500; // Max limit
    const actualLimit = Math.min(limit, maxLimit);
    const skip = (page - 1) * actualLimit;
    const search = req.query.search || '';
    const status = req.query.status || '';
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder || 'desc';

    logger.info(`Fetching Aadhaar-PAN records: page=${page}, limit=${actualLimit}, userId=${req.user.id}`);

    // Build query
    let query = { userId: req.user.id };
    
    // Add search filter
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { panNumber: searchRegex },
        { aadhaarNumber: searchRegex },
        { name: searchRegex }
      ];
    }
    
    // Add status filter
    if (status) {
      query.status = status;
    }

    // Get total count for pagination (with timeout protection)
    const totalRecords = await AadhaarPan.countDocuments(query).maxTimeMS(5000);
    const totalPages = Math.ceil(totalRecords / actualLimit);

    // Build sort object
    const sortObj = {};
    sortObj[sortBy] = sortOrder === 'asc' ? 1 : -1;

    // Get paginated records (with timeout protection)
    const records = await AadhaarPan.find(query)
      .sort(sortObj)
      .skip(skip)
      .limit(actualLimit)
      .maxTimeMS(10000) // 10 second timeout for query
      .lean();

    logger.info(`Found ${records.length} records, starting decryption...`);

    // Decrypt sensitive data in parallel for better performance
    const decryptedRecords = await Promise.all(
      records.map(async (record) => {
        try {
          // Create a temporary AadhaarPan instance to use the decryptData method
          const tempRecord = new AadhaarPan(record);
          return tempRecord.decryptData();
        } catch (error) {
          logger.error(`Decryption error for record ${record._id}:`, error.message);
          // Return original record with encrypted fields marked
          return {
            ...record,
            panNumber: record.panNumber ? '[ENCRYPTED]' : '',
            aadhaarNumber: record.aadhaarNumber ? '[ENCRYPTED]' : '',
            name: record.name ? '[ENCRYPTED]' : ''
          };
        }
      })
    );

    const processingTime = Date.now() - startTime;
    logger.info(`Records fetched and decrypted in ${processingTime}ms`);

    // Clear timeout since we're responding
    clearTimeout(requestTimeout);

    res.json({
      success: true,
      data: decryptedRecords,
      pagination: {
        currentPage: page,
        totalPages: totalPages,
        totalRecords: totalRecords,
        hasNext: page < totalPages,
        hasPrev: page > 1,
        limit: actualLimit
      },
      processingTime: processingTime
    });
  } catch (error) {
    // Clear timeout on error
    if (requestTimeout) {
      clearTimeout(requestTimeout);
    }
    
    logger.error('Error fetching Aadhaar-PAN records:', error);
    
    // Don't send response if already sent
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        message: 'Failed to fetch records',
        error: error.message
      });
    }
  }
});

// Get batch details
router.get('/batch/:batchId', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    const records = await AadhaarPan.find({
      userId: req.user.id,
      batchId: batchId
    }).select('-__v');

    // Decrypt the records before sending to frontend
    const decryptedRecords = records.map(record => {
      try {
        return record.decryptData();
      } catch (error) {
        logger.error('Error decrypting record:', error);
        return record.toObject();
      }
    });

    const stats = await AadhaarPan.getBatchStats(batchId);

    res.json({
      success: true,
      data: {
        batchId,
        records: decryptedRecords,
        stats
      }
    });
  } catch (error) {
    logger.error('Error fetching batch details:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch batch details'
    });
  }
});

// Upload Aadhaar-PAN file
router.post('/upload', protect, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    const workbook = XLSX.readFile(req.file.path);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(worksheet);

    if (data.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No data found in the Excel file'
      });
    }

    // Validate required columns with flexible column name matching
    const requiredColumns = ['panNumber', 'aadhaarNumber', 'name'];
    const firstRow = data[0];
    
    // Debug logging
    logger.info('Uploaded file columns:', Object.keys(firstRow));
    logger.info('Required columns:', requiredColumns);
    
    // Column name mapping for flexibility
    const columnMapping = {
      'panNumber': ['panNumber', 'PAN No', 'PAN', 'pan', 'PANNumber', 'pan_number'],
      'aadhaarNumber': ['aadhaarNumber', 'AADHAAR', 'Aadhaar', 'aadhaar', 'Aadhaar Number', 'aadhaar_number'],
      'name': ['name', 'Name', 'NAME', 'fullName', 'Full Name', 'full_name']
    };
    
    const missingColumns = [];
    const columnMap = {};
    
    // Check each required column
    requiredColumns.forEach(requiredCol => {
      const possibleNames = columnMapping[requiredCol];
      let found = false;
      
      for (const possibleName of possibleNames) {
        if (firstRow.hasOwnProperty(possibleName)) {
          columnMap[requiredCol] = possibleName;
          found = true;
          logger.info(`Column ${requiredCol} found as: ${possibleName}`);
          break;
        }
      }
      
      if (!found) {
        missingColumns.push(requiredCol);
        logger.info(`Column ${requiredCol} not found`);
      }
    });
    
    if (missingColumns.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required columns: ${missingColumns.join(', ')}`,
        debug: {
          foundColumns: Object.keys(firstRow),
          requiredColumns: requiredColumns,
          columnMapping: columnMapping
        }
      });
    }

    // Check if this is a PAN KYC file (contains fatherName or dateOfBirth columns)
    // Only reject if it's clearly a PAN KYC file (has fatherName AND dateOfBirth but missing aadhaarNumber)
    const panKycIndicators = ['fatherName', 'dateOfBirth', 'DOB', 'dob', 'Father Name', 'father_name'];
    const foundPanKycColumns = Object.keys(firstRow).filter(col => 
      panKycIndicators.some(indicator => 
        col.toLowerCase().includes(indicator.toLowerCase())
      )
    );
    
    // Only reject if it's clearly a PAN KYC file (has fatherName AND dateOfBirth but missing aadhaarNumber)
    const hasFatherName = foundPanKycColumns.some(col => 
      col.toLowerCase().includes('father')
    );
    const hasDateOfBirth = foundPanKycColumns.some(col => 
      col.toLowerCase().includes('dob') || col.toLowerCase().includes('dateofbirth')
    );
    const hasAadhaarNumber = Object.keys(firstRow).some(col => 
      columnMapping.aadhaarNumber.some(indicator => 
        col.toLowerCase().includes(indicator.toLowerCase())
      )
    );
    
    // Only reject if it has both fatherName and dateOfBirth but no aadhaarNumber
    if (hasFatherName && hasDateOfBirth && !hasAadhaarNumber) {
      return res.status(400).json({
        success: false,
        message: 'This appears to be a PAN KYC file. Please upload it to the PAN KYC module instead. Aadhaar-PAN linking requires: aadhaarNumber, panNumber, and name columns.',
        debug: {
          foundPanKycColumns: foundPanKycColumns,
          foundColumns: Object.keys(firstRow),
          hasAadhaarNumber: hasAadhaarNumber
        }
      });
    }

    // Generate unique batch ID with timestamp to ensure each upload is a new entry
    const originalName = path.parse(req.file.originalname).name;
    const timestamp = Date.now();
    const randomSuffix = Math.random().toString(36).substring(2, 8);
    const batchId = `${originalName}_${timestamp}_${randomSuffix}`;
    const records = [];

    // Process each row
    for (let i = 0; i < data.length; i++) {
      const row = data[i];
      
      // Extract values with proper handling
      const panNumberValue = row[columnMap.panNumber]?.toString().trim();
      const aadhaarNumberValue = row[columnMap.aadhaarNumber]?.toString().trim();
      const nameValue = row[columnMap.name]?.toString().trim();
      
      // Skip rows with missing required data
      if (!panNumberValue || !aadhaarNumberValue || !nameValue) {
        logger.info(`Skipping row ${i + 1}: Missing required data - PAN: ${panNumberValue}, Aadhaar: ${aadhaarNumberValue}, Name: ${nameValue}`);
        continue;
      }
      
      const record = new AadhaarPan({
        userId: req.user.id,
        batchId: batchId,
        panNumber: panNumberValue,
        aadhaarNumber: aadhaarNumberValue,
        name: nameValue,
        dateOfBirth: row.dateOfBirth || row.DOB || row['Date of Birth']?.toString().trim(),
        gender: row.gender || row.Gender?.toString().trim(),
        fatherName: row.fatherName || row['Father Name'] || row.father_name || '',
        fileUpload: {
          originalName: req.file.originalname,
          fileName: req.file.filename,
          fileSize: req.file.size,
          uploadDate: new Date()
        }
      });

      records.push(record);
    }

    // Save records individually to ensure middleware runs properly
    const savedRecords = [];
    for (const record of records) {
      try {
        await record.save();
        savedRecords.push(record);
      } catch (error) {
        logger.error(`Error saving record:`, error);
        // Continue with other records even if one fails
      }
    }

    // Log the upload event
    await logAadhaarPanEvent('aadhaar_pan_upload', req.user.id, {
      batchId,
      recordCount: savedRecords.length,
      fileName: req.file.originalname
    }, req);

    res.json({
      success: true,
      message: `Successfully uploaded ${savedRecords.length} records`,
      data: {
        batchId,
        recordCount: savedRecords.length,
        fileName: req.file.originalname
      }
    });

  } catch (error) {
    logger.error('Error uploading Aadhaar-PAN file:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload file'
    });
  }
});

// Process batch verification
router.post('/batch/:batchId/process', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    
    // Get pending records
    const pendingRecords = await AadhaarPan.find({
      userId: req.user.id,
      batchId: batchId,
      status: 'pending'
    });

    if (pendingRecords.length === 0) {
      return res.json({
        success: true,
        message: 'No pending records to process'
      });
    }

    // Process records in batches of 10
    const batchSize = 10;
    const results = [];

    for (let i = 0; i < pendingRecords.length; i += batchSize) {
      const batch = pendingRecords.slice(i, i + batchSize);
      
      for (const record of batch) {
        try {
          // Simulate API call (replace with actual API integration)
          const startTime = Date.now();
          
          // Mock linking verification logic
          const randomValue = Math.random();
          let status, linkingStatus;
          
          if (randomValue > 0.6) {
            status = 'linked';
            linkingStatus = 'linked';
          } else if (randomValue > 0.3) {
            status = 'not-linked';
            linkingStatus = 'not-linked';
          } else {
            status = 'invalid';
            linkingStatus = 'invalid';
          }
          
          const processingTime = Date.now() - startTime;
          
          // Update record
          record.status = status;
          record.isProcessed = true;
          record.processedAt = new Date();
          record.processingTime = processingTime;
          record.linkingDetails = {
            apiResponse: {
              status: status,
              linkingStatus: linkingStatus,
              timestamp: new Date(),
              processingTime: processingTime
            },
            linkingDate: new Date(),
            linkingStatus: linkingStatus,
            lastChecked: new Date(),
            remarks: status === 'linked' ? 'Aadhaar-PAN linked successfully' : 
                     status === 'not-linked' ? 'Aadhaar-PAN not linked' : 'Invalid data provided'
          };
          
          await record.save();
          
                    // Include Sandbox API response in error details
          results.push({
            recordId: record._id,
            status: status,
            linkingStatus: linkingStatus,
            processingTime: processingTime
          });

          // Log verification event
          await logAadhaarPanEvent('aadhaar_pan_verification', req.user.id, {
            recordId: record._id,
            batchId: batchId,
            status: status,
            linkingStatus: linkingStatus,
            processingTime: processingTime
          }, req);

        } catch (error) {
          logger.error(`Error processing record ${record._id}:`, error);
          
          record.status = 'error';
          record.errorMessage = error.message;
          record.isProcessed = true;
          record.processedAt = new Date();
          await record.save();
          
                    // Include Sandbox API response in error details
          results.push({
            recordId: record._id,
            status: 'error',
            error: error.message,
            sandboxApiResponse: error.sandboxApiResponse,
            sandboxApiStatus: error.sandboxApiStatus
          });
        }
      }
      
      // Add delay between batches to avoid overwhelming the API
      if (i + batchSize < pendingRecords.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    res.json({
      success: true,
      message: `Processed ${results.length} records`,
      data: {
        batchId,
        results,
        summary: {
          total: results.length,
          linked: results.filter(r => r.status === 'linked').length,
          notLinked: results.filter(r => r.status === 'not-linked').length,
          invalid: results.filter(r => r.status === 'invalid').length,
          error: results.filter(r => r.status === 'error').length
        }
      }
    });

  } catch (error) {
    logger.error('Error processing batch:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process batch'
    });
  }
});

// Get user statistics
router.get('/stats', protect, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const stats = await AadhaarPan.getUserStats(req.user.id, parseInt(days));
    
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Error fetching Aadhaar-PAN stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch statistics'
    });
  }
});

// Delete batch and all its records
router.delete('/batch/:batchId', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    
    // Find all records for this batch that belong to the user
    const records = await AadhaarPan.find({
      userId: new mongoose.Types.ObjectId(req.user.id),
      batchId: batchId
    });

    if (records.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Batch not found or access denied'
      });
    }

    // Delete all records for this batch
    const deleteResult = await AadhaarPan.deleteMany({
      userId: new mongoose.Types.ObjectId(req.user.id),
      batchId: batchId
    });

    // Log deletion event
    await logAadhaarPanEvent('batch_deleted', req.user.id, {
      batchId,
      recordCount: records.length
    }, req);

    res.json({
      success: true,
      message: `Successfully deleted batch with ${deleteResult.deletedCount} records`,
      data: {
        batchId,
        deletedRecords: deleteResult.deletedCount
      }
    });

  } catch (error) {
    logger.error('Error deleting batch:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete batch'
    });
  }
});

// Download batch report
router.get('/batch/:batchId/download', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    const { format = 'csv' } = req.query;
    
    const records = await AadhaarPan.find({
      userId: req.user.id,
      batchId: batchId
    }).select('-__v');

    if (records.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No records found for this batch'
      });
    }

    // Log download event
    await logAadhaarPanEvent('report_downloaded', req.user.id, {
      batchId,
      format,
      recordCount: records.length
    }, req);

    if (format === 'json') {
      res.json({
        success: true,
        data: records
      });
    } else {
      // Generate CSV
      const csvData = records.map(record => ({
        'PAN Number': record.panNumber,
        'Aadhaar Number': record.aadhaarNumber,
        'Name': record.name,
        'Date of Birth': record.dateOfBirth,
        'Gender': record.gender,
        'Status': record.status,
        'Linking Status': record.linkingDetails?.linkingStatus,
        'Processing Time (ms)': record.processingTime,
        'Processed At': record.processedAt,
        'Created At': record.createdAt
      }));

      const csv = XLSX.utils.json_to_sheet(csvData);
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, csv, 'Aadhaar-PAN Report');
      
      const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'csv' });
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="aadhaar-pan-${batchId}.csv"`);
      res.send(buffer);
    }

  } catch (error) {
    logger.error('Error downloading report:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to download report'
    });
  }
});

// Single Aadhaar-PAN linking verification
router.post('/verify-single', protect, async (req, res) => {
  try {
    const { aadhaarNumber, panNumber, name } = req.body;

    // Validate required fields
    if (!aadhaarNumber || !panNumber || !name) {
      return res.status(400).json({
        success: false,
        message: 'Aadhaar Number, PAN Number, and Name are required'
      });
    }

    // Validate Aadhaar format
    const aadhaarRegex = /^\d{12}$/;
    if (!aadhaarRegex.test(aadhaarNumber.replace(/\s/g, ''))) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Aadhaar number format'
      });
    }

    // Validate PAN format
    const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
    if (!panRegex.test(panNumber.toUpperCase())) {
      return res.status(400).json({
        success: false,
        message: 'Invalid PAN number format'
      });
    }

    // Create a temporary record for verification
    const tempRecord = new AadhaarPan({
      userId: req.user.id,
      batchId: 'SINGLE_LINKING_' + Date.now(),
      aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
      panNumber: panNumber.toUpperCase(),
      name: name.trim(),
      status: 'pending'
    });

    // Simulate verification process (replace with actual API call)
    const verificationResult = await simulateAadhaarPanLinking(tempRecord);

    // Update record with verification result
    tempRecord.status = verificationResult.status;
    tempRecord.verificationDetails = verificationResult.details;
    tempRecord.processedAt = new Date();
    tempRecord.processingTime = verificationResult.processingTime;

    await tempRecord.save();

    // Log verification event
    await logAadhaarPanEvent('single_linking_verified', req.user.id, {
      aadhaarNumber: tempRecord.aadhaarNumber,
      panNumber: tempRecord.panNumber,
      name: tempRecord.name,
      status: tempRecord.status
    }, req);

    // Remove message, confidence, and dataMatch from verificationDetails
    const { message, confidence, dataMatch, ...cleanVerificationDetails } = tempRecord.verificationDetails || {};
    
    res.json({
      success: true,
      message: 'Aadhaar-PAN linking verification completed',
      data: {
        aadhaarNumber: tempRecord.aadhaarNumber,
        panNumber: tempRecord.panNumber,
        name: tempRecord.name,
        status: tempRecord.status,
        verificationDetails: cleanVerificationDetails,
        processedAt: tempRecord.processedAt,
        processingTime: tempRecord.processingTime
      }
    });

  } catch (error) {
    logger.error('Error in single Aadhaar-PAN linking verification:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify Aadhaar-PAN linking'
    });
  }
});

// Get verification statistics
router.get('/stats', protect, async (req, res) => {
  try {
    const { timeframe = 'all' } = req.query;
    
    // Build date filter based on timeframe
    let dateFilter = {};
    const now = new Date();
    
    if (timeframe === 'month') {
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
      dateFilter = { createdAt: { $gte: startOfMonth } };
    } else if (timeframe === 'week') {
      const startOfWeek = new Date(now.setDate(now.getDate() - now.getDay()));
      startOfWeek.setHours(0, 0, 0, 0);
      dateFilter = { createdAt: { $gte: startOfWeek } };
    }

    // Aggregate statistics
    const stats = await AadhaarPan.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id), ...dateFilter } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          linked: { $sum: { $cond: [{ $eq: ['$status', 'linked'] }, 1, 0] } },
          'not-linked': { $sum: { $cond: [{ $eq: ['$status', 'not-linked'] }, 1, 0] } },
          pending: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
          invalid: { $sum: { $cond: [{ $eq: ['$status', 'invalid'] }, 1, 0] } },
          error: { $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] } }
        }
      }
    ]);

    const result = stats[0] || { total: 0, linked: 0, 'not-linked': 0, pending: 0, invalid: 0, error: 0 };
    const successRate = result.total > 0 ? (result.linked / result.total) * 100 : 0;

    res.json({
      success: true,
      data: {
        ...result,
        successRate
      }
    });

  } catch (error) {
    logger.error('Error fetching Aadhaar-PAN linking stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch verification statistics'
    });
  }
});

// Get monthly verification statistics
router.get('/monthly-stats', protect, async (req, res) => {
  try {
    const { timeframe = 'all' } = req.query;
    
    // Build date filter based on timeframe
    let dateFilter = {};
    const now = new Date();
    
    if (timeframe === 'month') {
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
      dateFilter = { createdAt: { $gte: startOfMonth } };
    } else if (timeframe === 'week') {
      const startOfWeek = new Date(now.setDate(now.getDate() - now.getDay()));
      startOfWeek.setHours(0, 0, 0, 0);
      dateFilter = { createdAt: { $gte: startOfWeek } };
    }

    // Aggregate monthly statistics
    const monthlyStats = await AadhaarPan.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id), ...dateFilter } },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          total: { $sum: 1 },
          linked: { $sum: { $cond: [{ $eq: ['$status', 'linked'] }, 1, 0] } },
          'not-linked': { $sum: { $cond: [{ $eq: ['$status', 'not-linked'] }, 1, 0] } },
          pending: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
          invalid: { $sum: { $cond: [{ $eq: ['$status', 'invalid'] }, 1, 0] } },
          error: { $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] } }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } }
    ]);

    // Format the results
    const formattedStats = monthlyStats.map(stat => ({
      month: new Date(stat._id.year, stat._id.month - 1).toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'long' 
      }),
      total: stat.total,
      linked: stat.linked,
      'not-linked': stat['not-linked'],
      pending: stat.pending,
      invalid: stat.invalid,
      error: stat.error
    }));

    res.json({
      success: true,
      data: formattedStats
    });

  } catch (error) {
    logger.error('Error fetching monthly Aadhaar-PAN linking stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch monthly statistics'
    });
  }
});

// Get recent verifications
router.get('/recent-verifications', protect, async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    const recentVerifications = await AadhaarPan.find({
      userId: new mongoose.Types.ObjectId(req.user.id)
    })
    .select('aadhaarNumber panNumber name status processedAt batchId')
    .sort({ createdAt: -1 })
    .limit(parseInt(limit))
    .lean();

    // Decrypt the records before sending to frontend
    const decryptedVerifications = recentVerifications.map(record => {
      try {
        // Create a temporary document instance to use decryptData method
        const tempDoc = new AadhaarPan(record);
        return tempDoc.decryptData();
      } catch (error) {
        logger.error('Error decrypting record:', error);
        return record;
      }
    });

    res.json({
      success: true,
      data: decryptedVerifications
    });

  } catch (error) {
    logger.error('Error fetching recent Aadhaar-PAN linking verifications:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch recent verifications'
    });
  }
});

// Aadhaar-PAN Verification endpoint (frontend calls this for batch verification)
router.post('/verify', protect, async (req, res) => {
  try {
    console.log('🔍 Received Aadhaar-PAN verification request:', {
      body: req.body,
      contentType: req.get('Content-Type'),
      user: req.user.id
    });

    // Check if this is a batch verification request
    if (req.body.recordIds && Array.isArray(req.body.recordIds)) {
      console.log('📦 Processing Aadhaar-PAN batch verification for records:', req.body.recordIds.length, 'records');
      
      const results = [];
      const totalRecords = req.body.recordIds.length;
      
      for (let i = 0; i < req.body.recordIds.length; i++) {
        const recordId = req.body.recordIds[i];
        console.log(`🔄 Processing Aadhaar-PAN record ${i + 1}/${totalRecords}: ${recordId}`);
        
        try {
          // Find the record
          const record = await AadhaarPan.findOne({
            _id: recordId,
            userId: req.user.id
          });

          if (!record) {
                      // Include Sandbox API response in error details
          results.push({
              recordId,
              status: 'error',
              error: 'Record not found'
            });
            continue;
          }

          // Decrypt the record data
          const decryptedRecord = record.decryptData();
          
          // Check status with Sandbox API
          const verificationResult = await checkAadhaarPANStatusWithSandbox(
            decryptedRecord.aadhaarNumber,
            decryptedRecord.panNumber,
            'Y',
            'KYC Verification'
          );

          // Update record with verification result
          record.status = verificationResult.valid ? 'linked' : 'not-linked';
          record.verificationDetails = {
            ...verificationResult,
            verifiedAt: new Date(),
            source: 'sandbox_api'
          };
          record.processedAt = new Date();

          await record.save();

          // Log verification event
          await logAadhaarPanEvent('record_verified', req.user.id, {
            aadhaarNumber: record.aadhaarNumber,
            panNumber: record.panNumber,
            status: record.status
          }, req);

                    // Include Sandbox API response in error details
          results.push({
            recordId,
            status: record.status,
            result: verificationResult,
            details: {
              aadhaarNumber: decryptedRecord.aadhaarNumber,
              panNumber: decryptedRecord.panNumber,
              name: decryptedRecord.name,
              dateOfBirth: decryptedRecord.dateOfBirth
            },
            verifiedAt: record.verifiedAt,
            source: 'sandbox_api'
          });

        } catch (error) {
          // Extract only the necessary error information to avoid circular references
          const errorInfo = {
            message: error.message,
            stack: error.stack?.split('\n')[0] // Only first line of stack trace
          };
          
          console.error(`Error processing record ${recordId}:`, errorInfo);
                    // Include Sandbox API response in error details
          results.push({
            recordId,
            status: 'error',
            error: error.message,
            sandboxApiResponse: error.sandboxApiResponse,
            sandboxApiStatus: error.sandboxApiStatus
          });
        }

        // Reduced delay between API calls for better performance
        await new Promise(resolve => setTimeout(resolve, 200));
      }

      console.log(`✅ Batch processing completed: ${totalRecords} records processed`);

      // Calculate summary
      const verified = results.filter(r => r.status === 'linked').length;
      const rejected = results.filter(r => r.status === 'not-linked').length;
      const error = results.filter(r => r.status === 'error').length;

      res.json({
        success: true,
        message: `Processed ${totalRecords} records`,
        data: {
          total: totalRecords,
          verified,
          rejected,
          error,
          sourceBreakdown: {
            sandbox_api: verified + rejected,
            error: error
          },
          results
        }
      });

    } else {
      // Single verification (if needed)
      res.status(400).json({
        success: false,
        message: 'Batch verification requires recordIds array'
      });
    }

  } catch (error) {
    // Extract only the necessary error information to avoid circular references
    const errorInfo = {
      message: error.message,
      stack: error.stack?.split('\n')[0] // Only first line of stack trace
    };
    
    console.error('Error in Aadhaar-PAN batch verification:', errorInfo);
    res.status(500).json({
      success: false,
      message: 'Failed to process Aadhaar-PAN verification'
    });
  }
});

// Aadhaar-PAN Status API using Sandbox API - handles both single and batch verification
router.post('/status', protect, async (req, res) => {
  try {
    console.log('🔍 Received Aadhaar-PAN status request:', {
      body: req.body,
      contentType: req.get('Content-Type'),
      user: req.user.id
    });

    // Check if this is a batch verification request
    if (req.body.recordIds && Array.isArray(req.body.recordIds)) {
      console.log('📦 Processing Aadhaar-PAN batch verification for records:', req.body.recordIds.length, 'records');
      
      // Set a longer timeout for batch processing
      req.setTimeout(300000); // 5 minutes timeout
      res.setTimeout(300000); // 5 minutes timeout
      
      const { recordIds } = req.body;
      const totalRecords = recordIds.length;
      const results = [];

      // Process each record
      for (let i = 0; i < totalRecords; i++) {
        const recordId = recordIds[i];
        console.log(`🔄 Processing Aadhaar-PAN record ${i + 1}/${totalRecords}: ${recordId}`);
        
        // Log progress every 5 records
        if ((i + 1) % 5 === 0) {
          console.log(`📊 Progress: ${i + 1}/${totalRecords} records processed (${Math.round(((i + 1) / totalRecords) * 100)}%)`);
        }

        try {
          // Find the record
          const record = await AadhaarPan.findById(recordId);
          if (!record) {
                      // Include Sandbox API response in error details
          results.push({
              recordId,
              status: 'error',
              error: 'Record not found'
            });
            continue;
          }

          // Check if user owns this record
          if (record.userId.toString() !== req.user.id) {
                      // Include Sandbox API response in error details
          results.push({
              recordId,
              status: 'error',
              error: 'Access denied'
            });
            continue;
          }

          // Decrypt the record data
          const decryptedRecord = record.decryptData();

          // Check status with Sandbox API
          const verificationResult = await checkAadhaarPANStatusWithSandbox(
            decryptedRecord.aadhaarNumber,
            decryptedRecord.panNumber,
            'Y',
            'KYC Verification'
          );

          // Update record status
          record.status = verificationResult.valid ? 'linked' : 'not-linked';
          record.verificationDetails = {
            ...verificationResult,
            verifiedAt: new Date(),
            source: 'sandbox_api'
          };
          record.processedAt = new Date();

          await record.save();

          // Log verification event
          await logAadhaarPanEvent('record_verified', req.user.id, {
            aadhaarNumber: record.aadhaarNumber,
            panNumber: record.panNumber,
            status: record.status
          }, req);

                    // Include Sandbox API response in error details
          results.push({
            recordId,
            status: record.status,
            result: verificationResult,
            details: {
              aadhaarNumber: decryptedRecord.aadhaarNumber,
              panNumber: decryptedRecord.panNumber,
              name: decryptedRecord.name,
              dateOfBirth: decryptedRecord.dateOfBirth
            },
            verifiedAt: record.verifiedAt,
            source: 'sandbox_api'
          });

        } catch (error) {
          // Extract only the necessary error information to avoid circular references
          const errorInfo = {
            message: error.message,
            stack: error.stack?.split('\n')[0] // Only first line of stack trace
          };
          
          console.error(`Error processing record ${recordId}:`, errorInfo);
                    // Include Sandbox API response in error details
          results.push({
            recordId,
            status: 'error',
            error: error.message,
            sandboxApiResponse: error.sandboxApiResponse,
            sandboxApiStatus: error.sandboxApiStatus
          });
        }

        // Reduced delay between API calls for better performance
        await new Promise(resolve => setTimeout(resolve, 200));
      }

      // Calculate summary
      const verified = results.filter(r => r.status === 'linked').length;
      const rejected = results.filter(r => r.status === 'not-linked').length;
      const error = results.filter(r => r.status === 'error').length;

      res.json({
        success: true,
        message: `Processed ${totalRecords} records`,
        data: {
          total: totalRecords,
          verified,
          rejected,
          error,
          sourceBreakdown: {
            sandbox_api: verified + rejected,
            error: error
          },
          results
        }
      });

    } else {
      // Single verification
      const { aadhaarNumber, panNumber } = req.body;

      // Validate required fields
      if (!aadhaarNumber || !panNumber) {
        return res.status(400).json({
          success: false,
          message: 'Aadhaar Number and PAN Number are required'
        });
      }

      // Validate Aadhaar format
      const aadhaarRegex = /^\d{12}$/;
      if (!aadhaarRegex.test(aadhaarNumber.replace(/\s/g, ''))) {
        return res.status(400).json({
          success: false,
          message: 'Invalid Aadhaar number format'
        });
      }

      // Validate PAN format
      const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
      if (!panRegex.test(panNumber.toUpperCase())) {
        return res.status(400).json({
          success: false,
          message: 'Invalid PAN number format'
        });
      }

      logger.info('Starting Aadhaar-PAN status check:', {
        aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
        panNumber: panNumber.toUpperCase()
      });

      logger.info('Authenticating with Sandbox API...');

      // Call Sandbox API for Aadhaar-PAN status
      const axios = require('axios');
      
      // First authenticate with Sandbox API
      const authResponse = await axios.post('https://api.sandbox.co.in/authenticate', {
        x_api_key: process.env.SANDBOX_API_KEY,
        x_api_secret: process.env.SANDBOX_API_SECRET
      }, {
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.SANDBOX_API_KEY,
          'x-api-secret': process.env.SANDBOX_API_SECRET
        }
      });

      if (!authResponse.data.access_token) {
        throw new Error('Failed to authenticate with Sandbox API');
      }

      const accessToken = authResponse.data.access_token;
      logger.info('Sandbox authentication successful');
      
      // Now call the Aadhaar-PAN status API
      logger.info('Calling Sandbox Aadhaar-PAN status API...');
      const options = {
        method: 'POST',
        url: 'https://api.sandbox.co.in/kyc/pan-aadhaar/status',
        headers: {
          accept: 'application/json', 
          'content-type': 'application/json',
          'authorization': accessToken,
          'x-api-key': process.env.SANDBOX_API_KEY
        },
        data: {
          '@entity': 'in.co.sandbox.kyc.pan_aadhaar.status',
          aadhaar_number: aadhaarNumber.replace(/\s/g, ''),
          pan: panNumber.toUpperCase(),
          consent: "Y",
          reason: "KYC Verification",  
        }
      };

      try {
        const response = await axios.request(options);
        
        logger.info('Sandbox API response received:', {
          status: response.status,
          data: response.data
        });

        // Create a temporary record for logging
        const tempRecord = new AadhaarPan({
          userId: req.user.id,
          batchId: 'STATUS_CHECK_' + Date.now(),
          aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
          panNumber: panNumber.toUpperCase(),
          name: 'Status Check',
          status: 'status_checked',
          verificationDetails: {
            apiResponse: response.data,
            source: 'sandbox_api',
            verificationDate: new Date()
            },
          processedAt: new Date()
        });

        await tempRecord.save();

        // Log verification event
        await logAadhaarPanEvent('status_check_completed', req.user.id, {
          aadhaarNumber: tempRecord.aadhaarNumber,
          panNumber: tempRecord.panNumber,
          status: 'status_checked'
        }, req);

        res.json({
          success: true,
          message: 'Aadhaar-PAN status check completed',
          data: {
            aadhaarNumber: tempRecord.aadhaarNumber,
            panNumber: tempRecord.panNumber,
            status: 'status_checked',
            apiResponse: response.data,
            processedAt: tempRecord.processedAt,
            source: 'sandbox_api'
          }
        });

      } catch (apiError) {
        logger.error('Sandbox API error:', apiError);
        
        // Create error record
        const tempRecord = new AadhaarPan({
          userId: req.user.id,
          batchId: 'STATUS_CHECK_' + Date.now(),
          aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
          panNumber: panNumber.toUpperCase(),
          name: 'Status Check',
          status: 'error',
          errorMessage: apiError.message,
          verificationDetails: {
            error: apiError.message,
            source: 'sandbox_api_error',
            verificationDate: new Date()
          },
          processedAt: new Date()
        });

        await tempRecord.save();

        res.status(500).json({
          success: false,
          message: 'Failed to check Aadhaar-PAN status',
          error: apiError.message,
          data: {
            aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
            panNumber: panNumber.toUpperCase(),
            status: 'error',
            processedAt: new Date(),
            source: 'sandbox_api_error'
          }
        });
      }
    }

  } catch (error) {
    logger.error('Error in Aadhaar-PAN status check:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check Aadhaar-PAN status'
    });
  }
});

module.exports = router;

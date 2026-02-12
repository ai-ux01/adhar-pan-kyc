const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const XLSX = require('xlsx');
const { protect } = require('../middleware/auth');
const PanKyc = require('../models/PanKyc');
const { logPanKycEvent } = require('../services/auditService');
const logger = require('../utils/logger');
const { verifyPAN } = require('../services/panVerificationService');

// Real-time Sandbox API integration - no simulation needed
// const simulatePANVerification = async (record) => {
//   // Function disabled - using real Sandbox API instead
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
  
  // Simulate verification logic
  const panNumber = record.panNumber;
  const name = record.name;
  const dateOfBirth = record.dateOfBirth;
  
  // Simple validation simulation
  const isValidPAN = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(panNumber);
  const isValidName = name && name.length >= 2;
  const isValidDOB = dateOfBirth && dateOfBirth.length > 0;
  
  let status = 'verified';
  let details = {
    message: 'Verification successful',
    confidence: 95,
    dataMatch: true
  };
  
  if (!isValidPAN) {
    status = 'rejected';
    details = {
      message: 'Invalid PAN number format',
      confidence: 0,
      dataMatch: false
    };
  } else if (!isValidName) {
    status = 'rejected';
    details = {
      message: 'Invalid name format',
      confidence: 0,
      dataMatch: false
    };
  } else if (!isValidDOB) {
    status = 'rejected';
    details = {
      message: 'Invalid date of birth',
      confidence: 0,
      dataMatch: false
    };
  } else {
    // Simulate random verification failures (10% chance)
    if (Math.random() < 0.1) {
      status = 'rejected';
      details = {
        message: 'Data mismatch with government records',
        confidence: 30,
        dataMatch: false
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
    const uploadDir = path.join(__dirname, '../../uploads/pan-kyc');
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

// Get all PAN KYC batches for the user
router.get('/batches', protect, async (req, res) => {
  try {
    const batches = await PanKyc.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id) } },
      {
        $group: {
          _id: '$batchId',
          totalRecords: { $sum: 1 },
          pendingRecords: {
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          verifiedRecords: {
            $sum: { $cond: [{ $eq: ['$status', 'verified'] }, 1, 0] }
          },
          rejectedRecords: {
            $sum: { $cond: [{ $eq: ['$status', 'rejected'] }, 1, 0] }
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

    res.json({
      success: true,
      data: batches
    });
  } catch (error) {
    logger.error('Error fetching PAN KYC batches:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch batches'
    });
  }
});

// Get all records for a user
router.get('/records', protect, async (req, res) => {
  try {
    const records = await PanKyc.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .lean();

    res.json({
      success: true,
      data: records
    });
  } catch (error) {
    logger.error('Error fetching PAN KYC records:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch records',
      error: error.message
    });
  }
});

// Get batch details
router.get('/batch/:batchId', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    const records = await PanKyc.find({
      userId: new mongoose.Types.ObjectId(req.user.id),
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

    const stats = await PanKyc.getBatchStats(batchId);

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

// Upload PAN KYC file
router.post('/upload', protect, upload.single('file'), async (req, res) => {
  try {
    console.log('🔍 Upload request received');
    console.log('Request body:', req.body);
    console.log('Request file:', req.file);
    console.log('Request headers:', req.headers);
    
    if (!req.file) {
      console.log('❌ No file uploaded');
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }
    
    console.log('✅ File uploaded successfully');
    console.log('File details:', {
      originalname: req.file.originalname,
      filename: req.file.filename,
      path: req.file.path,
      size: req.file.size,
      mimetype: req.file.mimetype
    });

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
    const requiredColumns = ['panNumber', 'name', 'dateOfBirth'];
    const firstRow = data[0];
    
    // Debug logging
    logger.info('Uploaded file columns:', Object.keys(firstRow));
    logger.info('Required columns:', requiredColumns);
    
    // Column name mapping for flexibility
    const columnMapping = {
      'panNumber': ['panNumber', 'PAN No', 'PAN', 'pan', 'PANNumber', 'pan_number', 'PAN No.'],
      'name': ['name', 'Name', 'NAME', 'fullName', 'Full Name', 'full_name', 'FULL NAME'],
      'dateOfBirth': ['dateOfBirth', 'DOB', 'dob', 'Date of Birth', 'dateOfBirth', 'birthDate', 'Birth Date', 'BIRTH DATE']
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

    // Check if this is an Aadhaar-PAN linking file (contains only aadhaarNumber, panNumber, name)
    const aadhaarPanIndicators = ['aadhaarNumber', 'AADHAAR', 'Aadhaar', 'aadhaar'];
    const foundAadhaarPanColumns = Object.keys(firstRow).filter(col => 
      aadhaarPanIndicators.some(indicator => 
        col.toLowerCase().includes(indicator.toLowerCase())
      )
    );
    
    if (foundAadhaarPanColumns.length > 0 && Object.keys(firstRow).length <= 3) {
      return res.status(400).json({
        success: false,
        message: 'This appears to be an Aadhaar-PAN linking file. Please upload it to the Aadhaar-PAN linking module instead. PAN KYC requires: panNumber, name, and dateOfBirth columns.',
        debug: {
          foundAadhaarPanColumns: foundAadhaarPanColumns,
          foundColumns: Object.keys(firstRow)
        }
      });
    }

    // Debug: Log the final column map
    logger.info('Final column map for processing:', columnMap);

    // Generate unique batch ID with timestamp to ensure each upload is a new entry
    const originalName = path.parse(req.file.originalname).name;
    const timestamp = Date.now();
    const randomSuffix = Math.random().toString(36).substring(2, 8);
    const batchId = `${originalName}_${timestamp}_${randomSuffix}`;
    const records = [];

    // Process each row
    for (let i = 0; i < data.length; i++) {
      const row = data[i];
      
      // Debug logging for first row
      if (i === 0) {
        logger.info('Processing first row:', row);
        logger.info('Column map:', columnMap);
        logger.info('Extracted values:', {
          panNumber: row[columnMap.panNumber],
          name: row[columnMap.name],
          dateOfBirth: row[columnMap.dateOfBirth]
        });
        logger.info('Raw extracted values:', {
          panNumberRaw: row[columnMap.panNumber],
          nameRaw: row[columnMap.name],
          dateOfBirthRaw: row[columnMap.dateOfBirth]
        });
      }
      
      const panNumberValue = row[columnMap.panNumber]?.toString().trim();
      const nameValue = row[columnMap.name]?.toString().trim();
      
      // Handle DOB - convert Excel date number to string
      let dateOfBirthValue = '';
      const dateOfBirthColumn = columnMap.dateOfBirth;
      if (row[dateOfBirthColumn] !== undefined) {
        if (typeof row[dateOfBirthColumn] === 'number') {
          // Convert Excel date number to date string
          const excelDate = row[dateOfBirthColumn];
          const date = new Date((excelDate - 25569) * 86400 * 1000);
          dateOfBirthValue = date.toLocaleDateString('en-GB'); // DD/MM/YYYY format
        } else {
          dateOfBirthValue = row[dateOfBirthColumn]?.toString().trim();
        }
      }
      
      const fatherNameValue = row.fatherName || row['Father Name'] || row.father_name || '';
      
      // Skip rows with missing required fields
      if (!panNumberValue || !nameValue || !dateOfBirthValue) {
        logger.warn(`Skipping row ${i + 1} - missing required fields:`, {
          panNumber: panNumberValue,
          name: nameValue,
          dateOfBirth: dateOfBirthValue,
          row: row
        });
        continue;
      }
      
      // Debug logging for first row
      if (i === 0) {
        logger.info('Values before creating record:', {
          panNumber: panNumberValue,
          name: nameValue,
          dateOfBirth: dateOfBirthValue,
          fatherName: fatherNameValue
        });
        logger.info('Value types:', {
          panNumberType: typeof panNumberValue,
          nameType: typeof nameValue,
          dateOfBirthType: typeof dateOfBirthValue,
          fatherNameType: typeof fatherNameValue
        });
        logger.info('Value lengths:', {
          panNumberLength: panNumberValue ? panNumberValue.length : 0,
          nameLength: nameValue ? nameValue.length : 0,
          dateOfBirthLength: dateOfBirthValue ? dateOfBirthValue.length : 0,
          fatherNameLength: fatherNameValue ? fatherNameValue.length : 0
        });
      }
      
      // Debug: Check user context
      if (i === 0) {
        logger.info('User context:', {
          userId: req.user.id,
          userType: typeof req.user.id,
          userExists: !!req.user,
          userKeys: req.user ? Object.keys(req.user) : 'no user',
          userObject: req.user ? {
            _id: req.user._id,
            id: req.user.id,
            email: req.user.email,
            role: req.user.role
          } : 'no user'
        });
      }

      // Create the record with real user ID
      const record = new PanKyc({
        userId: req.user.id,
        batchId: batchId,
        panNumber: panNumberValue,
        name: nameValue,
        dateOfBirth: dateOfBirthValue,
        fatherName: fatherNameValue,
        fileUpload: {
          originalName: req.file.originalname,
          fileName: req.file.filename,
          fileSize: req.file.size,
          uploadDate: new Date()
        }
      });

      records.push(record);
    }

    // Debug: Check first record before saving
    if (records.length > 0) {
      logger.info('First record before saving:', {
        panNumber: records[0].panNumber,
        name: records[0].name,
        dateOfBirth: records[0].dateOfBirth,
        fatherName: records[0].fatherName
      });
    }

    // Save all records individually to ensure proper validation and middleware
    const savedRecords = [];
    for (const record of records) {
      try {
        const savedRecord = await record.save();
        savedRecords.push(savedRecord);
      } catch (saveError) {
        logger.error('Error saving individual record:', saveError);
        throw saveError;
      }
    }

    // Log the upload event
    await logPanKycEvent('pan_kyc_upload', req.user.id, {
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
    logger.error('Error uploading PAN KYC file:', error);
    logger.error('Error details:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });
    res.status(500).json({
      success: false,
      message: 'Failed to upload file',
      error: error.message
    });
  }
});

// Process batch verification
router.post('/batch/:batchId/process', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    
    // Get pending records
    const pendingRecords = await PanKyc.find({
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
          // Use real Sandbox API for verification
          const startTime = Date.now();
          
          // Decrypt the data before calling the API
          const decryptedRecord = record.decryptData();
          
          // Call real PAN verification API with decrypted data
          const verificationResult = await verifyPAN(decryptedRecord.panNumber, decryptedRecord.name, decryptedRecord.dateOfBirth);
          
          const processingTime = Date.now() - startTime;
          
          // Update record with real verification result
          record.status = verificationResult.valid ? 'verified' : 'rejected';
          record.isProcessed = true;
          record.processedAt = new Date();
          record.processingTime = processingTime;
          record.verificationDetails = {
            apiResponse: verificationResult.details.apiResponse,
            verificationDate: new Date(),
            remarks: verificationResult.message,
            source: verificationResult.details.source,
            confidence: verificationResult.details.confidence,
            dataMatch: verificationResult.details.dataMatch,
            nameMatch: verificationResult.details.nameMatch,
            dobMatch: verificationResult.details.dobMatch,
            category: verificationResult.details.category,
            aadhaarSeedingStatus: verificationResult.details.aadhaarSeedingStatus,
            transactionId: verificationResult.details.transactionId
          };
          
          await record.save();
          
          results.push({
            recordId: record._id,
            status: record.status,
            result: verificationResult,
            processingTime: processingTime
          });

          // Log verification event
          await logPanKycEvent('pan_kyc_verification', req.user.id, {
            recordId: record._id,
            batchId: batchId,
            status: status,
            processingTime: processingTime
          }, req);

        } catch (error) {
          logger.error(`Error processing record ${record._id}:`, error);
          
          record.status = 'error';
          record.errorMessage = error.message;
          record.isProcessed = true;
          record.processedAt = new Date();
          await record.save();
          
          results.push({
            recordId: record._id,
            status: 'error',
            error: error.message
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
          verified: results.filter(r => r.status === 'verified').length,
          rejected: results.filter(r => r.status === 'rejected').length,
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



// Verify selected records
router.post('/verify', protect, async (req, res) => {
  try {
    const { recordIds } = req.body;
    
    if (!recordIds || !Array.isArray(recordIds) || recordIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Record IDs are required'
      });
    }

    // Find records that belong to the user and are pending
    const records = await PanKyc.find({
      _id: { $in: recordIds },
      userId: req.user.id,
      status: 'pending'
    });

    if (records.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No pending records found to verify'
      });
    }

    const results = [];
    const startTime = Date.now();

    // Process each record
    for (const record of records) {
      try {
        // Simulate PAN verification (replace with actual API call)
        const verificationResult = await verifyPAN(record.panNumber, record.name);
        
        // Update record with verification result
        record.status = verificationResult.valid ? 'verified' : 'rejected';
        record.verificationResult = verificationResult;
        record.processedAt = new Date();
        record.processingTime = Date.now() - startTime;
        
        await record.save();
        
        results.push({
          recordId: record._id,
          status: record.status,
          result: verificationResult
        });

        // Log verification event
        await logPanKycEvent('record_verified', req.user.id, {
          recordId: record._id,
          batchId: record.batchId,
          status: record.status,
          panNumber: record.panNumber
        }, req);

      } catch (error) {
        logger.error(`Error verifying record ${record._id}:`, error);
        
        record.status = 'error';
        record.verificationResult = { error: error.message };
        record.processedAt = new Date();
        record.processingTime = Date.now() - startTime;
        
        await record.save();
        
        results.push({
          recordId: record._id,
          status: 'error',
          error: error.message
        });
      }
    }

    res.json({
      success: true,
      message: `Processed ${results.length} records`,
      data: {
        total: results.length,
        verified: results.filter(r => r.status === 'verified').length,
        rejected: results.filter(r => r.status === 'rejected').length,
        error: results.filter(r => r.status === 'error').length,
        results
      }
    });

  } catch (error) {
    logger.error('Error verifying records:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify records'
    });
  }
});

// Delete batch and all its records
router.delete('/batch/:batchId', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    
    // Find all records for this batch that belong to the user
    const records = await PanKyc.find({
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
    const deleteResult = await PanKyc.deleteMany({
      userId: new mongoose.Types.ObjectId(req.user.id),
      batchId: batchId
    });

    // Log deletion event
    await logPanKycEvent('batch_deleted', req.user.id, {
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
    
    const records = await PanKyc.find({
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
    await logPanKycEvent('report_downloaded', req.user.id, {
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
        'Name': record.name,
        'Father Name': record.fatherName,
        'Date of Birth': record.dateOfBirth,
        'Status': record.status,
        'Processing Time (ms)': record.processingTime,
        'Processed At': record.processedAt,
        'Created At': record.createdAt
      }));

      const csv = XLSX.utils.json_to_sheet(csvData);
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, csv, 'PAN KYC Report');
      
      const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'csv' });
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="pan-kyc-${batchId}.csv"`);
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

// Single KYC verification endpoint
router.post('/verify-single', protect, async (req, res) => {
  try {
    const { panNumber, name, dateOfBirth } = req.body;

    // Validate required fields
    if (!panNumber || !name || !dateOfBirth) {
      return res.status(400).json({
        success: false,
        message: 'PAN Number, Name, and Date of Birth are required'
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
    const tempRecord = new PanKyc({
      userId: req.user.id,
      batchId: 'SINGLE_KYC_' + Date.now(),
      panNumber: panNumber.toUpperCase(),
      name: name.trim(),
      dateOfBirth: dateOfBirth.trim(),
      status: 'pending'
    });

    // Use real Sandbox API for verification
    const startTime = Date.now();
    const verificationResult = await verifyPAN(panNumber, name, dateOfBirth);
    
    // Update record with real verification result
    tempRecord.status = verificationResult.valid ? 'verified' : 'rejected';
    tempRecord.verificationDetails = {
      apiResponse: verificationResult.details.apiResponse,
      verificationDate: new Date(),
      remarks: verificationResult.message,
      source: verificationResult.details.source,
      confidence: verificationResult.details.confidence,
      dataMatch: verificationResult.details.dataMatch,
      nameMatch: verificationResult.details.nameMatch,
      dobMatch: verificationResult.details.dobMatch,
      category: verificationResult.details.category,
      aadhaarSeedingStatus: verificationResult.details.aadhaarSeedingStatus,
      transactionId: verificationResult.details.transactionId
    };
    tempRecord.processedAt = new Date();
    tempRecord.processingTime = Date.now() - startTime;
    
    await tempRecord.save();

    // Log verification event
    await logPanKycEvent('single_kyc_verified', req.user.id, {
      panNumber: tempRecord.panNumber,
      name: tempRecord.name,
      status: tempRecord.status
    }, req);

    res.json({
      success: true,
      message: 'KYC verification completed',
      data: {
        panNumber: tempRecord.panNumber,
        name: tempRecord.name,
        dateOfBirth: tempRecord.dateOfBirth,
        status: tempRecord.status,
        verificationDetails: tempRecord.verificationDetails,
        processedAt: tempRecord.processedAt,
        processingTime: tempRecord.processingTime
      }
    });

  } catch (error) {
    logger.error('Error in single KYC verification:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify KYC'
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
    const stats = await PanKyc.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id), ...dateFilter } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          verified: { $sum: { $cond: [{ $eq: ['$status', 'verified'] }, 1, 0] } },
          rejected: { $sum: { $cond: [{ $eq: ['$status', 'rejected'] }, 1, 0] } },
          pending: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
          error: { $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] } }
        }
      }
    ]);

    const result = stats[0] || { total: 0, verified: 0, rejected: 0, pending: 0, error: 0 };
    const successRate = result.total > 0 ? (result.verified / result.total) * 100 : 0;

    res.json({
      success: true,
      data: {
        ...result,
        successRate
      }
    });

  } catch (error) {
    logger.error('Error fetching verification stats:', error);
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
    const monthlyStats = await PanKyc.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id), ...dateFilter } },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          total: { $sum: 1 },
          verified: { $sum: { $cond: [{ $eq: ['$status', 'verified'] }, 1, 0] } },
          rejected: { $sum: { $cond: [{ $eq: ['$status', 'rejected'] }, 1, 0] } },
          pending: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
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
      verified: stat.verified,
      rejected: stat.rejected,
      pending: stat.pending,
      error: stat.error
    }));

    res.json({
      success: true,
      data: formattedStats
    });

  } catch (error) {
    logger.error('Error fetching monthly stats:', error);
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
    
    const recentVerifications = await PanKyc.find({
      userId: new mongoose.Types.ObjectId(req.user.id)
    })
    .select('panNumber name dateOfBirth status processedAt batchId')
    .sort({ createdAt: -1 })
    .limit(parseInt(limit))
    .lean();

    // Decrypt the records before sending to frontend
    const decryptedVerifications = recentVerifications.map(record => {
      try {
        // Create a temporary document instance to use decryptData method
        const tempDoc = new PanKyc(record);
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
    logger.error('Error fetching recent verifications:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch recent verifications'
    });
  }
});

module.exports = router;

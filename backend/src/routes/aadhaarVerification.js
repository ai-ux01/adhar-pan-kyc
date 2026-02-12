const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { protect } = require('../middleware/auth');
const AadhaarVerification = require('../models/AadhaarVerification');
const User = require('../models/User');
const { logAadhaarVerificationEvent } = require('../services/auditService');
const logger = require('../utils/logger');
const { verifyAadhaar, simulateAadhaarVerification } = require('../services/aadhaarVerificationService');
const { getAllowedOrigin } = require('../utils/corsHelper');

// Configure multer for selfie uploads
const selfieStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, '../../uploads/selfies');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'selfie-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const selfieUpload = multer({
  storage: selfieStorage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    // Accept only image files
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});



// Get all records for a user
router.get('/records', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50; // Increased default to 50 for better UX
    const maxLimit = 500; // Max limit
    const actualLimit = Math.min(limit, maxLimit);
    const skip = (page - 1) * actualLimit;
    const search = req.query.search || '';
    const status = req.query.status || '';
    const dateFrom = req.query.dateFrom || '';
    const dateTo = req.query.dateTo || '';
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder || 'desc';

    // Build search query
    let searchQuery = { userId: req.user.id };
    
    // Add search term filter
    if (search) {
      // Create regex for case-insensitive search
      const searchRegex = new RegExp(search, 'i');
      
      // Search in multiple fields including API response data
      searchQuery = {
        ...searchQuery,
        $or: [
          { aadhaarNumber: searchRegex },
          { name: searchRegex },
          { address: searchRegex },
          { district: searchRegex },
          { state: searchRegex },
          { pinCode: searchRegex },
          { careOf: searchRegex },
          // Search in API response data (where actual decrypted values are stored)
          { 'verificationDetails.apiResponse.data.name': searchRegex },
          { 'verificationDetails.apiResponse.data.address.full_address': searchRegex },
          { 'verificationDetails.apiResponse.data.address.district': searchRegex },
          { 'verificationDetails.apiResponse.data.address.state': searchRegex },
          { 'verificationDetails.apiResponse.data.address.pincode': searchRegex },
          { 'verificationDetails.apiResponse.data.care_of': searchRegex }
        ]
      };
    }

    // Add status filter
    if (status) {
      searchQuery = {
        ...searchQuery,
        status: status
      };
    }

    // Add date range filter
    if (dateFrom || dateTo) {
      searchQuery.dateOfBirth = {};
      if (dateFrom) {
        searchQuery.dateOfBirth.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        searchQuery.dateOfBirth.$lte = new Date(dateTo);
      }
    }

    // Debug: Log the search query
    if (search) {
      console.log('Search query built:', JSON.stringify(searchQuery, null, 2));
    }

    // Get total count for pagination (with timeout protection)
    const totalRecords = await AadhaarVerification.countDocuments(searchQuery).maxTimeMS(5000);
    const totalPages = Math.ceil(totalRecords / actualLimit);

    // Build sort object
    const sortObj = {};
    sortObj[sortBy] = sortOrder === 'asc' ? 1 : -1;

    // Get paginated records (with timeout protection)
    const records = await AadhaarVerification.find(searchQuery)
      .sort(sortObj)
      .skip(skip)
      .limit(limit)
      .maxTimeMS(10000) // 10 second timeout for query
      .lean();

    // Decrypt sensitive data in parallel for better performance
    const decryptedRecords = await Promise.all(
      records.map(async (record) => {
        try {
          // Create a temporary AadhaarVerification instance to use the decryptData method
          const tempRecord = new AadhaarVerification(record);
          const decryptedRecord = tempRecord.decryptData();
          
          // Extract care_of from API response if careOf field is encrypted or missing
          if ((decryptedRecord.careOf === '[ENCRYPTED]' || !decryptedRecord.careOf) && 
              decryptedRecord.verificationDetails && 
              decryptedRecord.verificationDetails.apiResponse && 
              decryptedRecord.verificationDetails.apiResponse.data && 
              decryptedRecord.verificationDetails.apiResponse.data.care_of) {
            decryptedRecord.careOf = decryptedRecord.verificationDetails.apiResponse.data.care_of;
          }
          
          return decryptedRecord;
        } catch (error) {
          logger.error('Decryption error for record:', record._id, error.message);
          // Return original record if decryption fails
          return record;
        }
      })
    );

    const responseData = {
      success: true,
      data: decryptedRecords,
      pagination: {
        currentPage: page,
        totalPages: totalPages,
        totalRecords: totalRecords,
        hasNext: page < totalPages,
        hasPrev: page > 1,
        limit: actualLimit
      }
    };
    
    console.log('Aadhaar verification records response:', {
      totalRecords,
      totalPages,
      currentPage: page,
      recordsReturned: decryptedRecords.length,
      searchTerm: search || 'none',
      searchQuery: search ? 'Applied' : 'None',
      filters: {
        status: status || 'none',
        dateFrom: dateFrom || 'none',
        dateTo: dateTo || 'none',
        sortBy,
        sortOrder
      }
    });
    
    res.json(responseData);
  } catch (error) {
    logger.error('Error fetching Aadhaar verification records:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch records',
      error: error.message
    });
  }
});





// Single Aadhaar verification endpoint - Send OTP
router.post('/verify-single', protect, async (req, res) => {
  try {
    const { aadhaarNumber, location = '', dynamicFields = [], consentAccepted } = req.body;

    if (!aadhaarNumber) {
      return res.status(400).json({
        success: false,
        message: 'Aadhaar Number is required'
      });
    }

    if (!consentAccepted) {
      return res.status(400).json({
      success: false,
        message: 'Consent is required to proceed'
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

    // Send OTP using Sandbox API
    const startTime = Date.now();
    const otpResult = await verifyAadhaar(aadhaarNumber, location, dynamicFields);
    
    logger.info("OTP sent successfully - returning transaction ID:", {
      transactionId: otpResult.details.transactionId,
      transactionIdType: typeof otpResult.details.transactionId,
      fullOtpResult: otpResult
    });
    
    res.json({
      success: true,
      message: 'OTP sent successfully',
      data: {
        aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
        location: location.trim(),
        dynamicFields: dynamicFields,
        otpSent: true,
        transactionId: otpResult.details.transactionId,
        apiResponse: otpResult.details.apiResponse,
        source: otpResult.details.source
      }
    });

  } catch (error) {
    logger.error('Error in single Aadhaar verification:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to send OTP'
    });
  }
});


// OTP verification endpoint
router.post('/verify-otp', protect, async (req, res) => {
  try {
    const { aadhaarNumber, otp, transactionId, dynamicFields = [], customFields = {} } = req.body;

    if (!aadhaarNumber || !otp || !transactionId) {
      return res.status(400).json({
        success: false,
        message: 'Aadhaar Number, OTP, and Transaction ID are required'
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

    // Validate OTP format
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid OTP format. Must be 6 digits.'
      });
    }

    // Verify OTP using Sandbox API
    const { verifyAadhaarOTP } = require('../services/aadhaarVerificationService');
    const startTime = Date.now();
    
    logger.info("OTP Verification route - received data:", {
      aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
      otp,
      transactionId,
      transactionIdType: typeof transactionId,
      transactionIdLength: transactionId ? transactionId.length : 'null'
    });
    
    const otpResult = await verifyAadhaarOTP(transactionId, otp);

    // Extract address details from API response
    const apiData = otpResult.data?.data || otpResult.data || {};
    const addressData = apiData.address || {};
    
    // Debug: Log photo data
    logger.info("Photo data from API:", {
      hasPhoto: !!apiData.photo,
      photoLength: apiData.photo ? apiData.photo.length : 0,
      photoPreview: apiData.photo ? apiData.photo.substring(0, 50) + '...' : 'No photo'
    });
    
    // Create verification record with complete address information
    const verificationRecord = new AadhaarVerification({
      userId: req.user.id,
      batchId: 'OTP_VERIFICATION_' + Date.now(),
      aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
      name: apiData.name || 'OTP Verified',
      dateOfBirth: apiData.date_of_birth || apiData.dateOfBirth || '',
      gender: apiData.gender || 'M',
      address: apiData.full_address || addressData.full_address || '',
      district: addressData.district || apiData.district || '',
      state: addressData.state || apiData.state || '',
      pinCode: addressData.pinCode || apiData.pinCode || '',
      careOf: apiData.care_of || '', // Add care_of field
      photo: apiData.photo || '', // Add photo field
      dynamicFields: [
        ...dynamicFields.map(field => ({
          label: field.label,
          value: field.value
        })),
        ...Object.entries(customFields).map(([key, value]) => ({
          label: key,
          value: value
        }))
      ], // Store the dynamic fields and custom fields from the request
      // Check status from API response - status can be in data.status or at root level
      // Also check if there's an error or if the verification was successful
      status: (apiData.status === 'VALID' || 
               otpResult.data?.status === 'VALID' || 
               otpResult.status === 'VALID' ||
               (otpResult.data && !otpResult.data.error && apiData.name)) ? 'verified' : 'rejected',
      verificationDetails: {
        apiResponse: otpResult,
        verificationDate: new Date(),
        remarks: otpResult.message || 'OTP verification completed',
        source: 'sandbox_api',
        transactionId: transactionId,
        otpVerified: true,
        // Store additional API data
        careOf: apiData.care_of || '',
        house: addressData.house || '',
        street: addressData.street || '',
        landmark: addressData.landmark || '',
        vtc: addressData.vtc || '',
        subdist: addressData.subdist || '',
        country: addressData.country || 'India',
        photo: apiData.photo || '',
        emailHash: apiData.email_hash || '',
        mobileHash: apiData.mobile_hash || '',
        yearOfBirth: apiData.year_of_birth || '',
        shareCode: apiData.share_code || ''
      },
      processingTime: Date.now() - startTime,
      isProcessed: true,
      processedAt: new Date()
    });

    await verificationRecord.save();

    // Log the verification event
    await logAadhaarVerificationEvent('otp_verification_completed', req.user.id, {
      recordId: verificationRecord._id,
      batchId: verificationRecord.batchId,
      aadhaarNumber: verificationRecord.aadhaarNumber,
      status: verificationRecord.status,
      processingTime: verificationRecord.processingTime
    }, req);

    res.json({
      success: true,
      message: 'OTP verification completed successfully',
      data: {
        recordId: verificationRecord._id,
        batchId: verificationRecord.batchId,
        aadhaarNumber: verificationRecord.aadhaarNumber,
        status: verificationRecord.status,
        verificationDetails: verificationRecord.verificationDetails,
        processingTime: verificationRecord.processingTime,
        verifiedAt: verificationRecord.processedAt
      }
    });

  } catch (error) {
    logger.error('Error verifying OTP:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to verify OTP'
    });
  }
});

// Upload selfie for a verification record
router.post('/records/:id/selfie', protect, selfieUpload.single('selfie'), async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No selfie file provided'
      });
    }

    // Find the verification record
    const verificationRecord = await AadhaarVerification.findById(id);
    
    if (!verificationRecord) {
      // Clean up uploaded file if record doesn't exist
      fs.unlinkSync(req.file.path);
      return res.status(404).json({
        success: false,
        message: 'Verification record not found'
      });
    }

    // Check if the record belongs to the user
    if (verificationRecord.userId.toString() !== req.user.id.toString()) {
      // Clean up uploaded file if unauthorized
      fs.unlinkSync(req.file.path);
      return res.status(403).json({
        success: false,
        message: 'Not authorized to upload selfie for this record'
      });
    }

    // Check if user has selfie-upload module access
    const User = require('../models/User');
    const user = await User.findById(req.user.id);
    if (!user || (user.role !== 'admin' && (!user.moduleAccess || !user.moduleAccess.includes('selfie-upload')))) {
      // Clean up uploaded file if no access
      fs.unlinkSync(req.file.path);
      return res.status(403).json({
        success: false,
        message: 'Selfie upload module is not enabled for your account'
      });
    }

    // Delete old selfie if exists
    if (verificationRecord.selfie && verificationRecord.selfie.path) {
      const oldPath = path.join(__dirname, '..', '..', verificationRecord.selfie.path);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }

    // Store the path correctly - ensure it's relative to project root
    // req.file.path is absolute, we need to make it relative
    // Format: uploads/selfies/filename
    const relativePath = req.file.path.replace(/^.*uploads/, 'uploads');
    
    logger.info(`Storing selfie path (protected): original=${req.file.path}, relative=${relativePath}`);

    // Update verification record with selfie using findByIdAndUpdate to avoid validation issues with encrypted fields
    await AadhaarVerification.findByIdAndUpdate(
      id,
      {
        $set: {
          selfie: {
            filename: req.file.filename,
            originalName: req.file.originalname,
            path: relativePath, // Store relative path
            mimetype: req.file.mimetype,
            size: req.file.size,
            uploadedAt: new Date()
          }
        }
      },
      { 
        runValidators: false, // Skip validation for encrypted fields
        new: true 
      }
    );

    // Fetch the updated record to get the selfie data
    const updatedRecord = await AadhaarVerification.findById(id);

    // Log the event
    await logAadhaarVerificationEvent('selfie_uploaded', req.user.id, {
      recordId: id,
      batchId: verificationRecord.batchId,
      fileName: req.file.filename
    }, req);

    res.json({
      success: true,
      message: 'Selfie uploaded successfully',
      data: {
        recordId: id,
        selfie: updatedRecord?.selfie
      }
    });
  } catch (error) {
    logger.error('Error uploading selfie:', error);
    
    // Clean up uploaded file on error
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkError) {
        logger.error('Error cleaning up uploaded file:', unlinkError);
      }
    }
    
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to upload selfie'
    });
  }
});

// Public selfie upload for QR code flow (no auth required)
router.post('/records/:id/selfie-public', selfieUpload.single('selfie'), async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No selfie file provided'
      });
    }

    // Find the verification record
    const verificationRecord = await AadhaarVerification.findById(id);
    
    if (!verificationRecord) {
      fs.unlinkSync(req.file.path);
      return res.status(404).json({
        success: false,
        message: 'Verification record not found'
      });
    }

    // Only allow public uploads for QR code flow (batchId starts with 'qr-')
    if (!verificationRecord.batchId || !verificationRecord.batchId.startsWith('qr-')) {
      fs.unlinkSync(req.file.path);
      return res.status(403).json({
        success: false,
        message: 'Public selfie upload only allowed for QR code verifications'
      });
    }

    // Get user to check selfie access
    const user = await User.findById(verificationRecord.userId);
    if (!user || (user.role !== 'admin' && (!user.moduleAccess || !user.moduleAccess.includes('selfie-upload')))) {
      fs.unlinkSync(req.file.path);
      return res.status(403).json({
        success: false,
        message: 'Selfie upload module is not enabled for this user'
      });
    }

    // Delete old selfie if exists
    if (verificationRecord.selfie && verificationRecord.selfie.path) {
      const oldPath = path.join(__dirname, '..', '..', verificationRecord.selfie.path);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }

    // Store the path correctly - ensure it's relative to project root
    // req.file.path is absolute, we need to make it relative
    // Use the same logic as the protected endpoint for consistency
    const relativePath = req.file.path.replace(/^.*uploads/, 'uploads');
    
    logger.info(`Storing selfie path (public): original=${req.file.path}, relative=${relativePath}`);

    // Update verification record with selfie
    await AadhaarVerification.findByIdAndUpdate(
      id,
      {
        $set: {
          selfie: {
            filename: req.file.filename,
            originalName: req.file.originalname,
            path: relativePath,
            mimetype: req.file.mimetype,
            size: req.file.size,
            uploadedAt: new Date()
          }
        }
      },
      { 
        runValidators: false,
        new: true 
      }
    );

    const updatedRecord = await AadhaarVerification.findById(id);

    res.json({
      success: true,
      message: 'Selfie uploaded successfully',
      data: {
        recordId: id,
        selfie: updatedRecord?.selfie
      }
    });
  } catch (error) {
    logger.error('Error uploading selfie (public):', error);
    
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkError) {
        logger.error('Error cleaning up uploaded file:', unlinkError);
      }
    }
    
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to upload selfie'
    });
  }
});

// Get selfie for a verification record
router.get('/records/:id/selfie', protect, async (req, res) => {
  try {
    const { id } = req.params;
    
    logger.info(`Fetching selfie for record: ${id}, user: ${req.user.id}`);
    
    const verificationRecord = await AadhaarVerification.findById(id);
    
    if (!verificationRecord) {
      logger.warn(`Verification record not found: ${id}`);
      return res.status(404).json({
        success: false,
        message: 'Verification record not found'
      });
    }

    // Check if the record belongs to the user or user is admin
    const User = require('../models/User');
    const user = await User.findById(req.user.id);
    const isAdmin = user && user.role === 'admin';
    
    if (!isAdmin && verificationRecord.userId.toString() !== req.user.id.toString()) {
      logger.warn(`Unauthorized selfie access attempt: record ${id} by user ${req.user.id}`);
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this selfie'
      });
    }

    if (!verificationRecord.selfie || !verificationRecord.selfie.path) {
      logger.warn(`No selfie path found for record: ${id}`);
      return res.status(404).json({
        success: false,
        message: 'Selfie not found for this record'
      });
    }

    // Resolve the absolute path - handle both relative and absolute paths
    let absolutePath;
    const storedPath = verificationRecord.selfie.path;
    const filename = verificationRecord.selfie.filename || path.basename(storedPath);
    
    // Get the selfies directory (same as multer storage destination)
    const selfiesDir = path.join(__dirname, '..', '..', 'uploads', 'selfies');
    
    logger.info(`Selfie retrieval - storedPath: ${storedPath}, filename: ${filename}, selfiesDir: ${selfiesDir}`);
    
    if (path.isAbsolute(storedPath)) {
      absolutePath = storedPath;
    } else {
      // Handle relative paths - try multiple possible locations
      // storedPath format should be: uploads/selfies/filename or uploads/selfies/selfie-xxx.jpg
      const possiblePaths = [
        // First try: resolve from backend directory (most common case)
        path.resolve(__dirname, '..', '..', storedPath),
        // Second try: construct from selfies directory + filename (if storedPath is just filename)
        path.join(selfiesDir, filename),
        // Third try: if storedPath already includes selfies, extract filename and use it
        path.join(selfiesDir, path.basename(storedPath)),
        // Fourth try: resolve from project root
        path.resolve(process.cwd(), storedPath),
        // Fifth try: resolve from project root with selfies
        path.resolve(process.cwd(), 'uploads', 'selfies', filename),
        // Sixth try: if storedPath is just the filename without directory
        storedPath.startsWith('uploads/') ? path.resolve(__dirname, '..', '..', storedPath) : path.join(selfiesDir, storedPath)
      ];
      
      logger.info(`Trying possible paths: ${JSON.stringify(possiblePaths)}`);
      
      // Find the first existing path
      for (const possiblePath of possiblePaths) {
        if (fs.existsSync(possiblePath)) {
          absolutePath = possiblePath;
          logger.info(`Found selfie at: ${absolutePath}`);
          break;
        }
      }
      
      // If none found, try to search for the file by filename in the selfies directory
      if (!absolutePath || !fs.existsSync(absolutePath)) {
        try {
          if (fs.existsSync(selfiesDir)) {
            const files = fs.readdirSync(selfiesDir);
            logger.info(`Searching ${files.length} files in selfies directory for: ${filename} or ${path.basename(storedPath)}`);
            
            // Try exact matches first
            let matchingFile = files.find(f => f === filename || f === path.basename(storedPath));
            
            // If no exact match, try partial matches (filename contains stored filename or vice versa)
            if (!matchingFile) {
              const baseFilename = path.basename(storedPath);
              const filenameWithoutExt = path.parse(filename).name;
              const storedFilenameWithoutExt = path.parse(baseFilename).name;
              
              matchingFile = files.find(f => {
                const fWithoutExt = path.parse(f).name;
                return f === filename || 
                       f === baseFilename ||
                       fWithoutExt === filenameWithoutExt ||
                       fWithoutExt === storedFilenameWithoutExt ||
                       f.includes(filenameWithoutExt) ||
                       filenameWithoutExt.includes(fWithoutExt) ||
                       f.includes(storedFilenameWithoutExt) ||
                       storedFilenameWithoutExt.includes(fWithoutExt);
              });
            }
            
            if (matchingFile) {
              absolutePath = path.join(selfiesDir, matchingFile);
              logger.info(`Found selfie by filename search: ${absolutePath}`);
            } else {
              // Log available files for debugging
              logger.warn(`No matching file found. Available files (first 20): ${files.slice(0, 20).join(', ')}`);
              // Last resort: use the most likely path
              absolutePath = path.join(selfiesDir, filename);
              logger.warn(`No existing path found, using: ${absolutePath}`);
            }
          } else {
            logger.error(`Selfies directory does not exist: ${selfiesDir}`);
            absolutePath = path.join(selfiesDir, filename);
          }
        } catch (err) {
          logger.error(`Error searching selfies directory: ${err.message}`, err);
          absolutePath = path.join(selfiesDir, filename);
        }
      }
    }
    
    logger.info(`Final path resolution: stored=${storedPath}, resolved=${absolutePath}, exists=${fs.existsSync(absolutePath)}`);
    
    // Check if file exists
    if (!fs.existsSync(absolutePath)) {
      logger.error(`Selfie file not found: ${absolutePath} for record ${id}`);
      logger.error(`Stored path: ${storedPath}, Filename: ${filename}`);
      logger.error(`Selfies directory exists: ${fs.existsSync(selfiesDir)}`);
      if (fs.existsSync(selfiesDir)) {
        try {
          const files = fs.readdirSync(selfiesDir);
          logger.error(`Files in selfies directory: ${files.slice(0, 10).join(', ')} (showing first 10)`);
        } catch (err) {
          logger.error(`Error reading selfies directory: ${err.message}`);
        }
      }
      
      return res.status(404).json({
        success: false,
        message: 'Selfie file not found on server',
        debug: process.env.NODE_ENV === 'development' ? {
          storedPath: storedPath,
          resolvedPath: absolutePath,
          filename: filename,
          selfiesDir: selfiesDir,
          __dirname: __dirname,
          cwd: process.cwd()
        } : undefined
      });
    }

    // Set headers for image serving
    res.set({
      'Content-Type': verificationRecord.selfie.mimetype || 'image/jpeg',
      'Access-Control-Allow-Origin': getAllowedOrigin(req.headers.origin),
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'GET',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Cross-Origin-Embedder-Policy': 'unsafe-none',
      'Cache-Control': 'public, max-age=31536000' // Cache for 1 year
    });
    
    res.sendFile(absolutePath);
  } catch (error) {
    logger.error('Error serving selfie:', {
      error: error.message,
      stack: error.stack,
      recordId: req.params.id,
      userId: req.user?.id
    });
    res.status(500).json({
      success: false,
      message: 'Failed to serve selfie',
      error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message
    });
  }
});

// Public GET selfie endpoint for QR code flow (no auth required)
router.get('/records/:id/selfie-public', async (req, res) => {
  try {
    const { id } = req.params;
    
    logger.info(`Fetching selfie (public) for record: ${id}`);
    
    const verificationRecord = await AadhaarVerification.findById(id);
    
    if (!verificationRecord) {
      logger.warn(`Verification record not found: ${id}`);
      return res.status(404).json({
        success: false,
        message: 'Verification record not found'
      });
    }

    // Only allow public access for QR code flow (batchId starts with 'qr-')
    if (!verificationRecord.batchId || !verificationRecord.batchId.startsWith('qr-')) {
      return res.status(403).json({
        success: false,
        message: 'Public selfie access only allowed for QR code verifications'
      });
    }

    if (!verificationRecord.selfie || !verificationRecord.selfie.path) {
      logger.warn(`No selfie path found for record: ${id}`);
      return res.status(404).json({
        success: false,
        message: 'Selfie not found for this record'
      });
    }

    // Resolve the absolute path - handle both relative and absolute paths
    let absolutePath;
    const storedPath = verificationRecord.selfie.path;
    const filename = verificationRecord.selfie.filename || path.basename(storedPath);
    
    // Get the selfies directory (same as multer storage destination)
    const selfiesDir = path.join(__dirname, '..', '..', 'uploads', 'selfies');
    
    logger.info(`Selfie retrieval (public) - storedPath: ${storedPath}, filename: ${filename}, selfiesDir: ${selfiesDir}`);
    
    if (path.isAbsolute(storedPath)) {
      absolutePath = storedPath;
    } else {
      // Handle relative paths - try multiple possible locations
      // storedPath format should be: uploads/selfies/filename or uploads/selfies/selfie-xxx.jpg
      const possiblePaths = [
        // First try: resolve from backend directory (most common case)
        path.resolve(__dirname, '..', '..', storedPath),
        // Second try: construct from selfies directory + filename (if storedPath is just filename)
        path.join(selfiesDir, filename),
        // Third try: if storedPath already includes selfies, extract filename and use it
        path.join(selfiesDir, path.basename(storedPath)),
        // Fourth try: resolve from project root
        path.resolve(process.cwd(), storedPath),
        // Fifth try: resolve from project root with selfies
        path.resolve(process.cwd(), 'uploads', 'selfies', filename),
        // Sixth try: if storedPath is just the filename without directory
        storedPath.startsWith('uploads/') ? path.resolve(__dirname, '..', '..', storedPath) : path.join(selfiesDir, storedPath)
      ];
      
      logger.info(`Trying possible paths (public): ${JSON.stringify(possiblePaths)}`);
      
      // Find the first existing path
      for (const possiblePath of possiblePaths) {
        if (fs.existsSync(possiblePath)) {
          absolutePath = possiblePath;
          logger.info(`Found selfie at (public): ${absolutePath}`);
          break;
        }
      }
      
      // If none found, try to search for the file by filename in the selfies directory
      if (!absolutePath || !fs.existsSync(absolutePath)) {
        try {
          if (fs.existsSync(selfiesDir)) {
            const files = fs.readdirSync(selfiesDir);
            logger.info(`Searching ${files.length} files in selfies directory (public) for: ${filename} or ${path.basename(storedPath)}`);
            
            logger.info(`[Record ${id}] [PUBLIC] Looking for: filename="${filename}", storedPath="${storedPath}", basename="${path.basename(storedPath)}"`);
            
            // Try exact matches first
            let matchingFile = files.find(f => {
              const match = f === filename || f === path.basename(storedPath);
              if (match) logger.info(`[Record ${id}] [PUBLIC] Exact match found: ${f}`);
              return match;
            });
            
            // If no exact match, try to extract unique identifier from filename
            // Selfie filenames are like: selfie-1768271325411-85889526.jpg
            // Extract the timestamp and random number parts
            if (!matchingFile && filename) {
              const filenameParts = filename.match(/selfie-(\d+)-(\d+)\./);
              if (filenameParts) {
                const timestamp = filenameParts[1];
                const randomNum = filenameParts[2];
                logger.info(`[Record ${id}] [PUBLIC] Trying to match by timestamp=${timestamp}, random=${randomNum}`);
                
                matchingFile = files.find(f => {
                  const fParts = f.match(/selfie-(\d+)-(\d+)\./);
                  if (fParts) {
                    return fParts[1] === timestamp || fParts[2] === randomNum;
                  }
                  return false;
                });
                
                if (matchingFile) {
                  logger.info(`[Record ${id}] [PUBLIC] Found by timestamp/random match: ${matchingFile}`);
                }
              }
            }
            
            // If still no match, try partial matches (filename contains stored filename or vice versa)
            if (!matchingFile) {
              const baseFilename = path.basename(storedPath);
              const filenameWithoutExt = path.parse(filename).name;
              const storedFilenameWithoutExt = path.parse(baseFilename).name;
              
              logger.info(`[Record ${id}] [PUBLIC] Trying partial match: filenameWithoutExt="${filenameWithoutExt}", storedFilenameWithoutExt="${storedFilenameWithoutExt}"`);
              
              matchingFile = files.find(f => {
                const fWithoutExt = path.parse(f).name;
                const match = f === filename || 
                       f === baseFilename ||
                       fWithoutExt === filenameWithoutExt ||
                       fWithoutExt === storedFilenameWithoutExt ||
                       (filenameWithoutExt && f.includes(filenameWithoutExt)) ||
                       (filenameWithoutExt && filenameWithoutExt.includes(fWithoutExt)) ||
                       (storedFilenameWithoutExt && f.includes(storedFilenameWithoutExt)) ||
                       (storedFilenameWithoutExt && storedFilenameWithoutExt.includes(fWithoutExt));
                if (match) logger.info(`[Record ${id}] [PUBLIC] Partial match found: ${f}`);
                return match;
              });
            }
            
            // Last resort: if filename starts with "selfie-", try to find any file with similar pattern
            if (!matchingFile && filename && filename.startsWith('selfie-')) {
              logger.info(`[Record ${id}] [PUBLIC] Trying to find any selfie file with similar pattern`);
              // Get the date part from filename (selfie-TIMESTAMP-random.jpg)
              const dateMatch = filename.match(/selfie-(\d{10,})/);
              if (dateMatch) {
                const datePrefix = dateMatch[1].substring(0, 10); // First 10 digits (timestamp)
                matchingFile = files.find(f => f.startsWith('selfie-') && f.includes(datePrefix));
                if (matchingFile) {
                  logger.info(`[Record ${id}] [PUBLIC] Found by date prefix match: ${matchingFile}`);
                }
              }
            }
            
            if (matchingFile) {
              absolutePath = path.join(selfiesDir, matchingFile);
              logger.info(`[Record ${id}] [PUBLIC] ✅ Found selfie by filename search: ${absolutePath}`);
            } else {
              // Log available files for debugging
              const selfieFiles = files.filter(f => f.startsWith('selfie-'));
              logger.error(`[Record ${id}] [PUBLIC] ❌ No matching file found. Looking for: "${filename}" or "${path.basename(storedPath)}"`);
              logger.error(`[Record ${id}] [PUBLIC] Available selfie files (${selfieFiles.length} total, showing first 30): ${selfieFiles.slice(0, 30).join(', ')}`);
              // Last resort: use the most likely path
              absolutePath = path.join(selfiesDir, filename);
              logger.warn(`[Record ${id}] [PUBLIC] Using fallback path: ${absolutePath}`);
            }
          } else {
            logger.error(`Selfies directory does not exist (public): ${selfiesDir}`);
            absolutePath = path.join(selfiesDir, filename);
          }
        } catch (err) {
          logger.error(`Error searching selfies directory (public): ${err.message}`, err);
          absolutePath = path.join(selfiesDir, filename);
        }
      }
    }
    
    logger.info(`Final path resolution (public): stored=${storedPath}, resolved=${absolutePath}, exists=${fs.existsSync(absolutePath)}`);
    
    // Check if file exists
    if (!fs.existsSync(absolutePath)) {
      logger.error(`Selfie file not found (public): ${absolutePath} for record ${id}`);
      logger.error(`Stored path: ${storedPath}, Filename: ${filename}`);
      logger.error(`Selfies directory exists: ${fs.existsSync(selfiesDir)}`);
      if (fs.existsSync(selfiesDir)) {
        try {
          const files = fs.readdirSync(selfiesDir);
          logger.error(`Files in selfies directory: ${files.slice(0, 10).join(', ')} (showing first 10)`);
        } catch (err) {
          logger.error(`Error reading selfies directory: ${err.message}`);
        }
      }
      
      return res.status(404).json({
        success: false,
        message: 'Selfie file not found on server'
      });
    }

    // Set headers for image serving
    res.set({
      'Content-Type': verificationRecord.selfie.mimetype || 'image/jpeg',
      'Access-Control-Allow-Origin': getAllowedOrigin(req.headers.origin),
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'GET',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Cross-Origin-Embedder-Policy': 'unsafe-none',
      'Cache-Control': 'public, max-age=31536000' // Cache for 1 year
    });
    
    res.sendFile(absolutePath);
  } catch (error) {
    logger.error('Error serving selfie (public):', {
      error: error.message,
      stack: error.stack,
      recordId: req.params.id
    });
    res.status(500).json({
      success: false,
      message: 'Failed to serve selfie',
      error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message
    });
  }
});

// Public verification endpoint using QR code (no auth required)
router.post('/verify-qr/:qrCode', async (req, res) => {
  try {
    const { qrCode } = req.params;
    const { aadhaarNumber, location = '', dynamicFields = [], customFields = {}, consentAccepted } = req.body;

    // Find user by QR code
    const user = await User.findOne({ 'qrCode.code': qrCode, 'qrCode.isActive': true });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Invalid or inactive QR code'
      });
    }

    // Check if user has qr-code module access
    if (!user.moduleAccess || !user.moduleAccess.includes('qr-code')) {
      return res.status(403).json({
        success: false,
        message: 'QR code module is not enabled for this user'
      });
    }

    if (!aadhaarNumber) {
      return res.status(400).json({
        success: false,
        message: 'Aadhaar Number is required'
      });
    }

    if (!consentAccepted) {
      return res.status(400).json({
        success: false,
        message: 'Consent is required to proceed'
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

    // Send OTP using Sandbox API
    const startTime = Date.now();
    const otpResult = await verifyAadhaar(aadhaarNumber, location, dynamicFields);
    
    res.json({
      success: true,
      message: 'OTP sent successfully',
      data: {
        aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
        location: location.trim(),
        dynamicFields: dynamicFields,
        customFields: customFields,
        otpSent: true,
        transactionId: otpResult.details.transactionId,
        apiResponse: otpResult.details.apiResponse,
        source: otpResult.details.source,
        userId: user._id,
        hasSelfieAccess: user.moduleAccess && user.moduleAccess.includes('selfie-upload')
      }
    });

  } catch (error) {
    logger.error('Error in QR code verification:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to send OTP'
    });
  }
});

// Public OTP verification endpoint using QR code (no auth required)
router.post('/verify-otp-qr/:qrCode', async (req, res) => {
  try {
    const { qrCode } = req.params;
    const { aadhaarNumber, otp, transactionId, dynamicFields = [], customFields = {} } = req.body;

    // Find user by QR code
    const user = await User.findOne({ 'qrCode.code': qrCode, 'qrCode.isActive': true });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Invalid or inactive QR code'
      });
    }

    // Check if user has qr-code module access
    if (!user.moduleAccess || !user.moduleAccess.includes('qr-code')) {
      return res.status(403).json({
        success: false,
        message: 'QR code module is not enabled for this user'
      });
    }

    if (!aadhaarNumber || !otp || !transactionId) {
      return res.status(400).json({
        success: false,
        message: 'Aadhaar Number, OTP, and Transaction ID are required'
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

    // Validate OTP format
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid OTP format. Must be 6 digits.'
      });
    }

    // Verify OTP using Sandbox API
    const { verifyAadhaarOTP } = require('../services/aadhaarVerificationService');
    const startTime = Date.now();
    const verificationResult = await verifyAadhaarOTP(transactionId, otp);
    const processingTime = Date.now() - startTime;

    // Extract data from API response - handle different response structures
    const apiData = verificationResult.data?.data || verificationResult.data || {};
    const addressData = apiData.address || {};
    
    logger.info('QR OTP Verification - API Response:', {
      hasData: !!verificationResult.data,
      hasNestedData: !!verificationResult.data?.data,
      apiDataKeys: Object.keys(apiData),
      addressDataKeys: Object.keys(addressData)
    });

    // Create verification record
    const verificationRecord = new AadhaarVerification({
      userId: user._id,
      batchId: `qr-${Date.now()}`,
      aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
      name: apiData.name || '',
      dateOfBirth: apiData.date_of_birth || apiData.dateOfBirth || '',
      gender: apiData.gender || '',
      address: apiData.full_address || addressData.full_address || '',
      pinCode: addressData.pincode?.toString() || apiData.pincode?.toString() || apiData.pinCode || '',
      state: addressData.state || apiData.state || '',
      district: addressData.district || apiData.district || '',
      careOf: apiData.care_of || apiData.careOf || '',
      photo: apiData.photo || '',
      dynamicFields: [
        ...dynamicFields.map(field => ({
          label: field.label,
          value: field.value
        })),
        ...Object.entries(customFields).map(([key, value]) => ({
          label: key,
          value: value
        }))
      ],
      // Check status from API response - status can be in data.status or at root level
      // Also check if there's an error or if the verification was successful
      status: (apiData.status === 'VALID' || 
               verificationResult.data?.status === 'VALID' || 
               verificationResult.status === 'VALID' ||
               (apiData && !apiData.error && apiData.name)) ? 'verified' : 'rejected',
      verificationDetails: {
        apiResponse: verificationResult,
        verifiedName: apiData.name || '',
        verifiedDob: apiData.date_of_birth || apiData.dateOfBirth || '',
        verifiedGender: apiData.gender || '',
        verifiedAddress: apiData.full_address || addressData.full_address || '',
        verificationDate: new Date(),
        confidence: 95,
        dataMatch: true,
        source: verificationResult.source || 'sandbox_api',
        transactionId: transactionId.toString()
      },
      processingTime: processingTime,
      isProcessed: true,
      processedAt: new Date()
    });

    await verificationRecord.save();

    // Log the event
    await logAadhaarVerificationEvent('otp_verification_completed', user._id, {
      recordId: verificationRecord._id,
      batchId: verificationRecord.batchId,
      source: 'qr_code'
    }, req);

    res.json({
      success: true,
      message: 'Verification completed successfully',
      data: {
        recordId: verificationRecord._id,
        aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
        name: apiData.name || '',
        dateOfBirth: apiData.date_of_birth || apiData.dateOfBirth || '',
        gender: apiData.gender || '',
        address: apiData.full_address || addressData.full_address || '',
        status: verificationRecord.status,
        processingTime: processingTime,
        hasSelfieAccess: user.moduleAccess && user.moduleAccess.includes('selfie-upload')
      }
    });

  } catch (error) {
    logger.error('Error in QR code OTP verification:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to verify OTP'
    });
  }
});

module.exports = router;
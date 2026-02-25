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
const CustomField = require('../models/CustomField');

// Configure multer for selfie uploads (memory storage - save to MongoDB, not disk)
const selfieUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// Get dynamic field keys (from custom fields applied to verification) for the edit form
router.get('/dynamic-field-keys', protect, async (req, res) => {
  try {
    const fields = await CustomField.find({
      appliesTo: { $in: ['verification', 'both'] },
      isActive: true
    })
      .sort({ displayOrder: 1, createdAt: 1 })
      .select('fieldName fieldLabel fieldType placeholder required')
      .lean();
    res.json({
      success: true,
      data: fields.map((f) => ({
        fieldName: f.fieldName,
        fieldLabel: f.fieldLabel || f.fieldName,
        fieldType: f.fieldType || 'text',
        placeholder: f.placeholder,
        required: !!f.required
      }))
    });
  } catch (error) {
    logger.error('Error fetching dynamic field keys:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dynamic field keys',
      error: error.message
    });
  }
});

// Get all records for a user
router.get('/records', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
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

    // Get total count for pagination
    const totalRecords = await AadhaarVerification.countDocuments(searchQuery);
    const totalPages = Math.ceil(totalRecords / limit);

    // Build sort object
    const sortObj = {};
    sortObj[sortBy] = sortOrder === 'asc' ? 1 : -1;

    // Get paginated records
    const records = await AadhaarVerification.find(searchQuery)
      .sort(sortObj)
      .skip(skip)
      .limit(limit)
      .lean();

    // Fetch dynamic field keys (from custom fields) to fill default shape for dynamicFields
    const fieldKeys = await CustomField.find({
      appliesTo: { $in: ['verification', 'both'] },
      isActive: true
    })
      .sort({ displayOrder: 1, createdAt: 1 })
      .select('fieldName fieldLabel defaultValue')
      .lean();

    // Decrypt sensitive data for each record
    const decryptedRecords = records.map(record => {
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

        // Populate dynamicFields from default keys: each record gets same keys, values from record or default
        const existing = decryptedRecord.dynamicFields && Array.isArray(decryptedRecord.dynamicFields) ? decryptedRecord.dynamicFields : [];
        const getValue = (label, fieldName) => {
          const found = existing.find(f => f.label === label || f.label === fieldName);
          return found ? (found.value || '') : '';
        };
        if (fieldKeys.length > 0) {
          decryptedRecord.dynamicFields = fieldKeys.map(f => ({
            label: f.fieldLabel || f.fieldName,
            value: getValue(f.fieldLabel, f.fieldName) || (f.defaultValue != null ? String(f.defaultValue) : '')
          }));
        } else if (!decryptedRecord.dynamicFields || decryptedRecord.dynamicFields.length === 0) {
          decryptedRecord.dynamicFields = [];
        }
        
        return decryptedRecord;
      } catch (error) {
        console.error('Decryption error for record:', record._id, error.message);
        // Return original record if decryption fails
        return record;
      }
    });

    // Don't send selfie image data in list response (fetch via GET /records/:id/selfie)
    decryptedRecords.forEach(r => {
      if (r.selfie && r.selfie.data) delete r.selfie.data;
    });

    const responseData = {
      success: true,
      data: decryptedRecords,
      pagination: {
        currentPage: page,
        totalPages: totalPages,
        totalRecords: totalRecords,
        hasNext: page < totalPages,
        hasPrev: page > 1,
        limit: limit
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

// Update only dynamicFields for a record (PATCH). GET to this path is not supported.
router.route('/records/:id')
  .patch(protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { dynamicFields } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid record ID'
      });
    }

    const record = await AadhaarVerification.findById(id);
    if (!record) {
      return res.status(404).json({
        success: false,
        message: 'Verification record not found'
      });
    }

    if (record.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this record'
      });
    }

    const normalizedFields = Array.isArray(dynamicFields)
      ? dynamicFields
          .filter((f) => f && typeof f === 'object' && f.label != null)
          .map((f) => ({
            label: String(f.label).trim(),
            value: f.value != null ? String(f.value).trim() : ''
          }))
          .filter((f) => f.label !== '')
      : [];

    record.dynamicFields = normalizedFields;
    await record.save({ validateBeforeSave: false });

    const decrypted = record.decryptData();
    res.json({
      success: true,
      data: decrypted,
      message: 'Dynamic fields updated'
    });
  } catch (error) {
    logger.error('Error updating record dynamic fields:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update dynamic fields',
      error: error.message
    });
  }
  })
  .all((req, res) => {
    res.set('Allow', 'PATCH');
    res.status(405).json({
      success: false,
      error: 'Method not allowed',
      message: 'Use PATCH to update dynamic fields for this record'
    });
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
    const { aadhaarNumber, otp, transactionId, dynamicFields = [] } = req.body;

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
      dynamicFields: dynamicFields, // Store the dynamic fields from the request
      status: apiData.status === 'VALID' ? 'verified' : 'rejected',
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

    const isVerified = verificationRecord.status === 'verified';
    res.json({
      success: isVerified,
      message: isVerified ? 'OTP verification completed successfully' : 'Invalid OTP. Verification rejected.',
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

// Upload selfie for a verification record (stored in MongoDB)
router.post('/records/:id/selfie', protect, selfieUpload.single('selfie'), async (req, res) => {
  try {
    const { id } = req.params;

    if (!req.file || !req.file.buffer) {
      return res.status(400).json({
        success: false,
        message: 'No selfie file provided'
      });
    }

    const verificationRecord = await AadhaarVerification.findById(id);
    if (!verificationRecord) {
      return res.status(404).json({
        success: false,
        message: 'Verification record not found'
      });
    }

    if (verificationRecord.userId.toString() !== req.user.id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to upload selfie for this record'
      });
    }

    const user = await User.findById(req.user.id);
    if (!user || (user.role !== 'admin' && (!user.moduleAccess || !user.moduleAccess.includes('selfie-upload')))) {
      return res.status(403).json({
        success: false,
        message: 'Selfie upload module is not enabled for your account'
      });
    }

    const filename = req.file.originalname || `selfie-${Date.now()}${path.extname(req.file.originalname || '')}`;
    await AadhaarVerification.findByIdAndUpdate(
      id,
      {
        $set: {
          selfie: {
            filename,
            originalName: req.file.originalname || filename,
            path: null,
            data: req.file.buffer,
            mimetype: req.file.mimetype,
            size: req.file.size,
            uploadedAt: new Date()
          }
        }
      },
      { runValidators: false, new: false }
    );

    await logAadhaarVerificationEvent('selfie_uploaded', req.user.id, {
      recordId: id,
      batchId: verificationRecord.batchId,
      fileName: filename
    }, req);

    res.json({
      success: true,
      message: 'Selfie uploaded successfully',
      data: {
        recordId: id,
        selfie: { filename, originalName: req.file.originalname, mimetype: req.file.mimetype, size: req.file.size, uploadedAt: new Date() }
      }
    });
  } catch (error) {
    logger.error('Error uploading selfie:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to upload selfie'
    });
  }
});

// Public selfie upload for QR code flow (no auth required, stored in MongoDB)
router.post('/records/:id/selfie-public', selfieUpload.single('selfie'), async (req, res) => {
  try {
    const { id } = req.params;

    if (!req.file || !req.file.buffer) {
      return res.status(400).json({
        success: false,
        message: 'No selfie file provided'
      });
    }

    const verificationRecord = await AadhaarVerification.findById(id);
    if (!verificationRecord) {
      return res.status(404).json({
        success: false,
        message: 'Verification record not found'
      });
    }

    if (!verificationRecord.batchId || !verificationRecord.batchId.startsWith('qr-')) {
      return res.status(403).json({
        success: false,
        message: 'Public selfie upload only allowed for QR code verifications'
      });
    }

    const user = await User.findById(verificationRecord.userId);
    if (!user || (user.role !== 'admin' && (!user.moduleAccess || !user.moduleAccess.includes('selfie-upload')))) {
      return res.status(403).json({
        success: false,
        message: 'Selfie upload module is not enabled for this user'
      });
    }

    const filename = req.file.originalname || `selfie-${Date.now()}${path.extname(req.file.originalname || '')}`;
    await AadhaarVerification.findByIdAndUpdate(
      id,
      {
        $set: {
          selfie: {
            filename,
            originalName: req.file.originalname || filename,
            path: null,
            data: req.file.buffer,
            mimetype: req.file.mimetype,
            size: req.file.size,
            uploadedAt: new Date()
          }
        }
      },
      { runValidators: false, new: false }
    );

    res.json({
      success: true,
      message: 'Selfie uploaded successfully',
      data: {
        recordId: id,
        selfie: { filename, originalName: req.file.originalname, mimetype: req.file.mimetype, size: req.file.size, uploadedAt: new Date() }
      }
    });
  } catch (error) {
    logger.error('Error uploading selfie (public):', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to upload selfie'
    });
  }
});

// Get selfie for a verification record (from MongoDB or legacy disk path)
router.get('/records/:id/selfie', protect, async (req, res) => {
  try {
    const { id } = req.params;

    const verificationRecord = await AadhaarVerification.findById(id).select('userId selfie');
    if (!verificationRecord) {
      return res.status(404).json({
        success: false,
        message: 'Verification record not found'
      });
    }

    const user = await User.findById(req.user.id);
    const isAdmin = user && user.role === 'admin';
    if (!isAdmin && verificationRecord.userId.toString() !== req.user.id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this selfie'
      });
    }

    const selfie = verificationRecord.selfie;
    if (!selfie) {
      return res.status(404).json({
        success: false,
        message: 'Selfie not found for this record'
      });
    }

    // Prefer image data stored in MongoDB
    if (selfie.data && Buffer.isBuffer(selfie.data)) {
      res.set({
        'Content-Type': selfie.mimetype || 'image/jpeg',
        'Access-Control-Allow-Origin': getAllowedOrigin(req.headers.origin),
        'Access-Control-Allow-Credentials': 'true',
        'Cross-Origin-Resource-Policy': 'cross-origin',
        'Cross-Origin-Embedder-Policy': 'unsafe-none'
      });
      return res.send(selfie.data);
    }

    // Fallback: serve from legacy disk path
    if (selfie.path) {
      const absolutePath = path.resolve(__dirname, '..', '..', selfie.path);
      if (fs.existsSync(absolutePath)) {
        res.set({
          'Content-Type': selfie.mimetype || 'image/jpeg',
          'Access-Control-Allow-Origin': getAllowedOrigin(req.headers.origin),
          'Access-Control-Allow-Credentials': 'true',
          'Cross-Origin-Resource-Policy': 'cross-origin',
          'Cross-Origin-Embedder-Policy': 'unsafe-none'
        });
        return res.sendFile(absolutePath);
      }
    }

    return res.status(404).json({
      success: false,
      message: 'Selfie not found for this record'
    });
  } catch (error) {
    logger.error('Error serving selfie:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to serve selfie'
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

    // Create verification record
    const verificationRecord = new AadhaarVerification({
      userId: user._id,
      batchId: `qr-${Date.now()}`,
      aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
      name: verificationResult.data.name || '',
      dateOfBirth: verificationResult.data.date_of_birth || '',
      gender: verificationResult.data.gender || '',
      address: verificationResult.data.full_address || '',
      pinCode: verificationResult.data.address?.pincode?.toString() || '',
      state: verificationResult.data.address?.state || '',
      district: verificationResult.data.address?.district || '',
      careOf: verificationResult.data.care_of || '',
      photo: verificationResult.data.photo || '',
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
      status: verificationResult.status === 'VALID' ? 'verified' : 'invalid',
      verificationDetails: {
        apiResponse: verificationResult,
        verifiedName: verificationResult.data.name || '',
        verifiedDob: verificationResult.data.date_of_birth || '',
        verifiedGender: verificationResult.data.gender || '',
        verifiedAddress: verificationResult.data.full_address || '',
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

    const isVerified = verificationRecord.status === 'verified';
    res.json({
      success: isVerified,
      message: isVerified ? 'Verification completed successfully' : 'Invalid OTP. Verification rejected.',
      data: {
        recordId: verificationRecord._id,
        aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
        name: verificationResult.data?.name || '',
        dateOfBirth: verificationResult.data?.date_of_birth || '',
        gender: verificationResult.data?.gender || '',
        address: verificationResult.data?.full_address || '',
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
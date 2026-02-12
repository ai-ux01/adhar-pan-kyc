const express = require('express');
const router = express.Router();
const CustomField = require('../models/CustomField');
const { protect, authorize, optionalAuth } = require('../middleware/auth');
const { logEvent } = require('../services/auditService');
const logger = require('../utils/logger');

// @route   GET /api/custom-fields
// @desc    Get all custom fields (public for verification fields, private for others)
// @access  Public for verification fields, Private for others
router.get('/', optionalAuth, async (req, res) => {
  try {
    const { appliesTo, category, isActive, search } = req.query;
    
    // If requesting verification fields and user is not authenticated, allow public access
    // Otherwise, require authentication for non-verification fields
    const isPublicRequest = !req.user;
    const isVerificationRequest = appliesTo === 'verification';
    
    // For public requests, only allow verification fields
    if (isPublicRequest && !isVerificationRequest) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required to access non-verification custom fields'
      });
    }
    
    let query = {};
    
    // Filter by appliesTo
    if (appliesTo) {
      query.appliesTo = { $in: [appliesTo, 'both'] };
    }
    
    // Filter by category
    if (category) {
      query.category = category;
    }
    
    // Filter by active status
    // For public requests, always require isActive=true
    if (isPublicRequest) {
      query.isActive = true;
    } else if (isActive !== undefined) {
      query.isActive = isActive === 'true';
    }
    
    // Search by fieldName or fieldLabel
    if (search) {
      query.$or = [
        { fieldName: { $regex: search, $options: 'i' } },
        { fieldLabel: { $regex: search, $options: 'i' } }
      ];
    }
    
    const customFields = await CustomField.find(query)
      .populate('createdBy', 'name email')
      .populate('updatedBy', 'name email')
      .sort({ displayOrder: 1, createdAt: -1 });
    
    res.json({
      success: true,
      count: customFields.length,
      data: customFields
    });
  } catch (error) {
    logger.error('Error fetching custom fields:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch custom fields'
    });
  }
});

// @route   GET /api/custom-fields/:id
// @desc    Get single custom field
// @access  Private
router.get('/:id', protect, async (req, res) => {
  try {
    const customField = await CustomField.findById(req.params.id)
      .populate('createdBy', 'name email')
      .populate('updatedBy', 'name email');
    
    if (!customField) {
      return res.status(404).json({
        success: false,
        message: 'Custom field not found'
      });
    }
    
    res.json({
      success: true,
      data: customField
    });
  } catch (error) {
    logger.error('Error fetching custom field:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch custom field'
    });
  }
});

// @route   POST /api/custom-fields
// @desc    Create new custom field
// @access  Admin only
router.post('/', protect, authorize('admin'), async (req, res) => {
  try {
    const {
      fieldName,
      fieldLabel,
      fieldType,
      placeholder,
      helpText,
      required,
      options,
      validation,
      defaultValue,
      displayOrder,
      isActive,
      appliesTo,
      category,
      showInList,
      searchable
    } = req.body;
    
    // Validate required fields
    if (!fieldName || !fieldLabel || !fieldType) {
      return res.status(400).json({
        success: false,
        message: 'Please provide fieldName, fieldLabel, and fieldType'
      });
    }
    
    // Check if field with same name already exists
    const existingField = await CustomField.findOne({ 
      fieldName: fieldName.toLowerCase().replace(/[^a-z0-9]/g, '_').replace(/_{2,}/g, '_').replace(/^_|_$/g, '')
    });
    
    if (existingField) {
      return res.status(400).json({
        success: false,
        message: 'A field with this name already exists'
      });
    }
    
    // Validate options for select/multiselect/radio fields
    if (['select', 'multiselect', 'radio'].includes(fieldType) && (!options || options.length === 0)) {
      return res.status(400).json({
        success: false,
        message: 'Options are required for select, multiselect, and radio field types'
      });
    }
    
    const customField = new CustomField({
      fieldName,
      fieldLabel,
      fieldType,
      placeholder,
      helpText,
      required,
      options,
      validation,
      defaultValue,
      displayOrder,
      isActive,
      appliesTo,
      category,
      showInList,
      searchable,
      createdBy: req.user.id
    });
    
    await customField.save();
    
    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'custom_field_created',
      module: 'admin',
      resource: 'custom_field',
      resourceId: customField._id,
      details: {
        fieldName: customField.fieldName,
        fieldLabel: customField.fieldLabel,
        fieldType: customField.fieldType,
        appliesTo: customField.appliesTo
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    logger.info(`Custom field created: ${customField.fieldName} by user ${req.user.id}`);
    
    res.status(201).json({
      success: true,
      message: 'Custom field created successfully',
      data: customField
    });
  } catch (error) {
    logger.error('Error creating custom field:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'A field with this name already exists'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to create custom field'
    });
  }
});

// @route   PUT /api/custom-fields/:id
// @desc    Update custom field
// @access  Admin only
router.put('/:id', protect, authorize('admin'), async (req, res) => {
  try {
    const customField = await CustomField.findById(req.params.id);
    
    if (!customField) {
      return res.status(404).json({
        success: false,
        message: 'Custom field not found'
      });
    }
    
    const {
      fieldLabel,
      fieldType,
      placeholder,
      helpText,
      required,
      options,
      validation,
      defaultValue,
      displayOrder,
      isActive,
      appliesTo,
      category,
      showInList,
      searchable
    } = req.body;
    
    // Validate options for select/multiselect/radio fields
    if (['select', 'multiselect', 'radio'].includes(fieldType || customField.fieldType)) {
      if (!options || options.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Options are required for select, multiselect, and radio field types'
        });
      }
    }
    
    const oldData = customField.toObject();
    
    // Update fields (fieldName is immutable)
    if (fieldLabel) customField.fieldLabel = fieldLabel;
    if (fieldType) customField.fieldType = fieldType;
    if (placeholder !== undefined) customField.placeholder = placeholder;
    if (helpText !== undefined) customField.helpText = helpText;
    if (required !== undefined) customField.required = required;
    if (options) customField.options = options;
    if (validation) customField.validation = validation;
    if (defaultValue !== undefined) customField.defaultValue = defaultValue;
    if (displayOrder !== undefined) customField.displayOrder = displayOrder;
    if (isActive !== undefined) customField.isActive = isActive;
    if (appliesTo) customField.appliesTo = appliesTo;
    if (category) customField.category = category;
    if (showInList !== undefined) customField.showInList = showInList;
    if (searchable !== undefined) customField.searchable = searchable;
    customField.updatedBy = req.user.id;
    
    await customField.save();
    
    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'custom_field_updated',
      module: 'admin',
      resource: 'custom_field',
      resourceId: customField._id,
      details: {
        oldData,
        newData: customField.toObject()
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    logger.info(`Custom field updated: ${customField.fieldName} by user ${req.user.id}`);
    
    res.json({
      success: true,
      message: 'Custom field updated successfully',
      data: customField
    });
  } catch (error) {
    logger.error('Error updating custom field:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update custom field'
    });
  }
});

// @route   DELETE /api/custom-fields/:id
// @desc    Delete custom field
// @access  Admin only
router.delete('/:id', protect, authorize('admin'), async (req, res) => {
  try {
    const customField = await CustomField.findById(req.params.id);
    
    if (!customField) {
      return res.status(404).json({
        success: false,
        message: 'Custom field not found'
      });
    }
    
    const fieldData = customField.toObject();
    await customField.deleteOne();
    
    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'custom_field_deleted',
      module: 'admin',
      resource: 'custom_field',
      resourceId: req.params.id,
      details: {
        fieldName: fieldData.fieldName,
        fieldLabel: fieldData.fieldLabel,
        fieldType: fieldData.fieldType
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    logger.info(`Custom field deleted: ${fieldData.fieldName} by user ${req.user.id}`);
    
    res.json({
      success: true,
      message: 'Custom field deleted successfully'
    });
  } catch (error) {
    logger.error('Error deleting custom field:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete custom field'
    });
  }
});

// @route   POST /api/custom-fields/reorder
// @desc    Reorder custom fields
// @access  Admin only
router.post('/reorder', protect, authorize('admin'), async (req, res) => {
  try {
    const { fieldOrders } = req.body;
    
    if (!fieldOrders || !Array.isArray(fieldOrders)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an array of field orders'
      });
    }
    
    // Update display order for each field
    const updatePromises = fieldOrders.map(({ id, displayOrder }) =>
      CustomField.findByIdAndUpdate(id, { displayOrder, updatedBy: req.user.id })
    );
    
    await Promise.all(updatePromises);
    
    // Log the event
    await logEvent({
      userId: req.user.id,
      action: 'custom_fields_reordered',
      module: 'admin',
      resource: 'custom_field',
      details: {
        fieldOrders
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    logger.info(`Custom fields reordered by user ${req.user.id}`);
    
    res.json({
      success: true,
      message: 'Custom fields reordered successfully'
    });
  } catch (error) {
    logger.error('Error reordering custom fields:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reorder custom fields'
    });
  }
});

module.exports = router;



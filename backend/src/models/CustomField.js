const mongoose = require('mongoose');

const CustomFieldSchema = new mongoose.Schema({
  fieldName: {
    type: String,
    required: [true, 'Please add a field name'],
    trim: true,
    maxlength: [100, 'Field name cannot be more than 100 characters'],
  },
  fieldLabel: {
    type: String,
    required: [true, 'Please add a field label'],
    trim: true,
    maxlength: [200, 'Field label cannot be more than 200 characters'],
  },
  fieldType: {
    type: String,
    required: [true, 'Please add a field type'],
    enum: [
      'text',
      'email',
      'number',
      'phone',
      'date',
      'select',
      'multiselect',
      'textarea',
      'checkbox',
      'radio',
      'url',
      'file'
    ],
    default: 'text',
  },
  placeholder: {
    type: String,
    trim: true,
    maxlength: [200, 'Placeholder cannot be more than 200 characters'],
  },
  helpText: {
    type: String,
    trim: true,
    maxlength: [500, 'Help text cannot be more than 500 characters'],
  },
  required: {
    type: Boolean,
    default: false,
  },
  options: {
    type: [String],
    default: [],
    // Used for select, multiselect, radio field types
  },
  validation: {
    minLength: {
      type: Number,
      min: 0,
    },
    maxLength: {
      type: Number,
      min: 0,
    },
    min: {
      type: Number,
    },
    max: {
      type: Number,
    },
    pattern: {
      type: String,
    },
    patternMessage: {
      type: String,
    },
  },
  defaultValue: {
    type: String,
  },
  displayOrder: {
    type: Number,
    default: 0,
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  appliesTo: {
    type: String,
    enum: ['user', 'verification', 'both'],
    default: 'user',
    // user: applies to user profile/registration
    // verification: applies to verification records (PAN KYC, Aadhaar, etc.)
    // both: applies to both
  },
  category: {
    type: String,
    enum: ['personal', 'business', 'address', 'contact', 'other'],
    default: 'other',
  },
  showInList: {
    type: Boolean,
    default: false,
    // Whether to show this field in list views
  },
  searchable: {
    type: Boolean,
    default: false,
    // Whether this field should be searchable
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

// Index for better query performance
CustomFieldSchema.index({ fieldName: 1 });
CustomFieldSchema.index({ isActive: 1 });
CustomFieldSchema.index({ appliesTo: 1 });
CustomFieldSchema.index({ displayOrder: 1 });

// Ensure fieldName is unique
CustomFieldSchema.index({ fieldName: 1 }, { unique: true });

// Pre-save middleware to ensure fieldName is URL-friendly
CustomFieldSchema.pre('save', function(next) {
  if (this.isModified('fieldName')) {
    this.fieldName = this.fieldName
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '_')
      .replace(/_{2,}/g, '_')
      .replace(/^_|_$/g, '');
  }
  next();
});

module.exports = mongoose.model('CustomField', CustomFieldSchema);



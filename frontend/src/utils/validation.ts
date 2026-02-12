// Validation utilities for form fields

export interface ValidationResult {
  isValid: boolean;
  message?: string;
}

// PAN Number validation
export const validatePAN = (pan: string): ValidationResult => {
  const cleaned = pan.replace(/\s/g, '').toUpperCase();
  const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
  
  if (!cleaned) {
    return { isValid: false, message: 'PAN Number is required' };
  }
  
  if (cleaned.length !== 10) {
    return { isValid: false, message: 'PAN Number must be 10 characters' };
  }
  
  if (!panRegex.test(cleaned)) {
    return { isValid: false, message: 'Invalid PAN format (e.g., ABCDE1234F)' };
  }
  
  return { isValid: true };
};

// Aadhaar Number validation
export const validateAadhaar = (aadhaar: string): ValidationResult => {
  const cleaned = aadhaar.replace(/\s/g, '').replace(/-/g, '');
  
  if (!cleaned) {
    return { isValid: false, message: 'Aadhaar Number is required' };
  }
  
  if (cleaned.length !== 12) {
    return { isValid: false, message: 'Aadhaar Number must be 12 digits' };
  }
  
  if (!/^\d{12}$/.test(cleaned)) {
    return { isValid: false, message: 'Aadhaar Number must contain only digits' };
  }
  
  return { isValid: true };
};

// Email validation
export const validateEmail = (email: string): ValidationResult => {
  if (!email) {
    return { isValid: false, message: 'Email is required' };
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { isValid: false, message: 'Please enter a valid email address' };
  }
  
  return { isValid: true };
};

// Name validation
export const validateName = (name: string): ValidationResult => {
  if (!name.trim()) {
    return { isValid: false, message: 'Name is required' };
  }
  
  if (name.trim().length < 2) {
    return { isValid: false, message: 'Name must be at least 2 characters' };
  }
  
  if (name.trim().length > 100) {
    return { isValid: false, message: 'Name must be less than 100 characters' };
  }
  
  // Allow letters, spaces, hyphens, and apostrophes
  const nameRegex = /^[a-zA-Z\s\-']+$/;
  if (!nameRegex.test(name.trim())) {
    return { isValid: false, message: 'Name can only contain letters, spaces, hyphens, and apostrophes' };
  }
  
  return { isValid: true };
};

// Date of Birth validation
export const validateDateOfBirth = (dob: string): ValidationResult => {
  if (!dob.trim()) {
    return { isValid: false, message: 'Date of Birth is required' };
  }
  
  const dateRegex = /^\d{2}\/\d{2}\/\d{4}$/;
  if (!dateRegex.test(dob)) {
    return { isValid: false, message: 'Date must be in DD/MM/YYYY format' };
  }
  
  // Parse DD/MM/YYYY format
  const [day, month, year] = dob.split('/').map(Number);
  const date = new Date(year, month - 1, day); // month is 0-indexed in Date constructor
  const today = new Date();
  
  // Check if the parsed date is valid (handles invalid dates like 32/13/2023)
  if (date.getDate() !== day || date.getMonth() !== month - 1 || date.getFullYear() !== year) {
    return { isValid: false, message: 'Please enter a valid date' };
  }
  
  if (date > today) {
    return { isValid: false, message: 'Date of Birth cannot be in the future' };
  }
  
  const age = today.getFullYear() - date.getFullYear();
  if (age < 0 || age > 150) {
    return { isValid: false, message: 'Please enter a valid age' };
  }
  
  return { isValid: true };
};

// Password validation
export const validatePassword = (password: string): ValidationResult => {
  if (!password) {
    return { isValid: false, message: 'Password is required' };
  }
  
  if (password.length < 8) {
    return { isValid: false, message: 'Password must be at least 8 characters' };
  }
  
  if (!/(?=.*[a-z])/.test(password)) {
    return { isValid: false, message: 'Password must contain at least one lowercase letter' };
  }
  
  if (!/(?=.*[A-Z])/.test(password)) {
    return { isValid: false, message: 'Password must contain at least one uppercase letter' };
  }
  
  if (!/(?=.*\d)/.test(password)) {
    return { isValid: false, message: 'Password must contain at least one number' };
  }
  
  return { isValid: true };
};

// Phone number validation
export const validatePhone = (phone: string): ValidationResult => {
  if (!phone) {
    return { isValid: false, message: 'Phone number is required' };
  }
  
  const cleaned = phone.replace(/\s/g, '').replace(/-/g, '');
  const phoneRegex = /^[+]?[\d\s\-()]{10,15}$/;
  
  if (!phoneRegex.test(cleaned)) {
    return { isValid: false, message: 'Please enter a valid phone number' };
  }
  
  return { isValid: true };
};

// GST Number validation
export const validateGST = (gst: string): ValidationResult => {
  if (!gst) {
    return { isValid: true }; // GST is optional
  }
  
  const cleaned = gst.replace(/\s/g, '').toUpperCase();
  const gstRegex = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/;
  
  if (!gstRegex.test(cleaned)) {
    return { isValid: false, message: 'Invalid GST number format' };
  }
  
  return { isValid: true };
};

// Input filtering functions
export const filterPANInput = (value: string): string => {
  return value.replace(/[^A-Za-z0-9]/g, '').toUpperCase().substring(0, 10);
};

export const filterAadhaarInput = (value: string): string => {
  return value.replace(/[^0-9]/g, '').substring(0, 12);
};

export const filterNameInput = (value: string): string => {
  return value.replace(/[^a-zA-Z\s\-']/g, '');
};

export const filterPhoneInput = (value: string): string => {
  return value.replace(/[^0-9+\s\-()]/g, '');
};

export const filterEmailInput = (value: string): string => {
  return value.toLowerCase().trim();
};

export const filterDateInput = (value: string): string => {
  // Remove any non-digit characters except hyphens
  return value.replace(/[^0-9-]/g, '');
};

// Get validation status for UI
export const getValidationStatus = (value: string, validator: (val: string) => ValidationResult) => {
  if (!value) {
    return { status: 'empty', color: 'gray', icon: null, message: '' };
  }
  
  const result = validator(value);
  
  if (result.isValid) {
    return { status: 'valid', color: 'green', icon: 'check', message: '✓ Valid' };
  } else {
    return { status: 'invalid', color: 'red', icon: 'error', message: '✗ ' + result.message };
  }
};

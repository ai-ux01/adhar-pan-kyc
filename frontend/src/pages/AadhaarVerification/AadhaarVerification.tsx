import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import { 
  IdentificationIcon, 
  CheckCircleIcon, 
  XCircleIcon,
  ClockIcon,
  ArrowPathIcon,
  DocumentTextIcon,
  UserIcon,
  CalendarIcon,
  TrashIcon,
  CameraIcon,
  PhotoIcon
} from '@heroicons/react/24/outline';
import { validateAadhaar, filterAadhaarInput, getValidationStatus } from '../../utils/validation';
import CustomFieldsRenderer from '../../components/CustomFieldsRenderer';
import api from '../../services/api';

interface VerificationStep {
  step: 'enter-details' | 'otp-verification' | 'success' | 'error';
  data?: any;
}

interface CustomField {
  _id: string;
  fieldName: string;
  fieldLabel: string;
  fieldType: string;
  required: boolean;
  isActive: boolean;
  appliesTo: string;
}

const AadhaarVerification: React.FC = () => {
  const { user, token } = useAuth();
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState<VerificationStep>({ step: 'enter-details' });
  const [isLoading, setIsLoading] = useState(false);
  const [aadhaarNumber, setAadhaarNumber] = useState('');
  const [consentAccepted, setConsentAccepted] = useState(false);
  const [otp, setOtp] = useState('');
  const [transactionId, setTransactionId] = useState('');
  const [resendCooldown, setResendCooldown] = useState(0);
  const [canResend, setCanResend] = useState(false);
  const [customFields, setCustomFields] = useState<Record<string, any>>({});
  const [availableCustomFields, setAvailableCustomFields] = useState<CustomField[]>([]);
  const [customFieldErrors, setCustomFieldErrors] = useState<Record<string, string>>({});
  const [dynamicFields, setDynamicFields] = useState<Array<{id: string, label: string, value: string}>>([]);
  const [selfieFile, setSelfieFile] = useState<File | null>(null);
  const [selfiePreview, setSelfiePreview] = useState<string | null>(null);
  const [uploadingSelfie, setUploadingSelfie] = useState(false);
  const [selfieUploaded, setSelfieUploaded] = useState(false);
  const [verificationRecordId, setVerificationRecordId] = useState<string | null>(null);
  const [cameraMode, setCameraMode] = useState(false);
  const [videoStream, setVideoStream] = useState<MediaStream | null>(null);
  const videoRef = useRef<HTMLVideoElement>(null);

  // Email validation function
  const isValidEmail = (email: string): boolean => {
    if (!email) return true; // Empty is valid (not required)
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
  };

  // Fetch available custom fields on mount
  useEffect(() => {
    const fetchCustomFields = async () => {
      try {
        // If user has no enabled custom fields, show nothing
        if (!user?.enabledCustomFields || user.enabledCustomFields.length === 0) {
          setAvailableCustomFields([]);
          return;
        }

        const response = await api.get('/custom-fields', {
          params: {
            appliesTo: 'verification',
            isActive: 'true'
          }
        });
        
        let fieldsToShow = response.data.data || [];
        
        // Filter by enabled custom field IDs
        fieldsToShow = fieldsToShow.filter((field: CustomField) => 
          user.enabledCustomFields?.includes(field._id)
        );
        
        setAvailableCustomFields(fieldsToShow);
      } catch (error) {
        console.error('Error fetching custom fields:', error);
        setAvailableCustomFields([]);
      }
    };

    if (user) {
      fetchCustomFields();
    } else {
      // If no user, reset to empty
      setAvailableCustomFields([]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.enabledCustomFields, user]);

  // Countdown timer effect for resend OTP
  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (resendCooldown > 0) {
      interval = setInterval(() => {
        setResendCooldown((prev) => {
          if (prev <= 1) {
            setCanResend(true);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }

    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [resendCooldown]);

  // Email validation function for custom fields
  const isValidEmailFormat = (email: string): boolean => {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email.trim());
  };

  // Phone number validation function (exactly 10 digits, numeric only)
  const isValidPhoneNumber = (phone: string): boolean => {
    if (!phone || typeof phone !== 'string') return false;
    // Remove spaces, dashes, and other formatting characters
    const cleaned = phone.replace(/[\s\-()]/g, '');
    // Must be exactly 10 digits, numeric only
    return /^\d{10}$/.test(cleaned);
  };

  // Validate that all custom fields are filled and valid (all custom fields are mandatory)
  const areAllRequiredCustomFieldsFilled = (): boolean => {
    if (availableCustomFields.length === 0) return true; // No custom fields, so validation passes
    
    // Check if ALL custom fields (not just required ones) have values and are valid
    return availableCustomFields.every(field => {
      const value = customFields[field.fieldName];
      // Check if value exists and is not empty
      if (value === undefined || value === null) return false;
      if (typeof value === 'string' && value.trim() === '') return false;
      if (Array.isArray(value) && value.length === 0) return false;
      
      // Validate email format for email-type fields
      if (field.fieldType === 'email' && typeof value === 'string') {
        return isValidEmailFormat(value);
      }
      
      // Validate phone number format for phone-type fields
      if (field.fieldType === 'phone' && typeof value === 'string') {
        return isValidPhoneNumber(value);
      }
      
      return true;
    });
  };

  // Validate that all dynamic email fields have valid email format
  const areDynamicEmailFieldsValid = (): boolean => {
    return dynamicFields.every(field => {
      if (field.label === 'Email' || field.label === 'email') {
        const value = field.value?.trim();
        // If field has a value, it must be a valid email
        if (value && value !== '') {
          return isValidEmail(value);
        }
      }
      return true; // Non-email fields or empty email fields are valid
    });
  };

  // Validate email format in customFields (check for email-like field names)
  const areCustomEmailFieldsValid = (): boolean => {
    const emailFieldNames = ['email', 'Email', 'EMAIL', 'e-mail', 'E-mail'];
    return Object.entries(customFields).every(([fieldName, value]) => {
      const fieldNameLower = fieldName.toLowerCase();
      // Check if field name contains "email" or is an email-like field
      if (emailFieldNames.includes(fieldName) || fieldNameLower.includes('email') || fieldNameLower.includes('e-mail')) {
        const valueStr = typeof value === 'string' ? value.trim() : String(value).trim();
        // If field has a value, it must be a valid email
        if (valueStr && valueStr !== '') {
          return isValidEmailFormat(valueStr);
        }
      }
      return true; // Non-email fields or empty email fields are valid
    });
  };

  // Validate phone number format in dynamic fields
  const areDynamicPhoneFieldsValid = (): boolean => {
    const phoneFieldLabels = ['phone', 'Phone', 'PHONE', 'phone_no', 'Phone No', 'phone_no', 'mobile', 'Mobile', 'MOBILE', 'mobile_no', 'Mobile No'];
    return dynamicFields.every(field => {
      const fieldLabelLower = field.label?.toLowerCase() || '';
      // Check if field label contains "phone" or "mobile"
      if (phoneFieldLabels.includes(field.label) || fieldLabelLower.includes('phone') || fieldLabelLower.includes('mobile')) {
        const value = field.value?.trim();
        // If field has a value, it must be a valid phone number
        if (value && value !== '') {
          return isValidPhoneNumber(value);
        }
      }
      return true; // Non-phone fields or empty phone fields are valid
    });
  };

  // Validate phone number format in customFields (check for phone-like field names)
  const areCustomPhoneFieldsValid = (): boolean => {
    const phoneFieldNames = ['phone', 'Phone', 'PHONE', 'phone_no', 'phoneNo', 'mobile', 'Mobile', 'MOBILE', 'mobile_no', 'mobileNo'];
    return Object.entries(customFields).every(([fieldName, value]) => {
      const fieldNameLower = fieldName.toLowerCase();
      // Check if field name contains "phone" or "mobile"
      if (phoneFieldNames.includes(fieldName) || fieldNameLower.includes('phone') || fieldNameLower.includes('mobile')) {
        const valueStr = typeof value === 'string' ? value.trim() : String(value).trim();
        // If field has a value, it must be a valid phone number
        if (valueStr && valueStr !== '') {
          return isValidPhoneNumber(valueStr);
        }
      }
      return true; // Non-phone fields or empty phone fields are valid
    });
  };

  // Remove dynamic field
  const removeDynamicField = (id: string) => {
    setDynamicFields(dynamicFields.filter(field => field.id !== id));
  };

  // Update dynamic field value
  const updateDynamicField = (id: string, value: string) => {
    setDynamicFields(dynamicFields.map(field => {
      if (field.id === id) {
        // Filter input based on field type
        let filteredValue = value;
        
        // Emp Code should only accept numbers
        if (field.label === 'Emp Code') {
          filteredValue = value.replace(/[^0-9]/g, '');
        }
        
        // Phone No should only accept numbers, +, -, spaces, and parentheses
        if (field.label === 'Phone No') {
          // First, remove all non-numeric characters except + at the beginning
          let cleanedValue = value.replace(/[^0-9+]/g, '');
          
          // If it starts with +, keep it, otherwise remove it
          if (cleanedValue.startsWith('+')) {
            // For international numbers, allow the + but limit to reasonable length
            if (cleanedValue.length > 15) {
              cleanedValue = cleanedValue.substring(0, 15);
            }
          } else {
            // For local numbers, ensure exactly 10 digits and starts with 6-9
            cleanedValue = cleanedValue.replace(/[^0-9]/g, '');
            if (cleanedValue.length > 10) {
              cleanedValue = cleanedValue.substring(0, 10);
            }
            // If it has digits, ensure first digit is 6 or greater
            if (cleanedValue.length > 0 && cleanedValue[0] < '6') {
              cleanedValue = cleanedValue.substring(1);
            }
          }
          
          filteredValue = cleanedValue;
        }
        
        // Email validation - allow valid email characters
        if (field.label === 'Email') {
          // Allow letters, numbers, @, ., -, _, and + (for email aliases)
          filteredValue = value.replace(/[^a-zA-Z0-9@._+-]/g, '');
          
          // Limit length to reasonable email length
          if (filteredValue.length > 254) {
            filteredValue = filteredValue.substring(0, 254);
          }
        }
        
        return { ...field, value: filteredValue };
      }
      return field;
    }));
  };

  // Get Aadhaar validation status for UI
  const getAadhaarValidationStatus = () => {
    return getValidationStatus(aadhaarNumber, validateAadhaar);
  };

  // Format Aadhaar number for display
  const formatAadhaarNumber = (number: string) => {
    const cleaned = number.replace(/\s+/g, '').replace(/-/g, '');
    return cleaned.replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3');
  };


  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const aadhaarValidation = validateAadhaar(aadhaarNumber);
    if (!aadhaarValidation.isValid) {
      toast.error(aadhaarValidation.message || 'Please enter a valid Aadhaar number');
      return;
    }

    if (!consentAccepted) {
      toast.error('Please accept the consent to proceed');
      return;
    }

    // Validate that all custom fields are filled and valid (all custom fields are mandatory)
    if (!areAllRequiredCustomFieldsFilled()) {
      const missingFields = availableCustomFields.filter(field => {
        const value = customFields[field.fieldName];
        if (value === undefined || value === null) return true;
        if (typeof value === 'string' && value.trim() === '') return true;
        if (Array.isArray(value) && value.length === 0) return true;
        return false;
      });
      
      const invalidEmailFields = availableCustomFields.filter(field => {
        if (field.fieldType === 'email') {
          const value = customFields[field.fieldName];
          if (value && typeof value === 'string' && value.trim() !== '') {
            return !isValidEmailFormat(value);
          }
        }
        return false;
      });

      const invalidPhoneFields = availableCustomFields.filter(field => {
        if (field.fieldType === 'phone') {
          const value = customFields[field.fieldName];
          if (value && typeof value === 'string' && value.trim() !== '') {
            return !isValidPhoneNumber(value);
          }
        }
        return false;
      });
      
      if (missingFields.length > 0) {
        const missingFieldNames = missingFields.map(f => f.fieldLabel).join(', ');
        toast.error(`Please fill all custom fields: ${missingFieldNames}`);
      return;
    }

      if (invalidEmailFields.length > 0) {
        const invalidEmailNames = invalidEmailFields.map(f => f.fieldLabel).join(', ');
        toast.error(`Please enter a valid email address for: ${invalidEmailNames}`);
        return;
      }

      if (invalidPhoneFields.length > 0) {
        const invalidPhoneNames = invalidPhoneFields.map(f => f.fieldLabel).join(', ');
        toast.error(`Please enter a valid phone number (numeric only) for: ${invalidPhoneNames}`);
        return;
      }
    }

    // Validate email format in dynamic fields
    const invalidDynamicEmailFields = dynamicFields.filter(field => {
      if (field.label === 'Email' || field.label === 'email') {
        const value = field.value?.trim();
        // If field has a value, it must be a valid email
        if (value && value !== '') {
          return !isValidEmail(value);
        }
      }
      return false;
    });

    if (invalidDynamicEmailFields.length > 0) {
      toast.error('Please enter a valid email address for the Email field');
      return;
    }

    // Validate email format in customFields (check for email-like field names)
    const emailFieldNames = ['email', 'Email', 'EMAIL', 'e-mail', 'E-mail'];
    const invalidCustomEmailFields = Object.entries(customFields).filter(([fieldName, value]) => {
      const fieldNameLower = fieldName.toLowerCase();
      // Check if field name contains "email" or is an email-like field
      if (emailFieldNames.includes(fieldName) || fieldNameLower.includes('email') || fieldNameLower.includes('e-mail')) {
        const valueStr = typeof value === 'string' ? value.trim() : String(value).trim();
        // If field has a value, it must be a valid email
        if (valueStr && valueStr !== '') {
          return !isValidEmailFormat(valueStr);
        }
      }
      return false;
    });

    if (invalidCustomEmailFields.length > 0) {
      const invalidFieldNames = invalidCustomEmailFields.map(([fieldName]) => fieldName).join(', ');
      toast.error(`Please enter a valid email address for: ${invalidFieldNames}`);
      return;
    }

    // Validate phone number format in dynamic fields
    const phoneFieldLabels = ['phone', 'Phone', 'PHONE', 'phone_no', 'Phone No', 'phone_no', 'mobile', 'Mobile', 'MOBILE', 'mobile_no', 'Mobile No'];
    const invalidDynamicPhoneFields = dynamicFields.filter(field => {
      const fieldLabelLower = field.label?.toLowerCase() || '';
      // Check if field label contains "phone" or "mobile"
      if (phoneFieldLabels.includes(field.label) || fieldLabelLower.includes('phone') || fieldLabelLower.includes('mobile')) {
        const value = field.value?.trim();
        // If field has a value, it must be a valid phone number
        if (value && value !== '') {
          return !isValidPhoneNumber(value);
        }
      }
      return false;
    });

    if (invalidDynamicPhoneFields.length > 0) {
      const invalidFieldLabels = invalidDynamicPhoneFields.map(f => f.label).join(', ');
      toast.error(`Please enter a valid phone number (numeric only) for: ${invalidFieldLabels}`);
      return;
    }

    // Validate phone number format in customFields (check for phone-like field names)
    const phoneFieldNames = ['phone', 'Phone', 'PHONE', 'phone_no', 'phoneNo', 'mobile', 'Mobile', 'MOBILE', 'mobile_no', 'mobileNo'];
    const invalidCustomPhoneFields = Object.entries(customFields).filter(([fieldName, value]) => {
      const fieldNameLower = fieldName.toLowerCase();
      // Check if field name contains "phone" or "mobile"
      if (phoneFieldNames.includes(fieldName) || fieldNameLower.includes('phone') || fieldNameLower.includes('mobile')) {
        const valueStr = typeof value === 'string' ? value.trim() : String(value).trim();
        // If field has a value, it must be a valid phone number
        if (valueStr && valueStr !== '') {
          return !isValidPhoneNumber(valueStr);
        }
      }
      return false;
    });

    if (invalidCustomPhoneFields.length > 0) {
      const invalidFieldNames = invalidCustomPhoneFields.map(([fieldName]) => fieldName).join(', ');
      toast.error(`Please enter a valid phone number (numeric only) for: ${invalidFieldNames}`);
      return;
    }

    setIsLoading(true);
    try {
      // Determine API base URL
      const getApiBaseURL = () => {
        if (process.env.REACT_APP_API_URL) return process.env.REACT_APP_API_URL;
        const isProduction = window.location.hostname !== 'localhost' && 
                             window.location.hostname !== '127.0.0.1' &&
                             !window.location.hostname.startsWith('192.168.');
        return isProduction ? 'https://adhar-pan-kyc-1.onrender.com/api' : 'http://localhost:3002/api';
      };
      const response = await fetch(`${getApiBaseURL()}/aadhaar-verification/verify-single`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token') || sessionStorage.getItem('token')}`
        },
        body: JSON.stringify({ 
          aadhaarNumber: aadhaarNumber.replace(/\s+/g, '').replace(/-/g, ''),
          dynamicFields: [
            ...dynamicFields.map(field => ({
            label: field.label,
            value: field.value.trim()
          })),
            // Include custom fields
            ...Object.entries(customFields).map(([key, value]) => ({
              label: key,
              value: value
            }))
          ],
          customFields: customFields,
          consentAccepted: consentAccepted
        })
      });

      const data = await response.json();

      if (data.success) {
        if (data.data.otpSent) {
          setTransactionId(data.data.transactionId);
          setCurrentStep({ step: 'otp-verification', data: data.data });
          setResendCooldown(30); // Start 30-second countdown
          setCanResend(false);
          toast.success('OTP sent successfully! Please check your registered mobile number.');
        } else {
          setCurrentStep({ step: 'success', data: data.data });
          setVerificationRecordId(data.data.recordId || null);
          toast.success('Aadhaar verification completed successfully!');
        }
      } else {
        setCurrentStep({ step: 'error', data: { message: data.message } });
        toast.error(data.message || 'Verification failed');
      }
    } catch (error) {
      console.error('Error verifying Aadhaar:', error);
      setCurrentStep({ step: 'error', data: { message: 'Failed to verify Aadhaar. Please try again.' } });
      toast.error('Failed to verify Aadhaar. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle resend OTP
  const handleResendOtp = async () => {
    if (!canResend) return;
    
    
    setIsLoading(true);
    try {
      const response = await fetch('/api/aadhaar-verification/verify-single', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
          dynamicFields: [
            ...dynamicFields.map(field => ({
            label: field.label,
            value: field.value.trim()
          })),
            // Include custom fields
            ...Object.entries(customFields).map(([key, value]) => ({
              label: key,
              value: value
            }))
          ],
          customFields: customFields,
          consentAccepted: true
        })
      });

      const data = await response.json();

      if (data.success) {
        setTransactionId(data.data.transactionId);
        setResendCooldown(30); // Reset countdown
        setCanResend(false);
        toast.success('OTP resent successfully!');
      } else {
        toast.error(data.message || 'Failed to resend OTP');
      }
    } catch (error) {
      console.error('Error resending OTP:', error);
      toast.error('Failed to resend OTP. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle OTP verification
  const handleOtpVerification = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!otp.trim() || otp.length !== 6) {
      toast.error('Please enter a valid 6-digit OTP');
      return;
    }

    setIsLoading(true);
    try {
      // Determine API base URL
      const getApiBaseURL = () => {
        if (process.env.REACT_APP_API_URL) return process.env.REACT_APP_API_URL;
        const isProduction = window.location.hostname !== 'localhost' && 
                             window.location.hostname !== '127.0.0.1' &&
                             !window.location.hostname.startsWith('192.168.');
        return isProduction ? 'https://adhar-pan-kyc-1.onrender.com/api' : 'http://localhost:3002/api';
      };
      const response = await fetch(`${getApiBaseURL()}/aadhaar-verification/verify-otp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token') || sessionStorage.getItem('token')}`
        },
        body: JSON.stringify({
          aadhaarNumber: aadhaarNumber.replace(/\s+/g, '').replace(/-/g, ''),
          otp: otp.trim(),
          transactionId: transactionId,
          dynamicFields: dynamicFields.map(field => ({
            label: field.label,
            value: field.value.trim()
          }))
        })
      });

      const data = await response.json();

      if (data.success) {
        setCurrentStep({ step: 'success', data: data.data });
        setVerificationRecordId(data.data.recordId || null);
        toast.success('Aadhaar verification completed successfully!');
      } else {
        setCurrentStep({ step: 'error', data: { message: data.message } });
        toast.error(data.message || 'OTP verification failed');
      }
    } catch (error) {
      console.error('Error verifying OTP:', error);
      setCurrentStep({ step: 'error', data: { message: 'Failed to verify OTP. Please try again.' } });
      toast.error('Failed to verify OTP. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // Reset to initial state
  const resetVerification = () => {
    setCurrentStep({ step: 'enter-details' });
    setAadhaarNumber('');
    setConsentAccepted(false);
    setOtp('');
    setTransactionId('');
    setResendCooldown(0);
    setCanResend(false);
    setDynamicFields([]);
    setSelfieFile(null);
    setSelfiePreview(null);
    setSelfieUploaded(false);
    setVerificationRecordId(null);
    closeCamera(); // Close camera if open
  };

  // Open camera for selfie capture
  const openCamera = async () => {
    try {
      // Request camera access
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: 'user', // Front camera for selfie
          width: { ideal: 1280 },
          height: { ideal: 720 }
        },
        audio: false
      });

      setVideoStream(stream);
      setCameraMode(true);
    } catch (error: any) {
      console.error('Error accessing camera:', error);
      if (error.name === 'NotAllowedError' || error.name === 'PermissionDeniedError') {
        toast.error('Camera permission denied. Please allow camera access and try again.');
      } else if (error.name === 'NotFoundError' || error.name === 'DevicesNotFoundError') {
        toast.error('No camera found. Please use file upload instead.');
      } else {
        toast.error('Unable to access camera. Please use file upload instead.');
      }
      setCameraMode(false);
    }
  };

  // Close camera
  const closeCamera = () => {
    if (videoStream) {
      videoStream.getTracks().forEach(track => track.stop());
      setVideoStream(null);
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setCameraMode(false);
  };

  // Capture image from camera
  const captureFromCamera = () => {
    if (!videoRef.current) return;

    const canvas = document.createElement('canvas');
    canvas.width = videoRef.current.videoWidth;
    canvas.height = videoRef.current.videoHeight;
    const ctx = canvas.getContext('2d');
    
    if (ctx) {
      ctx.drawImage(videoRef.current, 0, 0);
      
      // Convert canvas to blob
      canvas.toBlob((blob) => {
        if (blob) {
          // Create a File from the blob
          const file = new File([blob], 'selfie.jpg', { type: 'image/jpeg' });
          setSelfieFile(file);
          
          // Create preview
          setSelfiePreview(canvas.toDataURL('image/jpeg'));
          
          // Close camera
          closeCamera();
        }
      }, 'image/jpeg', 0.9);
    }
  };

  // Handle selfie file selection (fallback for file upload)
  const handleSelfieSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith('image/')) {
      toast.error('Please select an image file');
      return;
    }

    // Validate file size (5MB)
    if (file.size > 5 * 1024 * 1024) {
      toast.error('Image size must be less than 5MB');
      return;
    }

    setSelfieFile(file);
    
    // Create preview
    const reader = new FileReader();
    reader.onloadend = () => {
      setSelfiePreview(reader.result as string);
    };
    reader.readAsDataURL(file);
  };

  // Update video element when stream changes
  useEffect(() => {
    const videoElement = videoRef.current;
    if (videoElement && videoStream) {
      videoElement.srcObject = videoStream;
      videoElement.play().catch(err => {
        console.error('Error playing video:', err);
      });
    }
    return () => {
      if (videoElement) {
        videoElement.srcObject = null;
      }
    };
  }, [videoStream]);

  // Cleanup camera stream on unmount
  useEffect(() => {
    return () => {
      if (videoStream) {
        videoStream.getTracks().forEach(track => track.stop());
      }
    };
  }, [videoStream]);

  // Handle selfie upload
  const handleSelfieUpload = async () => {
    if (!selfieFile || !verificationRecordId) {
      toast.error('Please select a selfie image');
      return;
    }

    setUploadingSelfie(true);
    try {
      const formData = new FormData();
      formData.append('selfie', selfieFile);

      const authToken = token || localStorage.getItem('token') || sessionStorage.getItem('token');
      
      const response = await fetch(
        `${(() => {
          if (process.env.REACT_APP_API_URL) return process.env.REACT_APP_API_URL;
          const isProduction = window.location.hostname !== 'localhost' && 
                               window.location.hostname !== '127.0.0.1' &&
                               !window.location.hostname.startsWith('192.168.');
          return isProduction ? 'https://adhar-pan-kyc-1.onrender.com/api' : 'http://localhost:3002/api';
        })()}/aadhaar-verification/records/${verificationRecordId}/selfie`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${authToken}`
          },
          body: formData
        }
      );

      const data = await response.json();

      if (data.success) {
        setSelfieUploaded(true);
        toast.success('Selfie uploaded successfully!');
      } else {
        toast.error(data.message || 'Failed to upload selfie');
      }
    } catch (error) {
      console.error('Error uploading selfie:', error);
      toast.error('Failed to upload selfie. Please try again.');
    } finally {
      setUploadingSelfie(false);
    }
  };

  // Check if user has selfie-upload module access
  const hasSelfieUploadAccess = user?.role === 'admin' || (user?.moduleAccess && user.moduleAccess.includes('selfie-upload'));

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 relative overflow-visible">
      {/* Subtle Animated Background Elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-200 rounded-full mix-blend-multiply filter blur-xl opacity-30 animate-pulse"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-purple-200 rounded-full mix-blend-multiply filter blur-xl opacity-30 animate-pulse"></div>
        <div className="absolute top-40 left-1/2 w-80 h-80 bg-indigo-200 rounded-full mix-blend-multiply filter blur-xl opacity-30 animate-pulse"></div>
      </div>

      <div className="relative z-10 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8" style={{ overflow: 'visible' }}>
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div className="relative group">
              <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full blur-lg opacity-60 group-hover:opacity-80 transition-opacity duration-300"></div>
              <div className="relative p-3 bg-white rounded-full shadow-xl border-4 border-white/50 transform group-hover:scale-105 transition-transform duration-300">
                <IdentificationIcon className="w-8 h-8 text-blue-600" />
              </div>
            </div>
          </div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-600 bg-clip-text text-transparent mb-3">
            Aadhaar Verification
          </h1>
          <p className="text-base text-gray-600 mb-6 max-w-2xl mx-auto">
            🔐 Secure OTP-based verification with real-time validation and comprehensive data retrieval
          </p>
          
          {/* Navigation Buttons */}
          <div className="flex justify-center space-x-4">
          <button
            onClick={() => navigate('/aadhaar-verification-records')}
              className="group relative inline-flex items-center px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
          >
              <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-500 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              <DocumentTextIcon className="w-5 h-5 mr-2 relative z-10" />
              <span className="relative z-10 text-base">View Records</span>
          </button>
          </div>
        </div>

        <div className="max-w-5xl mx-auto">
          {/* Main Verification Area */}
          <div>
            <div className="bg-white/95 backdrop-blur-lg border border-white/50 rounded-2xl shadow-xl p-4 lg:p-6 transform hover:scale-[1.01] transition-transform duration-300" style={{ overflow: 'visible' }}>
              {/* Step 1: Enter Details */}
              {currentStep.step === 'enter-details' && (
                <div>
                  <h2 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mb-3 text-center">
                    ✨ Enter Aadhaar Details
                  </h2>
                  <form onSubmit={handleSubmit} className="space-y-3">
                    {/* Form Fields */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3" style={{ overflow: 'visible' }}>
                      {/* Aadhaar Number Field */}
                      <div className="group">
                        <label htmlFor="aadhaarNumber" className="block text-xs font-bold text-gray-700 mb-2 flex items-center">
                          <span className="w-2 h-2 bg-blue-500 rounded-full mr-2"></span>
                          Aadhaar Number *
                      </label>
                      <div className="relative">
                        <input
                          type="text"
                          id="aadhaarNumber"
                          value={aadhaarNumber}
                          onChange={(e) => setAadhaarNumber(filterAadhaarInput(e.target.value))}
                          placeholder="1234 5678 9012"
                          className={`w-full px-3 py-2 pr-10 border border-gray-300 rounded-md focus:ring-1 focus:ring-blue-500 focus:border-blue-500 text-base font-medium transition-all duration-300 ${
                            aadhaarNumber.length === 0 
                              ? 'border-gray-200 focus:border-blue-500' 
                              : aadhaarNumber.length === 12 && getAadhaarValidationStatus().status === 'valid'
                              ? 'border-green-500 focus:border-green-500 bg-green-50'
                              : aadhaarNumber.length === 12 && getAadhaarValidationStatus().status === 'invalid'
                              ? 'border-red-500 focus:border-red-500 bg-red-50'
                              : 'border-yellow-500 focus:border-yellow-500 bg-yellow-50'
                          }`}
                          maxLength={12}
                          required
                        />
                        {aadhaarNumber.length > 0 && (
                          <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                            {aadhaarNumber.length === 12 && getAadhaarValidationStatus().status === 'valid' ? (
                              <CheckCircleIcon className="w-5 h-5 text-green-500" />
                            ) : aadhaarNumber.length === 12 && getAadhaarValidationStatus().status === 'invalid' ? (
                              <XCircleIcon className="w-5 h-5 text-red-500" />
                            ) : (
                              <ClockIcon className="w-5 h-5 text-yellow-500" />
                            )}
                          </div>
                        )}
                      </div>
                      <div className="mt-1 text-xs text-center">
                        {aadhaarNumber.length === 0 ? (
                          <span className="text-gray-500">Enter 12-digit Aadhaar number</span>
                        ) : aadhaarNumber.length === 12 && getAadhaarValidationStatus().status === 'valid' ? (
                          <span className="text-green-600 font-medium">✓ Valid Aadhaar format</span>
                        ) : aadhaarNumber.length === 12 && getAadhaarValidationStatus().status === 'invalid' ? (
                          <span className="text-red-600 font-medium">✗ Invalid Aadhaar format</span>
                        ) : (
                          <span className="text-yellow-600 font-medium">
                            {aadhaarNumber.length}/12 digits
                          </span>
                        )}
                      </div>
                      </div>

                     
                    </div>


                    {/* Dynamic Fields */}
                    {dynamicFields.length > 0 && (
                      <div className="mt-6">
                        <h3 className="text-base font-bold text-gray-700 mb-3 flex items-center">
                          <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                          Additional Fields ({dynamicFields.length})
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                          {dynamicFields.map((field, index) => (
                            <div key={field.id} className="group relative">
                              <label className="block text-xs font-bold text-gray-700 mb-1 flex items-center">
                                <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                                {field.label}
                              </label>
                              <div className="relative">
                                <input
                                  type={field.label === 'Emp Code' || field.label === 'Phone No' ? 'text' : 
                                        field.label === 'Email' ? 'email' : 'text'}
                                  inputMode={field.label === 'Emp Code' || field.label === 'Phone No' ? 'numeric' : undefined}
                                  value={field.value}
                                  onChange={(e) => updateDynamicField(field.id, e.target.value)}
                                  onKeyPress={(e) => {
                                    // Emp Code: Only allow numeric characters
                                    if (field.label === 'Emp Code' && !/[0-9]/.test(e.key)) {
                                      e.preventDefault();
                                    }
                                  }}
                                  placeholder={
                                    field.label === 'Emp Code' ? 'Enter employee code (numbers only)' :
                                    field.label === 'Phone No' ? 'Enter 10-digit phone number (starts with 6-9)' :
                                    field.label === 'Email' ? 'Enter email address (e.g., user@example.com)' :
                                    `Enter ${field.label.toLowerCase()}`
                                  }
                                  className={`w-full px-3 py-2 pr-10 border border-gray-300 rounded-md focus:ring-1 focus:ring-green-500 focus:border-green-500 text-sm font-medium transition-all duration-300 ${
                                    field.label === 'Email' && field.value && !isValidEmail(field.value)
                                      ? 'border-red-300 focus:ring-red-500/20 focus:border-red-500 bg-red-50'
                                      : field.label === 'Email' && field.value && isValidEmail(field.value)
                                      ? 'border-green-300 focus:ring-green-500/20 focus:border-green-500 bg-green-50'
                                      : 'border-gray-200 focus:ring-indigo-500/20 focus:border-indigo-500 group-hover:border-indigo-300'
                                  }`}
                                />
                                <button
                                  type="button"
                                  onClick={() => removeDynamicField(field.id)}
                                  className="absolute right-2 top-1/2 transform -translate-y-1/2 p-1 bg-red-500 hover:bg-red-600 text-white rounded-full transition-all duration-300 hover:scale-110 shadow-lg"
                                  title="Remove field"
                                >
                                  <TrashIcon className="w-3 h-3" />
                                </button>
                              </div>
                              {/* Email validation feedback */}
                              {field.label === 'Email' && field.value && !isValidEmail(field.value) && (
                                <p className="mt-1 text-xs text-red-600 font-medium flex items-center">
                                  <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                                  </svg>
                                  Please enter a valid email address
                                </p>
                              )}
                              {field.label === 'Email' && field.value && isValidEmail(field.value) && (
                                <p className="mt-1 text-xs text-green-600 font-medium flex items-center">
                                  <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                                  </svg>
                                  Valid email format
                                </p>
                              )}
                          </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Custom Fields from Admin */}
                    {availableCustomFields.length > 0 && (
                      <div className="mt-6">
                        <h3 className="text-base font-bold text-gray-700 mb-3 flex items-center">
                          <span className="w-2 h-2 bg-purple-500 rounded-full mr-2"></span>
                          Custom Fields
                        </h3>
                        <CustomFieldsRenderer
                          appliesTo="verification"
                          values={customFields}
                          onChange={(fieldName, value) => {
                            setCustomFields({
                              ...customFields,
                              [fieldName]: value
                            });
                            
                            // Validate email fields in real-time
                            const field = availableCustomFields.find(f => f.fieldName === fieldName);
                            if (field && field.fieldType === 'email' && typeof value === 'string') {
                              if (value.trim() === '') {
                                // Clear error if field is empty (will be caught by required validation)
                                setCustomFieldErrors(prev => {
                                  const newErrors = { ...prev };
                                  delete newErrors[fieldName];
                                  return newErrors;
                                });
                              } else if (!isValidEmailFormat(value)) {
                                setCustomFieldErrors(prev => ({
                                  ...prev,
                                  [fieldName]: 'Please enter a valid email address'
                                }));
                              } else {
                                // Clear error if email is valid
                                setCustomFieldErrors(prev => {
                                  const newErrors = { ...prev };
                                  delete newErrors[fieldName];
                                  return newErrors;
                                });
                              }
                            } else {
                              // Clear error for non-email fields
                              setCustomFieldErrors(prev => {
                                const newErrors = { ...prev };
                                delete newErrors[fieldName];
                                return newErrors;
                              });
                            }
                          }}
                          errors={customFieldErrors}
                          enabledCustomFieldIds={user?.enabledCustomFields}
                        />
                      </div>
                    )}

                    {/* Consent Checkbox */}
                    <div className="flex items-start bg-gradient-to-r from-blue-50 to-purple-50 p-4 rounded-xl border-2 border-blue-100">
                      <div className="flex items-center h-5">
                          <input
                          id="consent"
                            type="checkbox"
                            checked={consentAccepted}
                            onChange={(e) => setConsentAccepted(e.target.checked)}
                          className="w-4 h-4 text-blue-600 bg-white border-2 border-gray-300 rounded-lg focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300"
                          required
                        />
                      </div>
                      <div className="ml-3 text-sm">
                        <label htmlFor="consent" className="font-bold text-gray-700 cursor-pointer">
                          ✅ Aadhaar Consent Declaration *
                          </label>
                        <div className="text-gray-600 mt-1 text-xs space-y-2">
                          <p className="font-semibold">I hereby voluntarily provide my Aadhaar details to {user?.branding?.companyName || 'the Company'} for the purpose of employee verification, statutory compliance, and internal record maintenance.</p>
                          
                          <p className="font-semibold">I confirm and acknowledge that:</p>
                          
                          <ul className="list-disc list-inside space-y-1 ml-2">
                            <li>My Aadhaar information will be used only for official and lawful purposes, including identity verification and compliance with applicable laws.</li>
                            <li>The company shall ensure the confidentiality and security of my Aadhaar details, in accordance with the Aadhaar Act, 2016 and relevant data protection regulations.</li>
                            <li>I am submitting this information willingly and without any coercion or undue pressure.</li>
                            <li>I authorize {user?.branding?.companyName || 'the Company'} to use, store, and process the provided Aadhaar details solely for the purposes stated above.</li>
                            <li>The information I have provided is true and correct to the best of my knowledge.</li>
                          </ul>
                          
                          <p className="font-semibold">I have read and understood the above declaration and provide my consent.</p>
                        </div>
                      </div>
                    </div>
                    
                    <button
                      type="submit"
                      disabled={isLoading || !validateAadhaar(aadhaarNumber).isValid || !consentAccepted || !areAllRequiredCustomFieldsFilled() || !areDynamicEmailFieldsValid() || !areCustomEmailFieldsValid() || !areDynamicPhoneFieldsValid() || !areCustomPhoneFieldsValid() || Object.keys(customFieldErrors).length > 0}
                      className="group relative w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-4 px-6 rounded-xl font-bold text-lg shadow-2xl hover:shadow-3xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-600 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                      {isLoading ? (
                        <div className="flex items-center justify-center relative z-10">
                          <ArrowPathIcon className="w-5 h-5 animate-spin mr-2" />
                          <span className="text-base">Sending OTP...</span>
                        </div>
                      ) : (
                        <span className="relative z-10 flex items-center justify-center">
                          <span className="mr-2">🚀</span>
                          Send OTP
                        </span>
                      )}
                    </button>
                  </form>
                </div>
              )}

              {/* Step 2: OTP Verification */}
              {currentStep.step === 'otp-verification' && (
                <div>
                  <h2 className="text-2xl font-bold bg-gradient-to-r from-green-600 to-blue-600 bg-clip-text text-transparent mb-4 text-center">
                    📱 Enter OTP
                  </h2>
                  <p className="text-base text-gray-600 mb-6 text-center max-w-xl mx-auto">
                    🔐 We have sent a 6-digit OTP to your registered mobile number. Please enter it below to complete the verification.
                  </p>
                  
                  <form onSubmit={handleOtpVerification} className="space-y-3">
                    <div className="group">
                      <label htmlFor="otp" className="block text-base font-bold text-gray-700 mb-2 text-center">
                        <span className="w-3 h-3 bg-green-500 rounded-full mr-2 inline-block"></span>
                        OTP Code *
                      </label>
                      <input
                        type="text"
                        id="otp"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        placeholder="123456"
                        className="w-full px-4 py-3 border border-gray-300 rounded-md focus:ring-1 focus:ring-green-500 focus:border-green-500 text-lg text-center tracking-widest font-bold transition-all duration-300"
                        maxLength={6}
                        required
                      />
                      <p className="mt-4 text-center text-gray-600 font-medium">
                        📲 Enter the 6-digit OTP sent to your mobile number
                      </p>
                    </div>
                    
                    <button
                      type="submit"
                      disabled={isLoading || otp.length !== 6}
                      className="group relative w-full bg-gradient-to-r from-green-600 to-blue-600 text-white py-5 px-8 rounded-2xl font-bold text-xl shadow-2xl hover:shadow-3xl focus:outline-none focus:ring-4 focus:ring-green-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-green-600 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                      {isLoading ? (
                        <div className="flex items-center justify-center relative z-10">
                          <ArrowPathIcon className="w-6 h-6 animate-spin mr-3" />
                          <span className="text-lg">Verifying OTP...</span>
                        </div>
                      ) : (
                        <span className="relative z-10 flex items-center justify-center">
                          <span className="mr-2">✅</span>
                          Verify OTP
                        </span>
                      )}
                    </button>
                  </form>
                  
                  <div className="mt-6 text-center space-y-3">
                      <button
                      onClick={() => setCurrentStep({ step: 'enter-details' })}
                      className="group inline-flex items-center px-6 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 font-semibold rounded-xl transition-all duration-300 transform hover:scale-105"
                      >
                      <span className="mr-2">←</span>
                      Back to form
                      </button>
                    
                    <div className="bg-gradient-to-r from-yellow-50 to-orange-50 p-4 rounded-xl border border-yellow-100">
                      <p className="text-base font-semibold text-gray-700 mb-3 text-center">
                        📱 Didn't receive the OTP?
                      </p>
                      <button
                        onClick={handleResendOtp}
                        disabled={!canResend || isLoading}
                        className={`group relative w-full px-4 py-3 rounded-lg font-bold text-base transition-all duration-300 transform ${
                          canResend && !isLoading
                            ? 'bg-gradient-to-r from-orange-500 to-red-500 text-white hover:shadow-2xl hover:scale-105 focus:outline-none focus:ring-4 focus:ring-orange-500/20'
                            : 'bg-gray-300 text-gray-500 cursor-not-allowed'
                        }`}
                      >
                        <div className={`absolute inset-0 bg-gradient-to-r from-red-500 to-orange-500 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 ${!canResend || isLoading ? 'hidden' : ''}`}></div>
                        {isLoading ? (
                          <div className="flex items-center justify-center relative z-10">
                            <ArrowPathIcon className="w-5 h-5 animate-spin mr-2" />
                            <span>Resending...</span>
                          </div>
                        ) : resendCooldown > 0 ? (
                          <span className="relative z-10">⏰ Resend OTP in {resendCooldown}s</span>
                        ) : (
                          <span className="relative z-10 flex items-center justify-center">
                            <span className="mr-2">🔄</span>
                            Resend OTP
                          </span>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* Step 3: Success */}
              {currentStep.step === 'success' && (
                <div className="text-center">
                  <div className="flex justify-center mb-8">
                    <div className="relative">
                      <div className="absolute inset-0 bg-green-400 rounded-full blur-lg opacity-60 animate-pulse"></div>
                      <div className="relative p-6 bg-white rounded-full shadow-2xl border-4 border-green-100">
                        <CheckCircleIcon className="w-20 h-20 text-green-500" />
                      </div>
                    </div>
                  </div>
                  <h2 className="text-5xl font-bold bg-gradient-to-r from-green-600 to-blue-600 bg-clip-text text-transparent mb-6">
                    🎉 Verification Successful!
                  </h2>
                  <p className="text-xl text-gray-600 mb-10 max-w-2xl mx-auto">
                    ✅ Your Aadhaar details have been successfully verified and stored securely.
                  </p>
                  
                  {currentStep.data && (
                    <div className="bg-gradient-to-r from-green-50 to-blue-50 rounded-2xl p-8 mb-8 border-2 border-green-100 shadow-xl">
                      <h3 className="text-2xl font-bold text-green-800 mb-6 text-center">📋 Verification Details</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-base">
                        <div className="flex items-center bg-white/50 p-3 rounded-xl">
                          <IdentificationIcon className="w-5 h-5 mr-3 text-blue-600" />
                          <span className="font-bold text-gray-700">Aadhaar Number:</span>
                          <span className="ml-2 font-mono text-lg font-bold text-blue-600">{formatAadhaarNumber(currentStep.data.aadhaarNumber)}</span>
                        </div>
                        <div className="flex items-center bg-white/50 p-3 rounded-xl">
                          <UserIcon className="w-5 h-5 mr-3 text-purple-600" />
                          <span className="font-bold text-gray-700">Name:</span>
                          <span className="ml-2 text-lg font-bold text-purple-600">{currentStep.data.name}</span>
                        </div>
                        <div className="flex items-center bg-white/50 p-3 rounded-xl">
                          <CalendarIcon className="w-5 h-5 mr-3 text-green-600" />
                          <span className="font-bold text-gray-700">Date of Birth:</span>
                          <span className="ml-2 text-lg font-bold text-green-600">{currentStep.data.dateOfBirth}</span>
                        </div>
                        <div className="flex items-center bg-white/50 p-3 rounded-xl">
                          <UserIcon className="w-5 h-5 mr-3 text-pink-600" />
                          <span className="font-bold text-gray-700">Gender:</span>
                          <span className="ml-2 text-lg font-bold text-pink-600">{currentStep.data.gender === 'M' ? 'Male' : currentStep.data.gender === 'F' ? 'Female' : 'Other'}</span>
                        </div>
                        {currentStep.data.verificationDetails && (
                          <>
                            <div className="flex items-center bg-white/50 p-3 rounded-xl">
                              <CheckCircleIcon className="w-5 h-5 mr-3 text-green-600" />
                              <span className="font-bold text-gray-700">Status:</span>
                              <span className="ml-2 text-lg font-bold text-green-600 capitalize">{currentStep.data.status}</span>
                            </div>
                            <div className="flex items-center bg-white/50 p-3 rounded-xl">
                              <ClockIcon className="w-5 h-5 mr-3 text-orange-600" />
                              <span className="font-bold text-gray-700">Processing Time:</span>
                              <span className="ml-2 text-lg font-bold text-orange-600">{currentStep.data.processingTime}ms</span>
                            </div>
                          </>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Selfie Upload Section */}
                  {hasSelfieUploadAccess && verificationRecordId && (
                    <div className="bg-gradient-to-r from-purple-50 to-pink-50 rounded-2xl p-8 mb-8 border-2 border-purple-100 shadow-xl">
                      <h3 className="text-2xl font-bold text-purple-800 mb-4 text-center flex items-center justify-center">
                        <CameraIcon className="w-6 h-6 mr-2" />
                        Upload Selfie
                      </h3>
                      <p className="text-sm text-gray-600 mb-6 text-center">
                        Please upload a selfie photo to complete your verification record
                      </p>

                      {selfieUploaded ? (
                        <div className="text-center">
                          <div className="flex justify-center mb-4">
                            <div className="relative">
                              <div className="absolute inset-0 bg-green-400 rounded-full blur-lg opacity-60 animate-pulse"></div>
                              <div className="relative p-4 bg-white rounded-full shadow-xl border-4 border-green-100">
                                <CheckCircleIcon className="w-12 h-12 text-green-500" />
                              </div>
                            </div>
                          </div>
                          <p className="text-lg font-semibold text-green-600 mb-2">✅ Selfie uploaded successfully!</p>
                          {selfiePreview && (
                            <div className="mt-4 flex justify-center">
                              <img 
                                src={selfiePreview} 
                                alt="Uploaded selfie" 
                                className="max-w-xs max-h-64 rounded-lg shadow-lg border-4 border-purple-200"
                              />
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="space-y-4">
                          {cameraMode ? (
                            <div className="flex flex-col items-center space-y-4">
                              <div className="relative bg-black rounded-lg overflow-hidden">
                                <video
                                  ref={videoRef}
                                  autoPlay
                                  playsInline
                                  muted
                                  className="max-w-md max-h-96 w-full h-auto"
                                  style={{ transform: 'scaleX(-1)' }} // Mirror effect for selfie
                                />
                                <div className="absolute top-2 right-2">
                                  <button
                                    onClick={closeCamera}
                                    className="bg-red-500 text-white rounded-full p-2 hover:bg-red-600 transition-colors"
                                    title="Close camera"
                                  >
                                    <XCircleIcon className="w-6 h-6" />
                                  </button>
                                </div>
                              </div>
                              <div className="flex space-x-4">
                                <button
                                  onClick={closeCamera}
                                  className="px-6 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors"
                                >
                                  Cancel
                                </button>
                                <button
                                  onClick={captureFromCamera}
                                  className="px-6 py-2 bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-lg hover:from-purple-700 hover:to-pink-700 transition-colors flex items-center"
                                >
                                  <CameraIcon className="w-5 h-5 mr-2" />
                                  Capture
                                </button>
                              </div>
                            </div>
                          ) : selfiePreview ? (
                            <div className="flex flex-col items-center space-y-4">
                              <div className="relative">
                                <img 
                                  src={selfiePreview} 
                                  alt="Selfie preview" 
                                  className="max-w-xs max-h-64 rounded-lg shadow-lg border-4 border-purple-200"
                                />
                              </div>
                              <div className="flex space-x-4">
                                <button
                                  onClick={() => {
                                    setSelfieFile(null);
                                    setSelfiePreview(null);
                                  }}
                                  className="px-6 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors"
                                >
                                  Change Photo
                                </button>
                                <button
                                  onClick={handleSelfieUpload}
                                  disabled={uploadingSelfie}
                                  className="px-6 py-2 bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-lg hover:from-purple-700 hover:to-pink-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
                                >
                                  {uploadingSelfie ? (
                                    <>
                                      <ArrowPathIcon className="w-5 h-5 mr-2 animate-spin" />
                                      Uploading...
                                    </>
                                  ) : (
                                    <>
                                      <PhotoIcon className="w-5 h-5 mr-2" />
                                      Upload Selfie
                                    </>
                                  )}
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div className="flex flex-col items-center space-y-4">
                              <button
                                onClick={openCamera}
                                className="w-full border-4 border-dashed border-purple-300 rounded-xl p-8 hover:border-purple-500 transition-colors bg-white"
                              >
                                <div className="flex flex-col items-center">
                                  <CameraIcon className="w-16 h-16 text-purple-500 mb-4" />
                                  <p className="text-lg font-semibold text-gray-700 mb-2">Open Camera</p>
                                  <p className="text-sm text-gray-500">Capture selfie with camera</p>
                                </div>
                              </button>
                              <div className="flex items-center w-full">
                                <div className="flex-grow border-t border-gray-300"></div>
                                <span className="px-4 text-sm text-gray-500">OR</span>
                                <div className="flex-grow border-t border-gray-300"></div>
                              </div>
                              <label className="cursor-pointer w-full">
                                <div className="border-2 border-purple-300 rounded-xl p-6 hover:border-purple-500 transition-colors bg-white text-center">
                                  <p className="text-sm font-semibold text-gray-700 mb-1">Upload from device</p>
                                  <p className="text-xs text-gray-500">PNG, JPG, GIF up to 5MB</p>
                                </div>
                                <input
                                  type="file"
                                  accept="image/*"
                                  onChange={handleSelfieSelect}
                                  className="hidden"
                                />
                              </label>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                  
                  <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-6 justify-center">
                  <button
                    onClick={resetVerification}
                      className="group relative inline-flex items-center px-10 py-5 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-bold rounded-2xl shadow-2xl hover:shadow-3xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-600 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                      <span className="relative z-10 flex items-center">
                        <span className="mr-2">🔄</span>
                        Verify Another
                      </span>
                    </button>
                    <button
                      onClick={() => navigate('/aadhaar-verification-records')}
                      className="group relative inline-flex items-center px-10 py-5 bg-gradient-to-r from-gray-600 to-gray-700 text-white font-bold rounded-2xl shadow-2xl hover:shadow-3xl focus:outline-none focus:ring-4 focus:ring-gray-500/20 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-gray-700 to-gray-600 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                      <span className="relative z-10 flex items-center">
                        <span className="mr-2">📋</span>
                        View Records
                      </span>
                  </button>
                  </div>
                </div>
              )}

              {/* Step 3: Error */}
              {currentStep.step === 'error' && (
                <div className="text-center">
                  <div className="flex justify-center mb-8">
                    <div className="relative">
                      <div className="absolute inset-0 bg-red-400 rounded-full blur-lg opacity-60 animate-pulse"></div>
                      <div className="relative p-6 bg-white rounded-full shadow-2xl border-4 border-red-100">
                        <XCircleIcon className="w-20 h-20 text-red-500" />
                      </div>
                    </div>
                  </div>
                  <h2 className="text-5xl font-bold bg-gradient-to-r from-red-600 to-orange-600 bg-clip-text text-transparent mb-6">
                    ❌ Verification Failed
                  </h2>
                  <p className="text-xl text-gray-600 mb-10 max-w-2xl mx-auto">
                    {currentStep.data?.message || 'An error occurred during verification.'}
                  </p>
                  
                  <button
                    onClick={resetVerification}
                    className="group relative inline-flex items-center px-10 py-5 bg-gradient-to-r from-red-600 to-orange-600 text-white font-bold rounded-2xl shadow-2xl hover:shadow-3xl focus:outline-none focus:ring-4 focus:ring-red-500/20 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1"
                  >
                    <div className="absolute inset-0 bg-gradient-to-r from-orange-600 to-red-600 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                    <span className="relative z-10 flex items-center">
                      <span className="mr-2">🔄</span>
                    Try Again
                    </span>
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AadhaarVerification;

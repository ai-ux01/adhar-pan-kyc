import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import {
  IdentificationIcon,
  CheckCircleIcon,
  XCircleIcon,
  CameraIcon,
  PhotoIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';
import { validateAadhaar, filterAadhaarInput } from '../../utils/validation';
import CustomFieldsRenderer from '../../components/CustomFieldsRenderer';
import api from '../../services/api';

interface VerificationStep {
  step: 'enter-details' | 'otp-verification' | 'success' | 'error';
  data?: any;
}

const QrVerification: React.FC = () => {
  const { qrCode } = useParams<{ qrCode: string }>();
  const [currentStep, setCurrentStep] = useState<VerificationStep>({ step: 'enter-details' });
  const [isLoading, setIsLoading] = useState(false);
  const [aadhaarNumber, setAadhaarNumber] = useState('');
  const [consentAccepted, setConsentAccepted] = useState(false);
  const [otp, setOtp] = useState('');
  const [transactionId, setTransactionId] = useState('');
  const [resendCooldown, setResendCooldown] = useState(0);
  const [canResend, setCanResend] = useState(false);
  const [customFields, setCustomFields] = useState<Record<string, any>>({});
  const [availableCustomFields, setAvailableCustomFields] = useState<any[]>([]);
  const [customFieldErrors, setCustomFieldErrors] = useState<Record<string, string>>({});
  const [selfieFile, setSelfieFile] = useState<File | null>(null);
  const [selfiePreview, setSelfiePreview] = useState<string | null>(null);
  const [uploadingSelfie, setUploadingSelfie] = useState(false);
  const [selfieUploaded, setSelfieUploaded] = useState(false);
  const [verificationRecordId, setVerificationRecordId] = useState<string | null>(null);
  const [hasSelfieAccess, setHasSelfieAccess] = useState(false);
  const [cameraMode, setCameraMode] = useState(false);
  const [videoStream, setVideoStream] = useState<MediaStream | null>(null);
  const videoRef = React.useRef<HTMLVideoElement>(null);

  // Validate email format
  const isValidEmailFormat = (email: string): boolean => {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email.trim());
  };

  // Validate phone number format
  const isValidPhoneNumber = (phone: string): boolean => {
    if (!phone || typeof phone !== 'string') return false;
    const cleaned = phone.replace(/[\s-()]/g, '');
    return /^\d{10}$/.test(cleaned);
  };

  // Validate that all custom fields are filled
  const areAllRequiredCustomFieldsFilled = (): boolean => {
    if (availableCustomFields.length === 0) return true;
    return availableCustomFields.every(field => {
      const value = customFields[field.fieldName];
      if (value === undefined || value === null) return false;
      if (typeof value === 'string' && value.trim() === '') return false;
      if (Array.isArray(value) && value.length === 0) return false;
      if (field.fieldType === 'email' && typeof value === 'string') {
        return isValidEmailFormat(value);
      }
      if (field.fieldType === 'phone' && typeof value === 'string') {
        return isValidPhoneNumber(value);
      }
      return true;
    });
  };

  // Fetch user info and custom fields on mount
  useEffect(() => {
    const fetchUserInfo = async () => {
      if (!qrCode) return;

      try {
        const userResponse = await api.get(`/admin/qr/${qrCode}`);
        if (userResponse.data.success) {
          setHasSelfieAccess(userResponse.data.data.hasSelfieAccess || false);
        }

        const fieldsResponse = await api.get('/custom-fields', {
          params: {
            appliesTo: 'verification',
            isActive: 'true'
          }
        });
        
        setAvailableCustomFields(fieldsResponse.data.data || []);
      } catch (error) {
        console.error('Error fetching user info:', error);
        toast.error('Invalid QR code');
      }
    };

    fetchUserInfo();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qrCode]);

  // Countdown timer for resend OTP
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

  // Camera functions
  const openCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: 'user',
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

  const captureFromCamera = () => {
    if (!videoRef.current) return;

    const canvas = document.createElement('canvas');
    canvas.width = videoRef.current.videoWidth;
    canvas.height = videoRef.current.videoHeight;
    const ctx = canvas.getContext('2d');
    
    if (ctx) {
      ctx.drawImage(videoRef.current, 0, 0);
      
      canvas.toBlob((blob) => {
        if (blob) {
          const file = new File([blob], 'selfie.jpg', { type: 'image/jpeg' });
          setSelfieFile(file);
          setSelfiePreview(canvas.toDataURL('image/jpeg'));
          closeCamera();
        }
      }, 'image/jpeg', 0.9);
    }
  };

  const handleSelfieSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      toast.error('Please select an image file');
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      toast.error('Image size must be less than 5MB');
      return;
    }

    setSelfieFile(file);
    
    const reader = new FileReader();
    reader.onloadend = () => {
      setSelfiePreview(reader.result as string);
    };
    reader.readAsDataURL(file);
  };

  const handleSelfieUpload = async () => {
    if (!selfieFile || !verificationRecordId || !qrCode) {
      toast.error('Please select a selfie image');
      return;
    }

    setUploadingSelfie(true);
    try {
      const formData = new FormData();
      formData.append('selfie', selfieFile);

      // Use api instance for better error handling and retry logic
      const response = await api.post(
        `/aadhaar-verification/records/${verificationRecordId}/selfie-public`,
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      );

      const data = response.data;

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

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!qrCode) {
      toast.error('Invalid QR code');
      return;
    }

    const aadhaarValidation = validateAadhaar(aadhaarNumber);
    if (!aadhaarValidation.isValid) {
      toast.error(aadhaarValidation.message || 'Please enter a valid Aadhaar number');
      return;
    }

    if (!consentAccepted) {
      toast.error('Please accept the consent to proceed');
      return;
    }

    if (!areAllRequiredCustomFieldsFilled()) {
      toast.error('Please fill all custom fields correctly');
      return;
    }

    setIsLoading(true);
    try {
      // Use api instance for better error handling and retry logic
      const response = await api.post(
        `/aadhaar-verification/verify-qr/${qrCode}`,
        {
          aadhaarNumber: aadhaarNumber.replace(/\s+/g, '').replace(/-/g, ''),
          location: '',
          dynamicFields: [],
          customFields: customFields,
          consentAccepted: consentAccepted
        }
      );

      const data = response.data;

      if (data.success) {
        if (data.data.otpSent) {
          setTransactionId(data.data.transactionId);
          setCurrentStep({ step: 'otp-verification', data: data.data });
          setResendCooldown(30);
          setCanResend(false);
          setHasSelfieAccess(data.data.hasSelfieAccess || false);
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

  const handleVerifyOtp = async () => {
    if (!qrCode) {
      toast.error('Invalid QR code');
      return;
    }

    if (!otp || otp.length !== 6) {
      toast.error('Please enter a valid 6-digit OTP');
      return;
    }

    setIsLoading(true);
    try {
      // Use api instance for better error handling and retry logic
      const response = await api.post(
        `/aadhaar-verification/verify-otp-qr/${qrCode}`,
        {
          aadhaarNumber: aadhaarNumber.replace(/\s/g, ''),
          otp: otp,
          transactionId: transactionId,
          dynamicFields: [],
          customFields: customFields
        }
      );

      const data = response.data;

      if (data.success) {
        // Check if verification was actually successful (status should be 'verified')
        if (data.data && data.data.status === 'rejected') {
          // Verification failed even though API call succeeded
          setCurrentStep({ step: 'error', data: { message: 'Aadhaar verification failed. Please check your details and try again.' } });
          toast.error('Aadhaar verification failed');
        } else {
          setCurrentStep({ step: 'success', data: data.data });
          setVerificationRecordId(data.data.recordId || null);
          setHasSelfieAccess(data.data.hasSelfieAccess || false);
          toast.success('Aadhaar verification completed successfully!');
        }
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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
            🔐 Secure OTP-based verification
          </p>
        </div>

        <div className="bg-white rounded-3xl shadow-2xl p-8 md:p-10 lg:p-12 border border-gray-100">
          {/* Step 1: Enter Details */}
          {currentStep.step === 'enter-details' && (
            <form onSubmit={handleVerify} className="space-y-6">
              <div>
                <label htmlFor="aadhaar" className="block text-sm font-medium text-gray-700 mb-2">
                  Aadhaar Number
                </label>
                <input
                  type="text"
                  id="aadhaar"
                  value={aadhaarNumber}
                  onChange={(e) => setAadhaarNumber(filterAadhaarInput(e.target.value))}
                  placeholder="XXXX XXXX XXXX"
                  maxLength={14}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  required
                />
              </div>

              {/* Custom Fields */}
              {availableCustomFields.length > 0 && (
                <div className="border-t border-gray-200 pt-6">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Additional Information</h3>
                  <CustomFieldsRenderer
                    appliesTo="verification"
                    values={customFields}
                    onChange={(fieldName, value) => {
                      setCustomFields({ ...customFields, [fieldName]: value });
                      const field = availableCustomFields.find(f => f.fieldName === fieldName);
                      if (field?.fieldType === 'email') {
                        if (value && !isValidEmailFormat(value)) {
                          setCustomFieldErrors({ ...customFieldErrors, [fieldName]: 'Invalid email format' });
                        } else {
                          const { [fieldName]: _, ...rest } = customFieldErrors;
                          setCustomFieldErrors(rest);
                        }
                      } else if (field?.fieldType === 'phone') {
                        if (value && !isValidPhoneNumber(value)) {
                          setCustomFieldErrors({ ...customFieldErrors, [fieldName]: 'Invalid phone number (must be 10 digits)' });
                        } else {
                          const { [fieldName]: _, ...rest } = customFieldErrors;
                          setCustomFieldErrors(rest);
                        }
                      }
                    }}
                    errors={customFieldErrors}
                  />
                </div>
              )}

              {/* Consent Checkbox */}
              <div className="flex items-start bg-gradient-to-r from-blue-50 to-purple-50 p-4 rounded-xl border-2 border-blue-100">
                <div className="flex items-center h-5 mt-1">
                  <input
                    id="consent"
                    type="checkbox"
                    checked={consentAccepted}
                    onChange={(e) => setConsentAccepted(e.target.checked)}
                    className="w-4 h-4 text-blue-600 bg-white border-2 border-gray-300 rounded-lg focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300"
                    required
                  />
                </div>
                <div className="ml-3 flex-1">
                  <label htmlFor="consent" className="font-bold text-gray-700 cursor-pointer block mb-2">
                    ✅ Aadhaar Consent Declaration *
                  </label>
                  <div className="text-gray-600 text-xs space-y-1.5 leading-relaxed">
                    <p className="font-semibold">
                      I hereby voluntarily provide my Aadhaar details to AVI HR SOFTWARE PVT LTD for the purpose of employee verification, statutory compliance, and internal record maintenance.
                    </p>
                    <p className="font-semibold mt-2">I confirm and acknowledge that:</p>
                    <ul className="list-disc list-inside space-y-1 ml-2">
                      <li>My Aadhaar information will be used only for official and lawful purposes, including identity verification and compliance with applicable laws.</li>
                      <li>The company shall ensure the confidentiality and security of my Aadhaar details, in accordance with the Aadhaar Act, 2016 and relevant data protection regulations.</li>
                      <li>I am submitting this information willingly and without any coercion or undue pressure.</li>
                      <li>I authorize AVI HR SOFTWARE PVT LTD to use, store, and process the provided Aadhaar details solely for the purposes stated above.</li>
                      <li>The information I have provided is true and correct to the best of my knowledge.</li>
                      <li>I have read and understood the above declaration and provide my consent.</li>
                    </ul>
                  </div>
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading || !areAllRequiredCustomFieldsFilled() || Object.keys(customFieldErrors).length > 0}
                className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white font-bold py-3 px-6 rounded-lg hover:from-blue-700 hover:to-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Sending OTP...' : 'Send OTP'}
              </button>
            </form>
          )}

          {/* Step 2: OTP Verification */}
          {currentStep.step === 'otp-verification' && (
            <div className="text-center space-y-6">
              <h2 className="text-2xl font-bold text-gray-900">Enter OTP</h2>
              <p className="text-gray-600">Please enter the 6-digit OTP sent to your registered mobile number</p>
              
              <input
                type="text"
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="XXXXXX"
                maxLength={6}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-center text-2xl font-mono tracking-widest"
              />

              <div className="flex space-x-4">
                <button
                  onClick={handleVerifyOtp}
                  disabled={isLoading || otp.length !== 6}
                  className="flex-1 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-bold py-3 px-6 rounded-lg hover:from-blue-700 hover:to-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? 'Verifying...' : 'Verify OTP'}
                </button>
                
                {canResend && (
                  <button
                    onClick={() => {
                      setCurrentStep({ step: 'enter-details' });
                      setOtp('');
                      setResendCooldown(0);
                    }}
                    className="px-4 py-3 border border-gray-300 rounded-lg hover:bg-gray-50"
                  >
                    Resend OTP
                  </button>
                )}
                
                {resendCooldown > 0 && (
                  <div className="px-4 py-3 text-gray-600">
                    Resend in {resendCooldown}s
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Step 3: Success */}
          {currentStep.step === 'success' && (
            <div className="text-center space-y-6">
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
                ✅ Your Aadhaar details have been successfully verified.
              </p>

              {/* Selfie Upload Section */}
              {hasSelfieAccess && verificationRecordId && !selfieUploaded && (
                <div className="bg-gradient-to-r from-purple-50 to-pink-50 rounded-2xl p-8 mb-8 border-2 border-purple-100 shadow-xl">
                  <h3 className="text-2xl font-bold text-purple-800 mb-4 text-center flex items-center justify-center">
                    <CameraIcon className="w-6 h-6 mr-2" />
                    Upload Selfie
                  </h3>

                  {cameraMode ? (
                    <div className="flex flex-col items-center space-y-4">
                      <div className="relative bg-black rounded-lg overflow-hidden">
                        <video
                          ref={videoRef}
                          autoPlay
                          playsInline
                          muted
                          className="max-w-md max-h-96 w-full h-auto"
                          style={{ transform: 'scaleX(-1)' }}
                        />
                        <div className="absolute top-2 right-2">
                          <button
                            onClick={closeCamera}
                            className="bg-red-500 text-white rounded-full p-2 hover:bg-red-600 transition-colors"
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
                      <img 
                        src={selfiePreview} 
                        alt="Selfie preview" 
                        className="max-w-xs max-h-64 rounded-lg shadow-lg border-4 border-purple-200"
                      />
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

              {/* Thank You Message */}
              {(!hasSelfieAccess || selfieUploaded || !verificationRecordId) && (
                <div className="bg-gradient-to-r from-green-50 to-blue-50 rounded-2xl p-8 mb-8 border-2 border-green-100 shadow-xl">
                  <h3 className="text-2xl font-bold text-green-800 mb-4 text-center">
                    Thank You!
                  </h3>
                  <p className="text-lg text-gray-700 text-center">
                    Your verification has been completed successfully. We appreciate your time!
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Step 4: Error */}
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
                {currentStep.data?.message || 'An unexpected error occurred during verification. Please try again.'}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default QrVerification;


import React, { useState, useEffect } from 'react';
import api from '../services/api';

interface CustomField {
  _id: string;
  fieldName: string;
  fieldLabel: string;
  fieldType: string;
  placeholder?: string;
  helpText?: string;
  required: boolean;
  options?: string[];
  validation?: {
    minLength?: number;
    maxLength?: number;
    min?: number;
    max?: number;
    pattern?: string;
    patternMessage?: string;
  };
  defaultValue?: string;
  isActive: boolean;
  appliesTo: string;
  category: string;
}

interface CustomFieldsRendererProps {
  appliesTo: 'user' | 'verification';
  values: Record<string, any>;
  onChange: (fieldName: string, value: any) => void;
  errors?: Record<string, string>;
  readonly?: boolean;
  enabledCustomFieldIds?: string[]; // Array of custom field IDs that are enabled for this user
}

const CustomFieldsRenderer: React.FC<CustomFieldsRendererProps> = ({
  appliesTo,
  values,
  onChange,
  errors = {},
  readonly = false,
  enabledCustomFieldIds
}) => {
  const [customFields, setCustomFields] = useState<CustomField[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCustomFields();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appliesTo, enabledCustomFieldIds]);

  const fetchCustomFields = async () => {
    try {
      setLoading(true);
      console.log('🔍 Fetching custom fields for:', appliesTo);
      console.log('🔑 Enabled custom field IDs:', enabledCustomFieldIds);
      const response = await api.get('/custom-fields', {
        params: {
          appliesTo,
          isActive: 'true'
        }
      });
      console.log('✅ Custom fields received:', response.data.data?.length || 0, 'fields');
      console.log('📋 Fields:', response.data.data);
      
      let fieldsToShow = response.data.data || [];
      
      // Filter by enabled custom field IDs if provided
      if (enabledCustomFieldIds !== undefined) {
        // If enabledCustomFieldIds is provided (even if empty array), filter by it
        if (enabledCustomFieldIds.length === 0) {
          // Empty array means no fields should be shown
          fieldsToShow = [];
        } else {
          // Filter to only show enabled fields
          fieldsToShow = fieldsToShow.filter((field: CustomField) => 
            enabledCustomFieldIds.includes(field._id)
          );
          console.log('🎯 Filtered to enabled fields:', fieldsToShow.length, 'fields');
        }
      }
      // If enabledCustomFieldIds is undefined, show all fields (for backwards compatibility)
      
      setCustomFields(fieldsToShow);
    } catch (error) {
      console.error('❌ Error fetching custom fields:', error);
    } finally {
      setLoading(false);
    }
  };

  const renderField = (field: CustomField) => {
    const fieldValue = values[field.fieldName] || field.defaultValue || '';
    const hasError = errors[field.fieldName];

    const commonProps = {
      id: field.fieldName,
      name: field.fieldName,
      disabled: readonly,
      required: field.required,
      className: `w-full px-4 py-2 border ${
        hasError ? 'border-red-500' : 'border-gray-300'
      } rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent ${
        readonly ? 'bg-gray-100 cursor-not-allowed' : ''
      }`,
      placeholder: field.placeholder || '',
    };

    switch (field.fieldType) {
      case 'text':
      case 'email':
      case 'url':
      case 'phone':
        return (
          <input
            {...commonProps}
            type={field.fieldType === 'email' ? 'email' : field.fieldType === 'url' ? 'url' : 'text'}
            value={fieldValue}
            onChange={(e) => onChange(field.fieldName, e.target.value)}
            minLength={field.validation?.minLength}
            maxLength={field.validation?.maxLength}
            pattern={field.validation?.pattern}
          />
        );

      case 'number':
        return (
          <input
            {...commonProps}
            type="number"
            value={fieldValue}
            onChange={(e) => onChange(field.fieldName, e.target.value)}
            min={field.validation?.min}
            max={field.validation?.max}
          />
        );

      case 'date':
        return (
          <input
            {...commonProps}
            type="date"
            value={fieldValue}
            onChange={(e) => onChange(field.fieldName, e.target.value)}
          />
        );

      case 'textarea':
        return (
          <textarea
            {...commonProps}
            value={fieldValue}
            onChange={(e) => onChange(field.fieldName, e.target.value)}
            rows={4}
            minLength={field.validation?.minLength}
            maxLength={field.validation?.maxLength}
          />
        );

      case 'select':
        return (
          <select
            {...commonProps}
            value={fieldValue}
            onChange={(e) => onChange(field.fieldName, e.target.value)}
          >
            <option value="">Select an option</option>
            {field.options?.map((option, index) => (
              <option key={index} value={option}>
                {option}
              </option>
            ))}
          </select>
        );

      case 'multiselect':
        return (
          <div className="space-y-2">
            {field.options?.map((option, index) => (
              <label key={index} className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  value={option}
                  checked={Array.isArray(fieldValue) ? fieldValue.includes(option) : false}
                  onChange={(e) => {
                    const currentValues = Array.isArray(fieldValue) ? fieldValue : [];
                    const newValues = e.target.checked
                      ? [...currentValues, option]
                      : currentValues.filter((v: string) => v !== option);
                    onChange(field.fieldName, newValues);
                  }}
                  disabled={readonly}
                  className="w-4 h-4 text-purple-600 border-gray-300 rounded focus:ring-purple-500"
                />
                <span className="text-sm text-gray-700">{option}</span>
              </label>
            ))}
          </div>
        );

      case 'radio':
        return (
          <div className="space-y-2">
            {field.options?.map((option, index) => (
              <label key={index} className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="radio"
                  name={field.fieldName}
                  value={option}
                  checked={fieldValue === option}
                  onChange={(e) => onChange(field.fieldName, e.target.value)}
                  disabled={readonly}
                  className="w-4 h-4 text-purple-600 border-gray-300 focus:ring-purple-500"
                />
                <span className="text-sm text-gray-700">{option}</span>
              </label>
            ))}
          </div>
        );

      case 'checkbox':
        return (
          <label className="flex items-center space-x-2 cursor-pointer">
            <input
              type="checkbox"
              checked={fieldValue === true || fieldValue === 'true'}
              onChange={(e) => onChange(field.fieldName, e.target.checked)}
              disabled={readonly}
              className="w-5 h-5 text-purple-600 border-gray-300 rounded focus:ring-purple-500"
            />
            <span className="text-sm text-gray-700">{field.fieldLabel}</span>
          </label>
        );

      case 'file':
        return (
          <input
            {...commonProps}
            type="file"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) {
                onChange(field.fieldName, file);
              }
            }}
          />
        );

      default:
        return (
          <input
            {...commonProps}
            type="text"
            value={fieldValue}
            onChange={(e) => onChange(field.fieldName, e.target.value)}
          />
        );
    }
  };

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mx-auto"></div>
        <p className="text-gray-600 mt-2 text-sm">Loading custom fields...</p>
      </div>
    );
  }

  if (customFields.length === 0) {
    return (
      <div className="text-center py-6 bg-gray-50 rounded-lg border-2 border-dashed border-gray-300">
        <p className="text-gray-600 text-sm">
          📝 No custom fields configured for this section yet.
        </p>
        <p className="text-gray-500 text-xs mt-1">
          {appliesTo === 'verification' 
            ? 'Admins can add custom fields in Admin Panel → Custom Fields (set "Applies To" = Verification Records or Both)'
            : 'Admins can add custom fields in Admin Panel → Custom Fields (set "Applies To" = User Profile or Both)'}
        </p>
      </div>
    );
  }

  // Group fields by category
  const fieldsByCategory = customFields.reduce((acc, field) => {
    const category = field.category || 'other';
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(field);
    return acc;
  }, {} as Record<string, CustomField[]>);

  const categoryLabels: Record<string, string> = {
    personal: 'Personal Information',
    business: 'Business Information',
    address: 'Address Information',
    contact: 'Contact Information',
    other: 'Additional Information'
  };

  return (
    <div className="space-y-6">
      {Object.entries(fieldsByCategory).map(([category, fields]) => (
        <div key={category} className="space-y-4">
          <h3 className="text-lg font-semibold text-gray-900 border-b border-gray-200 pb-2">
            {categoryLabels[category] || category}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {fields.map((field) => (
              <div
                key={field._id}
                className={field.fieldType === 'textarea' || field.fieldType === 'multiselect' ? 'md:col-span-2' : ''}
              >
                {field.fieldType !== 'checkbox' && (
                  <label htmlFor={field.fieldName} className="block text-sm font-medium text-gray-700 mb-2">
                    {field.fieldLabel}
                    {field.required && <span className="text-red-500 ml-1">*</span>}
                  </label>
                )}
                {renderField(field)}
                {field.helpText && (
                  <p className="text-xs text-gray-500 mt-1">{field.helpText}</p>
                )}
                {errors[field.fieldName] && (
                  <p className="text-sm text-red-600 mt-1">{errors[field.fieldName]}</p>
                )}
                {field.validation?.patternMessage && (
                  <p className="text-xs text-gray-500 mt-1">{field.validation.patternMessage}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

export default CustomFieldsRenderer;


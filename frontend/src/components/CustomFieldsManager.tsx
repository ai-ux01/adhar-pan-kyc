import React, { useState, useEffect } from 'react';
import api from '../services/api';
import { useToast } from '../contexts/ToastContext';
import {
  PlusIcon,
  PencilIcon,
  TrashIcon,
  XMarkIcon,
  ArrowUpIcon,
  ArrowDownIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';

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
  displayOrder: number;
  isActive: boolean;
  appliesTo: string;
  category: string;
  showInList: boolean;
  searchable: boolean;
  createdBy?: {
    name: string;
    email: string;
  };
  createdAt: string;
  updatedAt: string;
}

interface FormData {
  fieldName: string;
  fieldLabel: string;
  fieldType: string;
  placeholder: string;
  helpText: string;
  required: boolean;
  options: string[];
  validation: {
    minLength?: number;
    maxLength?: number;
    min?: number;
    max?: number;
    pattern?: string;
    patternMessage?: string;
  };
  defaultValue: string;
  displayOrder: number;
  isActive: boolean;
  appliesTo: string;
  category: string;
  showInList: boolean;
  searchable: boolean;
}

const fieldTypes = [
  { value: 'text', label: 'Text' },
  { value: 'email', label: 'Email' },
  { value: 'number', label: 'Number' },
  { value: 'phone', label: 'Phone' },
  { value: 'date', label: 'Date' },
  { value: 'select', label: 'Select (Dropdown)' },
  { value: 'multiselect', label: 'Multi-Select' },
  { value: 'textarea', label: 'Text Area' },
  { value: 'checkbox', label: 'Checkbox' },
  { value: 'radio', label: 'Radio Buttons' },
  { value: 'url', label: 'URL' },
  { value: 'file', label: 'File Upload' }
];

const categories = [
  { value: 'personal', label: 'Personal' },
  { value: 'business', label: 'Business' },
  { value: 'address', label: 'Address' },
  { value: 'contact', label: 'Contact' },
  { value: 'other', label: 'Other' }
];

const appliesTo = [
  { value: 'user', label: 'User Profile' },
  { value: 'verification', label: 'Verification Records' },
  { value: 'both', label: 'Both' }
];

const CustomFieldsManager: React.FC = () => {
  const { showToast } = useToast();
  const [customFields, setCustomFields] = useState<CustomField[]>([]);
  const [loading, setLoading] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [editingField, setEditingField] = useState<CustomField | null>(null);
  const [optionInput, setOptionInput] = useState('');
  const [formData, setFormData] = useState<FormData>({
    fieldName: '',
    fieldLabel: '',
    fieldType: 'text',
    placeholder: '',
    helpText: '',
    required: false,
    options: [],
    validation: {},
    defaultValue: '',
    displayOrder: 0,
    isActive: true,
    appliesTo: 'user',
    category: 'other',
    showInList: false,
    searchable: false
  });

  useEffect(() => {
    fetchCustomFields();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchCustomFields = async () => {
    try {
      setLoading(true);
      const response = await api.get('/custom-fields');
      setCustomFields(response.data.data || []);
    } catch (error: any) {
      console.error('Error fetching custom fields:', error);
      showToast({
        type: 'error',
        message: 'Failed to fetch custom fields',
        duration: 5000
      });
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target;
    const checked = (e.target as HTMLInputElement).checked;
    
    if (name.startsWith('validation.')) {
      const validationKey = name.split('.')[1];
      setFormData(prev => ({
        ...prev,
        validation: {
          ...prev.validation,
          [validationKey]: type === 'checkbox' ? checked : value
        }
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        [name]: type === 'checkbox' ? checked : value
      }));
    }
  };

  const handleAddOption = () => {
    if (optionInput.trim()) {
      setFormData(prev => ({
        ...prev,
        options: [...prev.options, optionInput.trim()]
      }));
      setOptionInput('');
    }
  };

  const handleRemoveOption = (index: number) => {
    setFormData(prev => ({
      ...prev,
      options: prev.options.filter((_, i) => i !== index)
    }));
  };

  const handleOpenModal = (field?: CustomField) => {
    if (field) {
      setEditingField(field);
      setFormData({
        fieldName: field.fieldName,
        fieldLabel: field.fieldLabel,
        fieldType: field.fieldType,
        placeholder: field.placeholder || '',
        helpText: field.helpText || '',
        required: field.required,
        options: field.options || [],
        validation: field.validation || {},
        defaultValue: field.defaultValue || '',
        displayOrder: field.displayOrder,
        isActive: field.isActive,
        appliesTo: field.appliesTo,
        category: field.category,
        showInList: field.showInList,
        searchable: field.searchable
      });
    } else {
      setEditingField(null);
      setFormData({
        fieldName: '',
        fieldLabel: '',
        fieldType: 'text',
        placeholder: '',
        helpText: '',
        required: false,
        options: [],
        validation: {},
        defaultValue: '',
        displayOrder: customFields.length,
        isActive: true,
        appliesTo: 'user',
        category: 'other',
        showInList: false,
        searchable: false
      });
    }
    setShowModal(true);
  };

  const handleCloseModal = () => {
    setShowModal(false);
    setEditingField(null);
    setOptionInput('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      setLoading(true);
      
      // Validate options for select/multiselect/radio fields
      if (['select', 'multiselect', 'radio'].includes(formData.fieldType) && formData.options.length === 0) {
        showToast({
          type: 'error',
          message: 'Please add at least one option for this field type',
          duration: 5000
        });
        return;
      }
      
      if (editingField) {
        await api.put(`/custom-fields/${editingField._id}`, formData);
        showToast({
          type: 'success',
          message: 'Custom field updated successfully!',
          duration: 4000
        });
      } else {
        await api.post('/custom-fields', formData);
        showToast({
          type: 'success',
          message: 'Custom field created successfully!',
          duration: 4000
        });
      }
      
      handleCloseModal();
      fetchCustomFields();
    } catch (error: any) {
      console.error('Error saving custom field:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to save custom field',
        duration: 5000
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (fieldId: string) => {
    if (!window.confirm('Are you sure you want to delete this custom field? This action cannot be undone.')) {
      return;
    }
    
    try {
      setLoading(true);
      await api.delete(`/custom-fields/${fieldId}`);
      showToast({
        type: 'success',
        message: 'Custom field deleted successfully!',
        duration: 4000
      });
      fetchCustomFields();
    } catch (error: any) {
      console.error('Error deleting custom field:', error);
      showToast({
        type: 'error',
        message: error.response?.data?.message || 'Failed to delete custom field',
        duration: 5000
      });
    } finally {
      setLoading(false);
    }
  };

  const handleMoveField = async (fieldId: string, direction: 'up' | 'down') => {
    const currentIndex = customFields.findIndex(f => f._id === fieldId);
    if (currentIndex === -1) return;
    
    const newIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
    if (newIndex < 0 || newIndex >= customFields.length) return;
    
    const reorderedFields = [...customFields];
    [reorderedFields[currentIndex], reorderedFields[newIndex]] = 
      [reorderedFields[newIndex], reorderedFields[currentIndex]];
    
    const fieldOrders = reorderedFields.map((field, index) => ({
      id: field._id,
      displayOrder: index
    }));
    
    try {
      await api.post('/custom-fields/reorder', { fieldOrders });
      setCustomFields(reorderedFields);
      showToast({
        type: 'success',
        message: 'Field order updated successfully!',
        duration: 3000
      });
    } catch (error: any) {
      console.error('Error reordering fields:', error);
      showToast({
        type: 'error',
        message: 'Failed to reorder fields',
        duration: 5000
      });
    }
  };

  const needsOptions = ['select', 'multiselect', 'radio'].includes(formData.fieldType);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Custom Fields</h2>
          <p className="text-gray-600 mt-1">Manage additional fields for users and verification records</p>
        </div>
        <button
          onClick={() => handleOpenModal()}
          className="flex items-center px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-lg hover:from-purple-700 hover:to-indigo-700 transition-all duration-200 shadow-md hover:shadow-lg"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Add Custom Field
        </button>
      </div>

      {/* Custom Fields List */}
      {loading && customFields.length === 0 ? (
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600 mx-auto"></div>
          <p className="text-gray-600 mt-4">Loading custom fields...</p>
        </div>
      ) : customFields.length === 0 ? (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
          <p className="text-gray-500 text-lg">No custom fields defined yet.</p>
          <p className="text-gray-400 mt-2">Click "Add Custom Field" to create your first custom field.</p>
        </div>
      ) : (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Field
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Category
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Applies To
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {customFields.map((field, index) => (
                <tr key={field._id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4">
                    <div>
                      <div className="text-sm font-medium text-gray-900">{field.fieldLabel}</div>
                      <div className="text-sm text-gray-500">{field.fieldName}</div>
                      {field.required && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 mt-1">
                          Required
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-sm text-gray-900 capitalize">{field.fieldType}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-sm text-gray-900 capitalize">{field.category}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-sm text-gray-900 capitalize">{field.appliesTo}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {field.isActive ? (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                        <CheckCircleIcon className="w-4 h-4 mr-1" />
                        Active
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                        <XCircleIcon className="w-4 h-4 mr-1" />
                        Inactive
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <div className="flex items-center justify-end space-x-2">
                      <button
                        onClick={() => handleMoveField(field._id, 'up')}
                        disabled={index === 0}
                        className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-30 disabled:cursor-not-allowed"
                        title="Move up"
                      >
                        <ArrowUpIcon className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => handleMoveField(field._id, 'down')}
                        disabled={index === customFields.length - 1}
                        className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-30 disabled:cursor-not-allowed"
                        title="Move down"
                      >
                        <ArrowDownIcon className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => handleOpenModal(field)}
                        className="p-1 text-indigo-600 hover:text-indigo-900"
                        title="Edit"
                      >
                        <PencilIcon className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => handleDelete(field._id)}
                        className="p-1 text-red-600 hover:text-red-900"
                        title="Delete"
                      >
                        <TrashIcon className="w-5 h-5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200 flex justify-between items-center sticky top-0 bg-white z-10">
              <h3 className="text-xl font-bold text-gray-900">
                {editingField ? 'Edit Custom Field' : 'Add Custom Field'}
              </h3>
              <button
                onClick={handleCloseModal}
                className="text-gray-400 hover:text-gray-600"
              >
                <XMarkIcon className="w-6 h-6" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Field Label */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Field Label <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="fieldLabel"
                    value={formData.fieldLabel}
                    onChange={handleInputChange}
                    required
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    placeholder="e.g., Company GST Number"
                  />
                </div>

                {/* Field Name */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Field Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="fieldName"
                    value={formData.fieldName}
                    onChange={handleInputChange}
                    required
                    disabled={!!editingField}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent disabled:bg-gray-100 disabled:cursor-not-allowed"
                    placeholder="e.g., company_gst_number"
                  />
                  <p className="text-xs text-gray-500 mt-1">Unique identifier (will be auto-formatted)</p>
                </div>

                {/* Field Type */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Field Type <span className="text-red-500">*</span>
                  </label>
                  <select
                    name="fieldType"
                    value={formData.fieldType}
                    onChange={handleInputChange}
                    required
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  >
                    {fieldTypes.map(type => (
                      <option key={type.value} value={type.value}>{type.label}</option>
                    ))}
                  </select>
                </div>

                {/* Category */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Category
                  </label>
                  <select
                    name="category"
                    value={formData.category}
                    onChange={handleInputChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  >
                    {categories.map(cat => (
                      <option key={cat.value} value={cat.value}>{cat.label}</option>
                    ))}
                  </select>
                </div>

                {/* Applies To */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Applies To
                  </label>
                  <select
                    name="appliesTo"
                    value={formData.appliesTo}
                    onChange={handleInputChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  >
                    {appliesTo.map(opt => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                </div>

                {/* Display Order */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Display Order
                  </label>
                  <input
                    type="number"
                    name="displayOrder"
                    value={formData.displayOrder}
                    onChange={handleInputChange}
                    min="0"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Placeholder */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Placeholder Text
                </label>
                <input
                  type="text"
                  name="placeholder"
                  value={formData.placeholder}
                  onChange={handleInputChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  placeholder="Enter placeholder text"
                />
              </div>

              {/* Help Text */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Help Text
                </label>
                <textarea
                  name="helpText"
                  value={formData.helpText}
                  onChange={handleInputChange}
                  rows={2}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  placeholder="Additional information about this field"
                />
              </div>

              {/* Options (for select, multiselect, radio) */}
              {needsOptions && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Options <span className="text-red-500">*</span>
                  </label>
                  <div className="flex space-x-2 mb-2">
                    <input
                      type="text"
                      value={optionInput}
                      onChange={(e) => setOptionInput(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddOption())}
                      className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      placeholder="Enter an option"
                    />
                    <button
                      type="button"
                      onClick={handleAddOption}
                      className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
                    >
                      <PlusIcon className="w-5 h-5" />
                    </button>
                  </div>
                  <div className="space-y-2">
                    {formData.options.map((option, index) => (
                      <div key={index} className="flex items-center justify-between bg-gray-50 px-3 py-2 rounded-lg">
                        <span className="text-sm text-gray-700">{option}</span>
                        <button
                          type="button"
                          onClick={() => handleRemoveOption(index)}
                          className="text-red-600 hover:text-red-800"
                        >
                          <XMarkIcon className="w-5 h-5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Validation Rules */}
              {(formData.fieldType === 'text' || formData.fieldType === 'textarea') && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Min Length
                    </label>
                    <input
                      type="number"
                      name="validation.minLength"
                      value={formData.validation.minLength || ''}
                      onChange={handleInputChange}
                      min="0"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Max Length
                    </label>
                    <input
                      type="number"
                      name="validation.maxLength"
                      value={formData.validation.maxLength || ''}
                      onChange={handleInputChange}
                      min="0"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                  </div>
                </div>
              )}

              {formData.fieldType === 'number' && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Min Value
                    </label>
                    <input
                      type="number"
                      name="validation.min"
                      value={formData.validation.min || ''}
                      onChange={handleInputChange}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Max Value
                    </label>
                    <input
                      type="number"
                      name="validation.max"
                      value={formData.validation.max || ''}
                      onChange={handleInputChange}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                  </div>
                </div>
              )}

              {/* Checkboxes */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    name="required"
                    checked={formData.required}
                    onChange={handleInputChange}
                    className="w-5 h-5 text-purple-600 border-gray-300 rounded focus:ring-purple-500"
                  />
                  <span className="text-sm text-gray-700">Required</span>
                </label>
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    name="isActive"
                    checked={formData.isActive}
                    onChange={handleInputChange}
                    className="w-5 h-5 text-purple-600 border-gray-300 rounded focus:ring-purple-500"
                  />
                  <span className="text-sm text-gray-700">Active</span>
                </label>
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    name="showInList"
                    checked={formData.showInList}
                    onChange={handleInputChange}
                    className="w-5 h-5 text-purple-600 border-gray-300 rounded focus:ring-purple-500"
                  />
                  <span className="text-sm text-gray-700">Show in List</span>
                </label>
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    name="searchable"
                    checked={formData.searchable}
                    onChange={handleInputChange}
                    className="w-5 h-5 text-purple-600 border-gray-300 rounded focus:ring-purple-500"
                  />
                  <span className="text-sm text-gray-700">Searchable</span>
                </label>
              </div>

              {/* Actions */}
              <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200">
                <button
                  type="button"
                  onClick={handleCloseModal}
                  className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-6 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-lg hover:from-purple-700 hover:to-indigo-700 transition-all duration-200 shadow-md hover:shadow-lg disabled:opacity-50"
                >
                  {loading ? 'Saving...' : editingField ? 'Update Field' : 'Create Field'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default CustomFieldsManager;


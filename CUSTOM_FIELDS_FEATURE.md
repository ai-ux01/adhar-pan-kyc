# Custom Fields Management System

## Overview

A comprehensive custom field management system has been implemented that allows administrators to dynamically add and manage additional fields for users and verification records. This feature provides flexibility to collect custom information without modifying the core application code.

## Features Implemented

### 1. Backend Components

#### Database Model (`backend/src/models/CustomField.js`)
- **Field Types Supported:**
  - Text, Email, Number, Phone, Date
  - Select (Dropdown), Multi-Select, Radio Buttons
  - Textarea, Checkbox, URL, File Upload

- **Field Properties:**
  - Field name (unique identifier)
  - Field label (display name)
  - Placeholder text and help text
  - Required/optional flag
  - Options (for select/multiselect/radio)
  - Validation rules (min/max length, patterns, etc.)
  - Default values
  - Display order
  - Active/inactive status
  - Category (Personal, Business, Address, Contact, Other)
  - Applies to (User Profile, Verification Records, or Both)
  - Searchable and show in list flags

#### API Routes (`backend/src/routes/customFields.js`)
- `GET /api/custom-fields` - Get all custom fields (with filtering)
- `GET /api/custom-fields/:id` - Get single custom field
- `POST /api/custom-fields` - Create new custom field (Admin only)
- `PUT /api/custom-fields/:id` - Update custom field (Admin only)
- `DELETE /api/custom-fields/:id` - Delete custom field (Admin only)
- `POST /api/custom-fields/reorder` - Reorder custom fields (Admin only)

#### User Model Update (`backend/src/models/User.js`)
- Added `customFields` field to store custom field values
- Uses MongoDB Map type for flexible key-value storage

### 2. Frontend Components

#### Custom Fields Manager (`frontend/src/components/CustomFieldsManager.tsx`)
- **Admin Interface for:**
  - Creating new custom fields
  - Editing existing custom fields
  - Deleting custom fields
  - Reordering fields (move up/down)
  - Activating/deactivating fields
  - Managing field options for select/multiselect/radio types
  - Setting validation rules
  
- **Features:**
  - Modal-based form for creating/editing fields
  - Real-time field preview
  - Drag-and-drop reordering
  - Field status indicators
  - Category-based organization

#### Custom Fields Renderer (`frontend/src/components/CustomFieldsRenderer.tsx`)
- **Dynamic Field Rendering:**
  - Automatically fetches and displays active custom fields
  - Renders appropriate input type based on field type
  - Applies validation rules
  - Groups fields by category
  - Shows help text and error messages
  - Supports readonly mode

#### Admin Panel Integration (`frontend/src/pages/Admin/Admin.tsx`)
- Added "Custom Fields" tab to admin panel
- Integrated CustomFieldsManager component
- Accessible only to administrators

#### Profile Page Integration (`frontend/src/pages/Profile/Profile.tsx`)
- Added custom fields section to user profile
- Fields are editable by users
- Values are saved with profile updates

## Usage Guide

### For Administrators

#### Creating a Custom Field

1. Navigate to Admin Panel → Custom Fields tab
2. Click "Add Custom Field" button
3. Fill in the field details:
   - **Field Label:** Display name for the field (e.g., "Company GST Number")
   - **Field Name:** Unique identifier (auto-formatted, e.g., "company_gst_number")
   - **Field Type:** Choose from 12 different types
   - **Category:** Select appropriate category
   - **Applies To:** Choose where the field should appear
   - **Validation:** Set min/max length, patterns, etc.
   - **Options:** Add options for select/radio/multiselect types
4. Set additional properties:
   - Required/Optional
   - Active/Inactive
   - Show in List View
   - Searchable
5. Click "Create Field"

#### Managing Custom Fields

- **Edit:** Click the pencil icon to modify field properties
- **Delete:** Click the trash icon to remove a field (requires confirmation)
- **Reorder:** Use up/down arrows to change field display order
- **Activate/Deactivate:** Toggle field status without deleting

### For Users

#### Viewing and Editing Custom Fields

1. Navigate to Profile page
2. Scroll to the custom fields section
3. Fields are organized by category
4. Fill in required fields (marked with *)
5. Click "Save Changes" to update

## Technical Details

### Data Flow

1. **Admin creates field:**
   - Frontend sends POST request to `/api/custom-fields`
   - Backend validates and saves to `customfields` collection
   - Audit log created

2. **User fills field:**
   - Frontend fetches active fields via GET `/api/custom-fields?appliesTo=user&isActive=true`
   - CustomFieldsRenderer dynamically generates form inputs
   - Values stored in user's `customFields` map

3. **Data storage:**
   - Field definitions: `customfields` collection
   - Field values: `users` collection → `customFields` field (Map type)

### Validation

- **Client-side:** HTML5 validation + React form validation
- **Server-side:** Express validator middleware
- **Field-level:** Custom validation rules (min/max, patterns)

### Security

- Only admins can create/modify field definitions
- Users can only edit their own custom field values
- All actions logged in audit system
- Rate limiting applied to API endpoints

## API Examples

### Create a Custom Field

```bash
POST /api/custom-fields
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "fieldName": "gst_number",
  "fieldLabel": "GST Number",
  "fieldType": "text",
  "placeholder": "Enter GST number",
  "helpText": "15-digit GST identification number",
  "required": true,
  "validation": {
    "minLength": 15,
    "maxLength": 15,
    "pattern": "^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$",
    "patternMessage": "Invalid GST number format"
  },
  "appliesTo": "user",
  "category": "business",
  "isActive": true
}
```

### Get All Active Custom Fields

```bash
GET /api/custom-fields?appliesTo=user&isActive=true
Authorization: Bearer <token>
```

### Update User Profile with Custom Fields

```bash
PUT /api/users/profile
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "John Doe",
  "profile": {
    "phone": "1234567890"
  },
  "customFields": {
    "gst_number": "22AAAAA0000A1Z5",
    "pan_number": "ABCDE1234F"
  }
}
```

## Best Practices

1. **Field Naming:**
   - Use lowercase with underscores
   - Make names descriptive
   - Avoid special characters

2. **Validation:**
   - Set appropriate min/max lengths
   - Use regex patterns for specific formats
   - Provide clear validation messages

3. **Organization:**
   - Group related fields in same category
   - Set logical display order
   - Use help text to guide users

4. **Performance:**
   - Keep number of fields reasonable
   - Mark fields as inactive instead of deleting
   - Use indexes for searchable fields

## Future Enhancements

Potential improvements:

1. Conditional field visibility based on other field values
2. Field-level permissions (specific roles can see/edit specific fields)
3. Import/Export field configurations
4. Field templates for common use cases
5. Advanced validation (custom JavaScript validators)
6. Field value history tracking
7. Bulk edit capabilities
8. Field usage analytics

## Troubleshooting

### Custom fields not showing

- Check if fields are marked as "Active"
- Verify "Applies To" setting matches the context (user vs verification)
- Ensure user is logged in and has proper permissions

### Validation errors

- Review field validation settings in admin panel
- Check browser console for detailed error messages
- Verify field values match expected format

### Performance issues

- Consider reducing number of active fields
- Use pagination for field management in admin panel
- Optimize database indexes for searchable fields

## Support

For issues or questions:
1. Check application logs in `backend/logs/`
2. Review audit logs for field-related actions
3. Contact system administrator

## Version History

- **v1.0.0** (Current) - Initial implementation with full CRUD operations, validation, and UI integration


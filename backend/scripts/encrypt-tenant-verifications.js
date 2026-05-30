/**
 * One-time migration: encrypt existing plaintext TenantAadhaarVerification records.
 * Run: ENCRYPTION_KEY=... node backend/scripts/encrypt-tenant-verifications.js
 */
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const mongoose = require('mongoose');
const TenantAadhaarVerification = require('../src/models/TenantAadhaarVerification');
const { isEncrypted } = require('../src/utils/encryption');

async function run() {
  if (!process.env.ENCRYPTION_KEY) {
    console.error('ENCRYPTION_KEY is required');
    process.exit(1);
  }

  const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/kyc-aadhaar-app';
  await mongoose.connect(uri);

  const records = await TenantAadhaarVerification.find({});
  let updated = 0;

  for (const record of records) {
    const needsEncrypt =
      (record.aadhaarNumber && !isEncrypted(record.aadhaarNumber)) ||
      (record.name && record.name.trim() && !isEncrypted(record.name));

    if (needsEncrypt) {
      await record.save();
      updated += 1;
    }
  }

  console.log(`Encrypted ${updated} of ${records.length} tenant verification record(s).`);
  await mongoose.disconnect();
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});

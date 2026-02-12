#!/usr/bin/env node

/**
 * Vercel Deployment Configuration Test Script
 * This script validates the configuration before deploying to Vercel
 */

const fs = require('fs');
const path = require('path');

console.log('🧪 Testing Vercel Deployment Configuration...\n');

let errors = [];
let warnings = [];
let success = [];

// Test 1: Check vercel.json exists
console.log('1. Checking vercel.json...');
if (fs.existsSync('vercel.json')) {
  try {
    const vercelConfig = JSON.parse(fs.readFileSync('vercel.json', 'utf8'));
    success.push('✓ vercel.json exists and is valid JSON');
    
    // Check build configuration
    if (vercelConfig.buildCommand || vercelConfig.builds) {
      success.push('✓ Build configuration found');
    } else {
      warnings.push('⚠ No build command specified (will use defaults)');
    }
    
    // Check routes
    if (vercelConfig.routes && vercelConfig.routes.length > 0) {
      success.push('✓ Routes configuration found');
    } else {
      warnings.push('⚠ No routes specified');
    }
  } catch (e) {
    errors.push('✗ vercel.json is invalid JSON: ' + e.message);
  }
} else {
  errors.push('✗ vercel.json not found');
}

// Test 2: Check API entry point
console.log('\n2. Checking API entry point...');
if (fs.existsSync('api/index.js')) {
  success.push('✓ api/index.js exists');
  
  const apiContent = fs.readFileSync('api/index.js', 'utf8');
  if (apiContent.includes('module.exports') || apiContent.includes('exports')) {
    success.push('✓ API exports correctly');
  } else {
    errors.push('✗ API file does not export anything');
  }
  
  // Check if it references backend
  if (apiContent.includes('../backend')) {
    success.push('✓ API references backend correctly');
  } else {
    warnings.push('⚠ API may not reference backend correctly');
  }
} else {
  errors.push('✗ api/index.js not found');
}

// Test 3: Check frontend structure
console.log('\n3. Checking frontend structure...');
if (fs.existsSync('frontend/package.json')) {
  success.push('✓ frontend/package.json exists');
  
  try {
    const frontendPkg = JSON.parse(fs.readFileSync('frontend/package.json', 'utf8'));
    
    if (frontendPkg.scripts && frontendPkg.scripts.build) {
      success.push('✓ Frontend has build script');
    } else {
      errors.push('✗ Frontend package.json missing build script');
    }
    
    if (frontendPkg.dependencies || frontendPkg.devDependencies) {
      success.push('✓ Frontend has dependencies defined');
    }
  } catch (e) {
    errors.push('✗ Frontend package.json is invalid: ' + e.message);
  }
} else {
  errors.push('✗ frontend/package.json not found');
}

// Test 4: Check backend structure
console.log('\n4. Checking backend structure...');
if (fs.existsSync('backend/src/server.js')) {
  success.push('✓ backend/src/server.js exists');
  
  const serverContent = fs.readFileSync('backend/src/server.js', 'utf8');
  if (serverContent.includes('module.exports')) {
    success.push('✓ Backend server exports correctly');
  } else {
    errors.push('✗ Backend server does not export');
  }
  
  // Check for Vercel compatibility
  if (serverContent.includes('VERCEL') || serverContent.includes('process.env.VERCEL')) {
    success.push('✓ Backend has Vercel environment check');
  } else {
    warnings.push('⚠ Backend may not handle Vercel environment correctly');
  }
} else {
  errors.push('✗ backend/src/server.js not found');
}

// Test 5: Check environment variables example
console.log('\n5. Checking environment variables...');
if (fs.existsSync('.vercel.env.example')) {
  success.push('✓ .vercel.env.example exists');
} else {
  warnings.push('⚠ .vercel.env.example not found (optional)');
}

// Test 6: Check package.json scripts
console.log('\n6. Checking root package.json...');
if (fs.existsSync('package.json')) {
  try {
    const rootPkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    if (rootPkg.scripts && rootPkg.scripts['vercel-build']) {
      success.push('✓ vercel-build script exists');
    } else {
      warnings.push('⚠ vercel-build script not found (Vercel will use vercel.json)');
    }
  } catch (e) {
    warnings.push('⚠ Could not parse root package.json');
  }
}

// Summary
console.log('\n' + '='.repeat(50));
console.log('📊 TEST SUMMARY');
console.log('='.repeat(50));

if (success.length > 0) {
  console.log('\n✅ SUCCESS:');
  success.forEach(msg => console.log('  ' + msg));
}

if (warnings.length > 0) {
  console.log('\n⚠️  WARNINGS:');
  warnings.forEach(msg => console.log('  ' + msg));
}

if (errors.length > 0) {
  console.log('\n❌ ERRORS:');
  errors.forEach(msg => console.log('  ' + msg));
  console.log('\n❌ Configuration has errors. Please fix them before deploying.');
  process.exit(1);
} else {
  console.log('\n✅ Configuration looks good! Ready for deployment.');
  console.log('\n📝 Next steps:');
  console.log('  1. Push code to GitHub');
  console.log('  2. Go to vercel.com and import your repository');
  console.log('  3. Add environment variables (see VERCEL_ENV_VARIABLES.md)');
  console.log('  4. Deploy!');
  process.exit(0);
}


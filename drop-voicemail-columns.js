// Script to drop voicemail columns from dialer_campaigns table
const mysql = require('mysql2/promise');
require('dotenv').config();

async function dropVoicemailColumns() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.error('ERROR: DATABASE_URL not found in .env');
    process.exit(1);
  }

  let pool;
  try {
    pool = mysql.createPool(dbUrl);
    console.log('Connected to database...');

    const dbName = 'defaultdb'; // from your DATABASE_URL

    // Check and drop voicemail_mode column
    console.log('\nChecking voicemail_mode column...');
    const [vmModeCheck] = await pool.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' AND column_name='voicemail_mode' LIMIT 1",
      [dbName]
    );
    
    if (vmModeCheck && vmModeCheck.length > 0) {
      console.log('Dropping voicemail_mode column...');
      await pool.query('ALTER TABLE dialer_campaigns DROP COLUMN voicemail_mode');
      console.log('✓ Dropped voicemail_mode');
    } else {
      console.log('✓ voicemail_mode column does not exist');
    }

    // Check and drop voicemail_audio_blob column
    console.log('\nChecking voicemail_audio_blob column...');
    const [vmBlobCheck] = await pool.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' AND column_name='voicemail_audio_blob' LIMIT 1",
      [dbName]
    );
    
    if (vmBlobCheck && vmBlobCheck.length > 0) {
      console.log('Dropping voicemail_audio_blob column...');
      await pool.query('ALTER TABLE dialer_campaigns DROP COLUMN voicemail_audio_blob');
      console.log('✓ Dropped voicemail_audio_blob');
    } else {
      console.log('✓ voicemail_audio_blob column does not exist');
    }

    // Check and drop voicemail_audio_filename column
    console.log('\nChecking voicemail_audio_filename column...');
    const [vmFilenameCheck] = await pool.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' AND column_name='voicemail_audio_filename' LIMIT 1",
      [dbName]
    );
    
    if (vmFilenameCheck && vmFilenameCheck.length > 0) {
      console.log('Dropping voicemail_audio_filename column...');
      await pool.query('ALTER TABLE dialer_campaigns DROP COLUMN voicemail_audio_filename');
      console.log('✓ Dropped voicemail_audio_filename');
    } else {
      console.log('✓ voicemail_audio_filename column does not exist');
    }

    // Check and drop voicemail_audio_mime column
    console.log('\nChecking voicemail_audio_mime column...');
    const [vmMimeCheck] = await pool.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' AND column_name='voicemail_audio_mime' LIMIT 1",
      [dbName]
    );
    
    if (vmMimeCheck && vmMimeCheck.length > 0) {
      console.log('Dropping voicemail_audio_mime column...');
      await pool.query('ALTER TABLE dialer_campaigns DROP COLUMN voicemail_audio_mime');
      console.log('✓ Dropped voicemail_audio_mime');
    } else {
      console.log('✓ voicemail_audio_mime column does not exist');
    }

    // Check and drop voicemail_audio_size column
    console.log('\nChecking voicemail_audio_size column...');
    const [vmSizeCheck] = await pool.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' AND column_name='voicemail_audio_size' LIMIT 1",
      [dbName]
    );
    
    if (vmSizeCheck && vmSizeCheck.length > 0) {
      console.log('Dropping voicemail_audio_size column...');
      await pool.query('ALTER TABLE dialer_campaigns DROP COLUMN voicemail_audio_size');
      console.log('✓ Dropped voicemail_audio_size');
    } else {
      console.log('✓ voicemail_audio_size column does not exist');
    }

    // Show remaining columns
    console.log('\n=== Remaining dialer_campaigns columns ===');
    const [columns] = await pool.query(
      "SELECT column_name, column_type FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' ORDER BY ordinal_position",
      [dbName]
    );
    
    columns.forEach(col => {
      console.log(`  - ${col.column_name} (${col.column_type})`);
    });

    console.log('\n✅ Voicemail columns removal complete!');
    console.log('\nNext steps:');
    console.log('1. Restart your backend server (pm2 restart server or similar)');
    console.log('2. Test campaign creation - the JSON parse error should be gone!');

  } catch (error) {
    console.error('ERROR:', error.message);
    process.exit(1);
  } finally {
    if (pool) {
      await pool.end();
    }
  }
}

dropVoicemailColumns();

// Script to add campaign audio columns to dialer_campaigns table
const mysql = require('mysql2/promise');
require('dotenv').config();

async function addCampaignAudioColumns() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.error('ERROR: DATABASE_URL not found in .env');
    process.exit(1);
  }

  let pool;
  try {
    pool = mysql.createPool(dbUrl);
    console.log('Connected to database...');

    const dbName = 'defaultdb';

    // Check and add campaign_audio_blob column
    console.log('\nChecking campaign_audio_blob column...');
    const [blobCheck] = await pool.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' AND column_name='campaign_audio_blob' LIMIT 1",
      [dbName]
    );
    
    if (blobCheck && blobCheck.length > 0) {
      console.log('✓ campaign_audio_blob column already exists');
    } else {
      console.log('Adding campaign_audio_blob column...');
      await pool.query('ALTER TABLE dialer_campaigns ADD COLUMN campaign_audio_blob MEDIUMBLOB NULL AFTER concurrency_limit');
      console.log('✓ Added campaign_audio_blob');
    }

    // Check and add campaign_audio_filename column
    console.log('\nChecking campaign_audio_filename column...');
    const [filenameCheck] = await pool.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' AND column_name='campaign_audio_filename' LIMIT 1",
      [dbName]
    );
    
    if (filenameCheck && filenameCheck.length > 0) {
      console.log('✓ campaign_audio_filename column already exists');
    } else {
      console.log('Adding campaign_audio_filename column...');
      await pool.query('ALTER TABLE dialer_campaigns ADD COLUMN campaign_audio_filename VARCHAR(255) NULL AFTER campaign_audio_blob');
      console.log('✓ Added campaign_audio_filename');
    }

    // Check and add campaign_audio_mime column
    console.log('\nChecking campaign_audio_mime column...');
    const [mimeCheck] = await pool.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' AND column_name='campaign_audio_mime' LIMIT 1",
      [dbName]
    );
    
    if (mimeCheck && mimeCheck.length > 0) {
      console.log('✓ campaign_audio_mime column already exists');
    } else {
      console.log('Adding campaign_audio_mime column...');
      await pool.query('ALTER TABLE dialer_campaigns ADD COLUMN campaign_audio_mime VARCHAR(128) NULL AFTER campaign_audio_filename');
      console.log('✓ Added campaign_audio_mime');
    }

    // Check and add campaign_audio_size column
    console.log('\nChecking campaign_audio_size column...');
    const [sizeCheck] = await pool.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' AND column_name='campaign_audio_size' LIMIT 1",
      [dbName]
    );
    
    if (sizeCheck && sizeCheck.length > 0) {
      console.log('✓ campaign_audio_size column already exists');
    } else {
      console.log('Adding campaign_audio_size column...');
      await pool.query('ALTER TABLE dialer_campaigns ADD COLUMN campaign_audio_size INT NULL AFTER campaign_audio_mime');
      console.log('✓ Added campaign_audio_size');
    }

    // Show all campaign columns
    console.log('\n=== All dialer_campaigns columns ===');
    const [columns] = await pool.query(
      "SELECT column_name, column_type FROM information_schema.columns WHERE table_schema=? AND table_name='dialer_campaigns' ORDER BY ordinal_position",
      [dbName]
    );
    
    columns.forEach(col => {
      console.log(`  - ${col.column_name} (${col.column_type})`);
    });

    console.log('\n✅ Campaign audio columns migration complete!');
    console.log('\nNext steps:');
    console.log('1. Restart your backend server');
    console.log('2. The API endpoints for campaign audio upload/download will be added');
    console.log('3. UI will allow creating campaigns without selecting an AI agent');

  } catch (error) {
    console.error('ERROR:', error.message);
    process.exit(1);
  } finally {
    if (pool) {
      await pool.end();
    }
  }
}

addCampaignAudioColumns();

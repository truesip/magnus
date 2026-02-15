-- Fix voicemail_mode ENUM in dialer_campaigns table
-- Run this script to manually fix the database if the automatic migration didn't work

-- Step 1: Check current column type
SELECT COLUMN_TYPE, COLUMN_DEFAULT 
FROM information_schema.columns 
WHERE table_name='dialer_campaigns' 
AND column_name='voicemail_mode';

-- Step 2: Update any existing rows with old values to 'dialout'
UPDATE dialer_campaigns 
SET voicemail_mode = 'dialout' 
WHERE voicemail_mode IN ('none', 'agent');

-- Step 3: Modify the ENUM to the correct values
ALTER TABLE dialer_campaigns 
MODIFY COLUMN voicemail_mode ENUM('dialout','audio') NOT NULL DEFAULT 'dialout';

-- Step 4: Verify the change
SELECT COLUMN_TYPE, COLUMN_DEFAULT 
FROM information_schema.columns 
WHERE table_name='dialer_campaigns' 
AND column_name='voicemail_mode';

-- Drop voicemail-related columns from dialer_campaigns table
-- Run this to completely remove voicemail feature columns

-- Drop voicemail columns if they exist
SET @dbname = DATABASE();

SET @query = (
  SELECT IF(
    EXISTS(
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = @dbname
      AND table_name = 'dialer_campaigns'
      AND column_name = 'voicemail_mode'
    ),
    'ALTER TABLE dialer_campaigns DROP COLUMN voicemail_mode',
    'SELECT "voicemail_mode column does not exist" AS message'
  )
);
PREPARE stmt FROM @query;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @query = (
  SELECT IF(
    EXISTS(
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = @dbname
      AND table_name = 'dialer_campaigns'
      AND column_name = 'voicemail_audio_blob'
    ),
    'ALTER TABLE dialer_campaigns DROP COLUMN voicemail_audio_blob',
    'SELECT "voicemail_audio_blob column does not exist" AS message'
  )
);
PREPARE stmt FROM @query;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @query = (
  SELECT IF(
    EXISTS(
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = @dbname
      AND table_name = 'dialer_campaigns'
      AND column_name = 'voicemail_audio_filename'
    ),
    'ALTER TABLE dialer_campaigns DROP COLUMN voicemail_audio_filename',
    'SELECT "voicemail_audio_filename column does not exist" AS message'
  )
);
PREPARE stmt FROM @query;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @query = (
  SELECT IF(
    EXISTS(
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = @dbname
      AND table_name = 'dialer_campaigns'
      AND column_name = 'voicemail_audio_mime'
    ),
    'ALTER TABLE dialer_campaigns DROP COLUMN voicemail_audio_mime',
    'SELECT "voicemail_audio_mime column does not exist" AS message'
  )
);
PREPARE stmt FROM @query;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @query = (
  SELECT IF(
    EXISTS(
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = @dbname
      AND table_name = 'dialer_campaigns'
      AND column_name = 'voicemail_audio_size'
    ),
    'ALTER TABLE dialer_campaigns DROP COLUMN voicemail_audio_size',
    'SELECT "voicemail_audio_size column does not exist" AS message'
  )
);
PREPARE stmt FROM @query;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Verify columns are dropped
SELECT 'Voicemail columns removal complete!' AS status;

SELECT column_name 
FROM information_schema.columns 
WHERE table_schema = DATABASE() 
  AND table_name = 'dialer_campaigns'
ORDER BY ordinal_position;

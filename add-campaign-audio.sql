-- Add audio playback fields to dialer_campaigns table
-- This allows campaigns to play pre-recorded audio instead of using an AI agent

-- Add columns for campaign audio storage
ALTER TABLE dialer_campaigns 
ADD COLUMN campaign_audio_blob MEDIUMBLOB NULL AFTER concurrency_limit,
ADD COLUMN campaign_audio_filename VARCHAR(255) NULL AFTER campaign_audio_blob,
ADD COLUMN campaign_audio_mime VARCHAR(128) NULL AFTER campaign_audio_filename,
ADD COLUMN campaign_audio_size INT NULL AFTER campaign_audio_mime;

-- Verify columns were added
SELECT column_name, column_type 
FROM information_schema.columns 
WHERE table_schema = DATABASE() 
  AND table_name = 'dialer_campaigns'
  AND column_name LIKE 'campaign_audio%'
ORDER BY ordinal_position;

SELECT 'Campaign audio columns added successfully!' AS status;

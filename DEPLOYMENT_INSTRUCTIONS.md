# Deployment Instructions - Dialer Status Update Fix

## Problem Fixed
Campaign statistics and call history were not updating because call status callbacks from Pipecat weren't configured.

## Solution Summary
Added direct webhook callbacks from the Pipecat bot agent to your server. When a dialout call ends, the bot now sends the call result directly to your server, which updates the database.

## Files Changed

### 1. `pipecat-agent/bot.py`
**Changes**:
- Added call duration tracking (lines 3012-3015)
- Added webhook callback when calls end (lines 3025-3043)
- Track transfer status (lines 2852, 2906)

### 2. `server.js`
**Changes**:
- Added Pipecat callback endpoint `/webhooks/pipecat/dialout-completed` (lines 15613-15672)
- Added debug logging to existing webhook endpoint (lines 15571-15573, 15945-15958)
- Added manual status update endpoint for testing (lines 7633-7692)

### 3. `DIALER_STATUS_UPDATE_FIX.md`
- Comprehensive troubleshooting guide

## Deployment Steps

### Step 1: Update Server Code
1. Upload the modified `server.js` to your production server
2. Restart the Node.js process

### Step 2: Rebuild Pipecat Agent
1. Build a new Docker image with the updated `bot.py`:
   ```bash
   cd pipecat-agent
   docker build -t truesip/agenttalkusa:fix-dialout-status .
   docker push truesip/agenttalkusa:fix-dialout-status
   ```

2. Update `.env` with new image tag:
   ```
   PIPECAT_AGENT_IMAGE=truesip/agenttalkusa:fix-dialout-status
   ```

### Step 3: Configure Pipecat Agent Environment

In your Pipecat Cloud dashboard, add this environment variable to your agent's secret set:

```
PORTAL_BASE_URL=https://www.talkusa.net
```

**Important**: This tells the bot where to send callbacks. Without this, the status updates won't work.

Optional (if you want to secure the webhook):
```
PORTAL_AGENT_ACTION_TOKEN=your_secure_random_token_here
```

If you set a token, update `server.js` line 15638 to verify it.

### Step 4: Redeploy Pipecat Agent

After updating the secret set, trigger a new deployment in Pipecat Cloud or wait for the next auto-deploy.

### Step 5: Test

1. Start a new campaign and make a test call
2. Wait for the call to complete
3. Refresh your campaign page - status should update immediately
4. Check Call History - status should show "completed", "answered", or "transferred" instead of "queued"

## Verification

### Check Server Logs
SSH into your production server and tail the logs:
```bash
tail -f /path/to/logs/server.out
```

Look for:
```
[pipecat.dialout-completed] Received: { callId: 'd1l2-...', result: 'answered', durationSec: 30 }
[pipecat.dialout-completed] Updated: { logId: 123, leadId: 456 }
```

### Check Pipecat Logs
In Pipecat Cloud dashboard, check agent logs for:
```
Dialout callback sent: 200
```

### Manual Test (if needed)
If automated callbacks aren't working, you can manually update stuck calls:

1. Get the call_id from Call History (format: `d{campaignId}l{leadId}-{timestamp}`)
2. Use the debug endpoint:
   ```bash
   curl -X POST https://www.talkusa.net/api/me/dialer/debug/update-call-status \
     -H "Content-Type: application/json" \
     -H "Cookie: connect.sid=YOUR_SESSION_COOKIE" \
     -d '{
       "call_id": "d1l2-abc123",
       "status": "completed",
       "result": "answered",
       "duration_sec": 30
     }'
   ```

## Rollback Plan

If the changes cause issues:

1. Revert to previous `server.js`
2. Revert to previous Pipecat agent image:
   ```
   PIPECAT_AGENT_IMAGE=truesip/agenttalkusa:ambience-2026-01-19-a7959c8
   ```
3. Restart both services

## Monitoring

After deployment, monitor for:
- Campaign stats updating within 1-2 seconds of call completion
- Call History showing proper statuses
- No errors in server logs related to `[pipecat.dialout-completed]`

## Troubleshooting

### Status Still Not Updating
1. Check `PORTAL_BASE_URL` is set in Pipecat agent's environment
2. Verify agent is using the new Docker image
3. Check server logs for incoming webhook calls
4. Check Pipecat logs for "Dialout callback sent" messages

### 404 Error in Pipecat Logs
The webhook endpoint isn't deployed. Verify `server.js` was updated and restarted.

### 500 Error in Pipecat Logs
Check server logs for the error. Likely a database issue.

### Still Not Working?
See `DIALER_STATUS_UPDATE_FIX.md` for comprehensive troubleshooting, including Daily webhook configuration as an alternative approach.

## Notes

- The fix uses a direct callback approach which is more reliable than relying on Daily webhooks
- Daily webhooks can still be configured as a backup (see fix guide)
- The bot calculates call duration client-side, which may differ slightly from Daily's calculation
- Transferred calls are properly tracked and marked as "transferred"

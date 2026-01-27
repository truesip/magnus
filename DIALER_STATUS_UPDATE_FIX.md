# Dialer Campaign Status Update Issue - Fix Guide

## Problem Summary
The outbound dialer campaign is showing:
- Campaign stats not updating (stuck at 1 Live, 0 for other counts)
- Call history status stuck on "Queued" instead of updating to final status

## Root Cause Analysis

### How the System Should Work

1. **Call Initiation** (`server.js:7726-7739`):
   - When a call starts, a record is created in `dialer_call_logs` with `status = 'queued'`
   - A record is also created/updated in `dialer_leads` with `status = 'queued'`

2. **Status Updates** (`server.js:15977-15990`):
   - Daily/Pipecat sends webhook events to `/webhooks/daily/events`
   - Webhooks include events like: `dialout.started`, `dialout.connected`, `dialout.answered`, `dialout.stopped`
   - These update both `dialer_call_logs` (status/result/duration) and `dialer_leads` (status)

3. **Campaign Stats Display** (`server.js:7261-7302`):
   - Stats are aggregated from `dialer_leads` (for pending/in-progress/completed/failed)
   - And from `dialer_call_logs` (for answered/voicemail/transferred)

4. **Call History Display** (`server.js:11748-11792`):
   - Shows dialer calls from `dialer_call_logs` table
   - Status field comes from the `status` or `result` column

### Likely Causes

1. **Webhooks Not Configured**: Daily platform may not be configured to send webhooks to your endpoint
2. **Webhook URL Incorrect**: The webhook URL in Daily must match your server exactly
3. **Token Mismatch**: Though the token is set, Daily might not be using it
4. **Pipecat Not Sending Events**: The Pipecat service may not be configured to send webhooks

## Fixes Applied

### 1. Enhanced Debugging (✓ Done)
Added detailed logging to track webhook reception and processing:
- Logs incoming webhook payloads
- Logs dialout event processing details
- Logs when call logs and leads are/aren't found

Location: `server.js:15571-15573, 15945-15958`

### 2. Debug API Endpoint (✓ Done)
Created a manual status update endpoint for testing:

**Endpoint**: `POST /api/me/dialer/debug/update-call-status`

**Body**:
```json
{
  "call_id": "d1l123-abc",
  "status": "completed",
  "result": "answered",
  "duration_sec": 45
}
```

Location: `server.js:7633-7692`

### 3. Pipecat Direct Callback (✓ Done) - **PRIMARY FIX**
Added code to the Pipecat bot to send status updates directly to your server when calls end, bypassing the need for Daily webhook configuration:

**What Changed**:
- Bot tracks call start/end times and calculates duration
- Bot sends webhook to `/webhooks/pipecat/dialout-completed` when calls finish
- Server endpoint updates both `dialer_call_logs` and `dialer_leads` tables
- Works for answered, transferred, and completed calls

**Files Modified**:
- `pipecat-agent/bot.py` - Added callback sending logic
- `server.js` - Added `/webhooks/pipecat/dialout-completed` endpoint (lines 15613-15672)

**Configuration Required**:
You must set `PORTAL_BASE_URL` in your Pipecat agent's environment (secret set):
```
PORTAL_BASE_URL=https://www.talkusa.net
```

## Next Steps

### Step 1: Check Server Logs
Restart your server with DEBUG enabled and make a test call. Check logs for:
```
[daily.webhook] Received webhook: ...
[daily.webhook] Processing dialout event: ...
```

If you DON'T see these logs, webhooks aren't being received.

### Step 2: Verify Daily Webhook Configuration

Your webhook endpoint should be configured in the Daily/Pipecat dashboard:

**Webhook URL**: `https://www.talkusa.net/webhooks/daily/events?token=987drtytkbxt34u6iljoijdt455ed`

**Events to Subscribe**:
- `dialout.started`
- `dialout.ringing`
- `dialout.connected`
- `dialout.answered`
- `dialout.stopped`
- `dialout.error`
- `dialout.warning`

### Step 3: Test with Debug Endpoint

To test if manual updates work:

1. Look at your call history and find a call_id (format: `d{campaignId}l{leadId}-{timestamp}`)
2. Use curl or Postman to call:

```bash
curl -X POST https://www.talkusa.net/api/me/dialer/debug/update-call-status \
  -H "Content-Type: application/json" \
  -H "Cookie: connect.sid=YOUR_SESSION_COOKIE" \
  -d '{
    "call_id": "YOUR_CALL_ID",
    "status": "completed",
    "result": "answered",
    "duration_sec": 30
  }'
```

3. Refresh your campaign page - stats should update immediately

### Step 4: Configure Daily Webhooks (Most Likely Fix)

If logs show webhooks aren't being received, you need to configure them in Daily:

1. Log into your Daily/Pipecat dashboard
2. Go to Webhook Settings
3. Add webhook URL: `https://www.talkusa.net/webhooks/daily/events?token=987drtytkbxt34u6iljoijdt455ed`
4. Enable the dialout events listed above
5. Test with a new call

### Step 5: Alternative - Check Pipecat Agent Configuration

The Pipecat agent running your calls must be configured to send webhooks. Check your agent configuration in `pipecat-agent/` directory or in your Pipecat Cloud settings.

## Quick Test Script

Run this to check if your webhook endpoint is accessible:

```bash
# Test webhook endpoint (should return 403 without token)
curl -X POST https://www.talkusa.net/webhooks/daily/events

# Test with correct token (should return 200)
curl -X POST 'https://www.talkusa.net/webhooks/daily/events?token=987drtytkbxt34u6iljoijdt455ed' \
  -H "Content-Type: application/json" \
  -d '{
    "type": "dialout.stopped",
    "call_id": "test-123",
    "payload": {
      "result": "answered",
      "duration": 10
    }
  }'
```

## Files Modified

1. `server.js` - Added debug logging and test endpoint
2. This guide - `DIALER_STATUS_UPDATE_FIX.md`

## Support

If webhooks are confirmed to be configured correctly but still not working:

1. Check firewall/network settings - ensure port 443 is accessible
2. Check if your PUBLIC_BASE_URL env variable is correct
3. Verify SSL certificate is valid
4. Contact Daily/Pipecat support about webhook delivery

## Database Schema Reference

### dialer_call_logs table
- `status`: Current status (queued, dialing, connected, completed, error, warning)
- `result`: Final result (answered, voicemail, transferred, failed)
- `duration_sec`: Call duration in seconds
- `call_id`: Unique call identifier used to match webhooks

### dialer_leads table  
- `status`: Lead status (pending, queued, dialing, answered, voicemail, transferred, failed, completed)
- `attempt_count`: Number of call attempts
- `last_call_at`: Timestamp of last call attempt

# DIDWW Capacity Pool Integration

## Overview
This application automatically assigns purchased DIDs to a DIDWW Capacity Pool to manage channel capacity and routing.

## Configuration

### Option 1: Using Capacity Pool Name
Set the pool name in your `.env` file:
```env
DIDWW_CAPACITY_POOL_NAME=USA
```

The system will automatically look up the pool ID by name when needed.

### Option 2: Using Capacity Pool ID
If you already know your pool ID, you can set it directly:
```env
DIDWW_CAPACITY_POOL_ID=your-pool-id-here
```

This is more efficient as it skips the lookup step.

## How It Works

1. **DID Purchase**: When a DID is purchased through the `/api/me/didww/orders` endpoint, the system:
   - Creates the order with DIDWW
   - Saves the DID to the local database
   - Automatically assigns it to the configured capacity pool

2. **Reconciliation**: For pending orders that complete asynchronously:
   - The system checks pending orders when loading the DIDs list
   - Automatically assigns any newly completed DIDs to the capacity pool

3. **Caching**: The capacity pool ID is cached after first lookup to improve performance

## API Endpoints

### List Capacity Pools
```
GET /api/me/didww/capacity-pools
```

Returns all available capacity pools from your DIDWW account.

Response:
```json
{
  "success": true,
  "data": [
    {
      "id": "pool-id",
      "type": "capacity_pools",
      "attributes": {
        "name": "USA",
        "channels_count": 100,
        ...
      }
    }
  ]
}
```

## Finding Your Capacity Pool

To find your capacity pool name or ID:

1. Make a GET request to `/api/me/didww/capacity-pools`
2. Or visit the DIDWW API directly: https://api.didww.com/v3/capacity_pools
3. Copy either the pool `name` or `id` to your `.env` file

## Debugging

Enable debug logging to see capacity pool assignment:
```env
DEBUG=1
```

Look for log entries like:
```
[didww.capacityPool] Looking up capacity pool: { configuredId: undefined, configuredName: 'USA' }
[didww.capacityPool] Available pools: [...]
[didww.order] Assigned DID to capacity pool: { didId: 'xxx', capacityPoolId: 'yyy' }
```

## Troubleshooting

### "No match found for name"
- Check that the pool name exactly matches (case-insensitive)
- Verify the pool exists in your DIDWW account via the API

### "Failed to assign DID to capacity pool"
- Check DIDWW API error in logs
- Verify your API key has permission to modify capacity pools
- Ensure the pool ID is valid

## References
- [DIDWW Capacity Pool API Documentation](https://doc.didww.com/api3/2022-05-10/inventory-resources/capacity-pool/)

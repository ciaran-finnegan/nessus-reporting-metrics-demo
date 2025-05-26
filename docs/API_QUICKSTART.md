# API Quick Start Guide

This guide helps frontend developers quickly understand and use the Vulnerability Management API.

## API Specification

The complete API specification is available in OpenAPI 3.0 format:
- **File**: [`api-specification.yaml`](api-specification.yaml)
- **Online Viewer**: Copy the contents and paste into [Swagger Editor](https://editor.swagger.io/)

## Authentication

All API endpoints (except login) require authentication using JWT tokens.

### Login Flow
```javascript
// 1. Login
POST /v1/auth/login
{
  "email": "user@example.com",
  "password": "password123"
}

// Response
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 3600,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "admin"
  }
}

// 2. Use access token in subsequent requests
GET /v1/assets
Headers: {
  "Authorization": "Bearer eyJ..."
}
```

### Token Refresh
```javascript
POST /v1/auth/refresh
{
  "refresh_token": "eyJ..."
}
```

## Common Patterns

### Pagination
All list endpoints support pagination:
```
GET /v1/assets?page=1&page_size=20
```

Response includes pagination metadata:
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_count": 150,
    "total_pages": 8
  }
}
```

### Filtering
Most list endpoints support filtering:
```
GET /v1/assets?type=Host&criticality_min=4
GET /v1/vulnerabilities?severity=Critical,High&status=Open
```

### Sorting
Use the `sort` parameter with `+` (ascending) or `-` (descending):
```
GET /v1/assets?sort=-criticality_score
GET /v1/vulnerabilities?sort=+created_at
```

## Key Endpoints

### Assets
- `GET /v1/assets` - List all assets with filtering
- `GET /v1/assets/{id}` - Get asset details
- `GET /v1/assets/{id}/vulnerabilities` - Get vulnerabilities for an asset
- `POST /v1/assets/{id}/tags` - Assign tags to an asset

### Vulnerabilities
- `GET /v1/vulnerabilities` - List vulnerabilities
- `GET /v1/vulnerabilities/{id}` - Get vulnerability details
- `PATCH /v1/vulnerabilities/{id}` - Update vulnerability status

### Business Groups
- `GET /v1/business-groups` - Get hierarchical business group tree
- `POST /v1/business-groups/{id}/assets` - Assign assets to group

### Asset Tags
- `GET /v1/tags` - List all tags
- `POST /v1/tags` - Create new tag (manual or dynamic)

### Dashboard
- `GET /v1/dashboard/summary` - Get dashboard summary data
- `GET /v1/dashboard/risk-matrix` - Get risk matrix data

### Reports
- `GET /v1/reports/executive-summary` - Executive summary
- `GET /v1/reports/vulnerability-trends` - Trend analysis

## Example Workflows

### 1. Display Dashboard
```javascript
// Get dashboard summary
const summary = await api.get('/v1/dashboard/summary');

// Get risk matrix
const riskMatrix = await api.get('/v1/dashboard/risk-matrix');
```

### 2. View Assets by Business Group
```javascript
// Get business groups
const groups = await api.get('/v1/business-groups');

// Get assets for a specific group
const assets = await api.get('/v1/assets?business_group_id=uuid');
```

### 3. Update Vulnerability Status
```javascript
// Update vulnerability
await api.patch('/v1/vulnerabilities/uuid', {
  status: 'Fixed',
  notes: 'Patched in version 2.1.0'
});
```

### 4. Upload and Process Scan
```javascript
// Upload scan file
const formData = new FormData();
formData.append('file', scanFile);
formData.append('scanner_type', 'nessus');
formData.append('scan_name', 'Weekly Infrastructure Scan');

const scan = await api.post('/v1/scans', formData, {
  headers: { 'Content-Type': 'multipart/form-data' }
});

// Check scan status
const status = await api.get(`/v1/scans/${scan.id}`);
```

## Error Handling

All errors follow a consistent format:
```json
{
  "error": "validation_error",
  "message": "Invalid request parameters",
  "details": {
    "field": "criticality_score",
    "reason": "Must be between 1 and 5"
  }
}
```

Common HTTP status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `422` - Validation Error
- `500` - Server Error

## Rate Limiting

The API implements rate limiting:
- **Default**: 100 requests per minute per user
- **Bulk operations**: 10 requests per minute
- Headers include rate limit information:
  - `X-RateLimit-Limit`
  - `X-RateLimit-Remaining`
  - `X-RateLimit-Reset`

## Next Steps

1. Review the full [API Specification](api-specification.yaml)
2. Set up authentication in your frontend app
3. Implement error handling and retry logic
4. Use the pagination patterns for large datasets
5. Leverage filtering for efficient data retrieval

## Support

For API issues or questions:
- Check the full specification for detailed schemas
- Review error messages for debugging
- Contact the backend team for integration support 
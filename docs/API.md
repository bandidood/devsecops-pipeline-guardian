# DevSecOps Pipeline Guardian - API Documentation

## Base URL

```
http://localhost:8000
```

## Authentication

Currently, the API does not require authentication. In production environments, implement OAuth2 or API key authentication.

## Endpoints

### Health Check

#### GET /health

Check the health status of the API.

**Response:**
```json
{
  "status": "healthy",
  "service": "DevSecOps Pipeline Guardian"
}
```

---

### Scans

#### POST /api/v1/scans

Create and initiate a new security scan.

**Request Body:**
```json
{
  "scan_type": "full",
  "target": "/path/to/project",
  "options": {
    "include_dast": true,
    "include_container": true,
    "evaluate_policy": true
  }
}
```

**Parameters:**
- `scan_type` (string, required): Type of scan - `full`, `sast`, `dast`, `dependency`, or `container`
- `target` (string, required): Target to scan (path, URL, or image name)
- `options` (object, optional): Additional scan options

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "message": "full scan initiated"
}
```

**Status Codes:**
- `200 OK`: Scan created successfully
- `400 Bad Request`: Invalid scan type or parameters
- `500 Internal Server Error`: Server error

---

#### GET /api/v1/scans/{scan_id}

Get scan results by scan ID.

**Path Parameters:**
- `scan_id` (string, required): Unique scan identifier

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "scan_type": "full",
  "target": "/path/to/project",
  "status": "completed",
  "start_time": "2025-01-17T10:00:00Z",
  "end_time": "2025-01-17T10:05:00Z",
  "duration_seconds": 300,
  "results": {
    "sast": {
      "summary": {
        "critical": 1,
        "high": 3,
        "medium": 5,
        "low": 10
      },
      "vulnerabilities": [...]
    },
    "dependency": {...},
    "dast": {...},
    "container": {...}
  },
  "policy_evaluation": {
    "decision": "deny",
    "security_score": 65,
    "violations": [...]
  }
}
```

**Status Codes:**
- `200 OK`: Scan found
- `404 Not Found`: Scan not found

---

#### GET /api/v1/scans/{scan_id}/status

Get scan status by scan ID.

**Path Parameters:**
- `scan_id` (string, required): Unique scan identifier

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running"
}
```

**Status Values:**
- `pending`: Scan queued but not started
- `running`: Scan in progress
- `completed`: Scan finished successfully
- `failed`: Scan failed
- `cancelled`: Scan cancelled

---

#### GET /api/v1/scans

List all scans.

**Response:**
```json
{
  "scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "completed",
      "details": {...}
    }
  ],
  "total": 1
}
```

---

#### GET /api/v1/scans/{scan_id}/export

Export scan results in specified format.

**Path Parameters:**
- `scan_id` (string, required): Unique scan identifier

**Query Parameters:**
- `format` (string, optional): Export format - `json`, `sarif`, `html` (default: `json`)

**Response:**
Returns the scan results in the requested format.

**Content Types:**
- `application/json` for JSON format
- `application/sarif+json` for SARIF format
- `text/html` for HTML format

---

### Policy

#### GET /api/v1/policy/status

Get policy enforcement status.

**Response:**
```json
{
  "enabled": true,
  "opa_url": "http://localhost:8181",
  "policy_package": "devsecops.security"
}
```

---

### Metrics

#### GET /api/v1/metrics

Get platform metrics summary.

**Response:**
```json
{
  "total_scans": 100,
  "completed_scans": 95,
  "failed_scans": 3,
  "running_scans": 2
}
```

---

#### GET /metrics

Prometheus metrics endpoint.

**Response:**
Returns metrics in Prometheus text exposition format.

```
# HELP devsecops_scans_total Total number of security scans performed
# TYPE devsecops_scans_total counter
devsecops_scans_total{scan_type="sast",status="completed"} 45
devsecops_scans_total{scan_type="dast",status="completed"} 30
...
```

---

## Error Responses

All error responses follow this format:

```json
{
  "detail": "Error message describing what went wrong"
}
```

**Common Status Codes:**
- `400 Bad Request`: Invalid request parameters
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

---

## Examples

### Python Example

```python
import requests

# Create a scan
response = requests.post('http://localhost:8000/api/v1/scans', json={
    'scan_type': 'full',
    'target': '/path/to/project',
    'options': {
        'include_dast': True,
        'evaluate_policy': True
    }
})

scan = response.json()
scan_id = scan['scan_id']

# Check status
status_response = requests.get(f'http://localhost:8000/api/v1/scans/{scan_id}/status')
print(status_response.json())

# Get results
results_response = requests.get(f'http://localhost:8000/api/v1/scans/{scan_id}')
results = results_response.json()
print(f"Security Score: {results['policy_evaluation']['security_score']}/100")

# Export as SARIF
sarif_response = requests.get(
    f'http://localhost:8000/api/v1/scans/{scan_id}/export',
    params={'format': 'sarif'}
)
with open('scan-results.sarif', 'w') as f:
    f.write(sarif_response.text)
```

### curl Examples

```bash
# Create scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "sast", "target": "./src"}'

# Get scan results
curl http://localhost:8000/api/v1/scans/{scan_id}

# Export as HTML
curl "http://localhost:8000/api/v1/scans/{scan_id}/export?format=html" \
  -o report.html

# Get Prometheus metrics
curl http://localhost:8000/metrics
```

---

## Interactive API Documentation

The API provides interactive documentation:

- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc

These interfaces allow you to explore and test all API endpoints directly from your browser.

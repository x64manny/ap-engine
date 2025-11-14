# Examples

This directory contains canonical request/response examples for the `/generate` endpoint.

## Structure

```
examples/
├── requests/          # Input examples (what you send to /generate)
└── responses/         # Output examples (what the engine returns)
```

## Examples

### 1. Simple Single Host (No Vulnerabilities)

- **Request**: `requests/simple_single_host.json`
- **Response**: `responses/simple_single_host.response.json`
- **Scenario**: Clean nginx web server with no detected vulnerabilities
- **Result**: Empty attack_paths array (nothing to exploit)

### 2. Single Host with High-Risk Vulnerability

- **Request**: `requests/single_host_high_risk_vuln.json`
- **Response**: `responses/single_host_high_risk_vuln.response.json`
- **Scenario**: Windows Server with SMBGhost (CVE-2020-0796, CVSS 10.0)
- **Result**: Single critical-risk attack path with Initial Access step

### 3. Single Host App Server with RCE

- **Request**: `requests/single_host_app_server_with_rce.json`
- **Response**: `responses/single_host_app_server_with_rce.response.json`
- **Scenario**: Apache Tomcat with deserialization RCE (CVE-2021-4104, CVSS 8.8)
- **Result**: High-risk attack path exploiting the web service

## Testing

Run any example:

```bash
curl -X POST http://127.0.0.1:8000/generate \
  -H "Content-Type: application/json" \
  -d @examples/requests/simple_single_host.json \
  -s | python3 -m json.tool
```

## Notes

- All examples follow the single-host contract (one element in `targets` array)
- All optional fields are set to `null` when not provided
- Response structure is consistent across all examples
- Empty vulnerabilities array results in empty attack_paths array

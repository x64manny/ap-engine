# /generate Contract

## Request

The `/generate` endpoint receives a JSON body that conforms to `BackendInput`:

```json
{
  "targets": [
    {
      "IpAddress": "10.42.17.8",
      "Hostname": "app-server-01",
      "Os": "Ubuntu 20.04 LTS",
      "MacAddress": null,
      "LastSeen": null,
      "Services": [
        {
          "Port": 8080,
          "Protocol": "tcp",
          "State": "open",
          "ServiceName": "http",
          "Product": "Apache Tomcat",
          "Version": "9.0.31",
          "ExtraInfo": null,
          "LastSeen": null,
          "Vulnerabilities": [
            {
              "template": null,
              "template_id": "CVE-2021-4104",
              "info": {
                "name": "Apache Tomcat - Deserialization RCE",
                "author": null,
                "tags": null,
                "description": null,
                "impact": null,
                "reference": null,
                "severity": "high",
                "metadata": null,
                "classification": {
                  "cve_id": ["CVE-2021-4104"],
                  "cwe_id": null,
                  "cvss_metrics": null,
                  "cvss_score": 8.8,
                  "epss_score": null,
                  "epss_percentile": null,
                  "cpe": null
                },
                "remediation": "Upgrade Tomcat to latest 9.x"
              },
              "type": null,
              "host": null,
              "port": null,
              "scheme": null,
              "url": null,
              "ip": null,
              "timestamp": null,
              "matcher_status": null,
              "meta": null
            }
          ]
        }
      ]
    }
  ]
}
```

**In practice:** the collector sends exactly one host per request (one element in `targets`), with as many optional fields filled as it managed to collect.

## Response

The endpoint returns `AttackPathResponse`, embedding `AttackPathResult`. Canonical example:

```json
{
  "request_id": "c41cf2e2-ecd2-4bda-9495-09d903f50d4b",
  "attack_path_result": {
    "attack_paths": [
      {
        "id": "AP-1",
        "risk_score": 0.95,
        "risk_level": "Critical",
        "justification": "Exploits CVE-2017-5638 in Apache Struts 2 on port 8080 (Apache Tomcat) on host app-server-01, then pivots to the MySQL database on db-master using weak internal controls.",
        "targets_involved": ["app-server-01", "db-master"],
        "mitre_chain": [
          {
            "stage": "Initial Access",
            "tactic": "TA0001 Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "description": "The attacker exploits CVE-2017-5638 in the Apache Struts 2 application exposed via Apache Tomcat on port 8080 on app-server-01 to gain code execution on the web server.",
            "defensive_context": "Patch Apache Struts 2, keep Tomcat and the OS updated, and place the application behind a hardened WAF with strict input validation.",
            "detection_ideas": "Monitor web server logs and WAF alerts for exploit payloads and anomalous HTTP requests targeting Struts endpoints."
          },
          {
            "stage": "Lateral Movement",
            "tactic": "TA0008 Lateral Movement",
            "technique_id": "T1021",
            "technique_name": "Remote Services",
            "description": "From app-server-01, the attacker connects to the MySQL service on db-master over port 3306, leveraging stolen or weak credentials to gain access to the database host.",
            "defensive_context": "Restrict connectivity from the web tier to the database tier, enforce strong authentication and network segmentation, and harden MySQL configuration.",
            "detection_ideas": "Monitor internal traffic from web servers to MySQL on db-master and alert on unusual connection patterns or authentication failures."
          }
        ]
      }
    ]
  },
  "execution_time_seconds": 10.36,
  "estimated_cost_usd": 0.0005
}
```

This is the canonical contract for `/generate`. Any consumer should expect this shape.

## Usage

### Basic curl Example

```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [
      {
        "IpAddress": "192.168.1.100",
        "Hostname": "web-server",
        "Os": "Ubuntu 22.04",
        "Services": [
          {
            "Port": 80,
            "Protocol": "tcp",
            "State": "open",
            "ServiceName": "http",
            "Product": "Apache",
            "Version": "2.4.52",
            "Vulnerabilities": [
              {
                "template_id": "CVE-2023-1234",
                "info": {
                  "name": "Apache HTTP Server RCE",
                  "severity": "critical",
                  "classification": {
                    "cve_id": ["CVE-2023-1234"],
                    "cvss_score": 9.8
                  }
                }
              }
            ]
          }
        ]
      }
    ]
  }'
```

### Using a File

```bash
# Save your request to a file
cat > request.json << 'EOF'
{
  "targets": [
    {
      "IpAddress": "10.0.0.50",
      "Hostname": "db-server",
      "Os": "CentOS 7",
      "Services": [
        {
          "Port": 5432,
          "Protocol": "tcp",
          "ServiceName": "postgresql",
          "Product": "PostgreSQL",
          "Version": "9.6",
          "Vulnerabilities": []
        }
      ]
    }
  ]
}
EOF

# Send the request
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d @request.json
```

### Minimal Request (No Vulnerabilities)

```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [
      {
        "IpAddress": "10.0.0.1",
        "Services": [
          {
            "Port": 443,
            "ServiceName": "https",
            "Vulnerabilities": []
          }
        ]
      }
    ]
  }'
```

### full_surface_single_host_exploitation.json Example

```bash
curl -X POST http://127.0.0.1:8000/generate \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [
      {
        "IpAddress": "172.22.50.14",
        "Hostname": "corp-app-db-02",
        "Os": "Windows Server 2016",
        "Services": [
          {
            "Port": 80,
            "Protocol": "tcp",
            "State": "open",
            "ServiceName": "http",
            "Product": "IIS",
            "Version": "10.0",
            "Vulnerabilities": [
              {
                "template_id": "CVE-2017-7269",
                "info": {
                  "name": "IIS WebDAV RCE",
                  "severity": "critical",
                  "classification": {
                    "cve_id": ["CVE-2017-7269"],
                    "cvss_score": 9.3
                  },
                  "remediation": "Apply Microsoft security update for WebDAV processing."
                }
              }
            ]
          },
          {
            "Port": 445,
            "Protocol": "tcp",
            "State": "open",
            "ServiceName": "microsoft-ds",
            "Product": "SMBv3",
            "Version": "3.1.1",
            "Vulnerabilities": [
              {
                "template_id": "CVE-2020-0796",
                "info": {
                  "name": "SMBGhost RCE",
                  "severity": "critical",
                  "classification": {
                    "cve_id": ["CVE-2020-0796"],
                    "cvss_score": 10.0
                  },
                  "remediation": "Apply Microsoft patch and disable SMB compression."
                }
              }
            ]
          },
          {
            "Port": 5985,
            "Protocol": "tcp",
            "State": "open",
            "ServiceName": "winrm",
            "Product": "Windows Remote Management",
            "Version": "2.0",
            "Vulnerabilities": []
          },
          {
            "Port": 1433,
            "Protocol": "tcp",
            "State": "open",
            "ServiceName": "ms-sql-s",
            "Product": "Microsoft SQL Server",
            "Version": "2016",
            "Vulnerabilities": [
              {
                "template_id": "CVE-2016-7249",
                "info": {
                  "name": "SQL Server Privilege Escalation",
                  "severity": "high",
                  "classification": {
                    "cve_id": ["CVE-2016-7249"],
                    "cvss_score": 8.5
                  },
                  "remediation": "Apply cumulative updates and restrict DB access."
                }
              }
            ]
          }
        ]
      }
    ]
  }' | python3 -m json.tool > corp_windows_multistage_test.json

```

**Expected response:** `{"attack_paths": []}` (empty array when no vulnerabilities)

## Examples

Example requests are under `examples/requests/` and their corresponding engine outputs under `examples/responses/`.

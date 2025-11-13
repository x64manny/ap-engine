"""
Host-related data models.

This module defines the input data structure for the Attack Path Engine.
It uses Pydantic for data validation and type safety, ensuring that all
incoming data from external vulnerability collectors is properly validated.

The models support a hierarchical structure with nested services and
detailed vulnerability information including CVE data, CVSS scores, and
exploitation metadata.

Design Philosophy:
    - Hierarchical structure matching real vulnerability scanner output
    - Rich vulnerability metadata for comprehensive attack path analysis
    - Type-safe models for all nested levels
    - Self-documenting via Field descriptions

Architecture Role:
    - Data Layer component
    - Defines API contract for input data
    - Provides validation and type safety
    - Supports vulnerability scanner integration (Nmap, Nuclei, etc.)

Usage:
    >>> # Parse scanner output
    >>> host = InputHost(
    ...     IpAddress="192.168.1.100",
    ...     Os="Linux 3.10 - 4.11",
    ...     Hostname="web-server",
    ...     Services=[
    ...         Service(
    ...             Port=80,
    ...             ServiceName="http",
    ...             Product="Apache",
    ...             Version="2.4.41"
    ...         )
    ...     ]
    ... )
"""
from typing import List, Optional

from pydantic import BaseModel, Field

# =============================================================================
# Vulnerability Classification Models
# =============================================================================

class Classification(BaseModel):
    """
    CVE classification and scoring information.
    
    Contains CVSS scores, EPSS probabilities, CWE mappings, and CPE identifiers
    for comprehensive vulnerability assessment.
    """
    cve_id: Optional[List[str]] = Field(
        None,
        alias="cve-id",
        description="CVE identifiers for this vulnerability"
    )
    cwe_id: Optional[List[str]] = Field(
        None,
        alias="cwe-id",
        description="CWE (Common Weakness Enumeration) identifiers"
    )
    cvss_metrics: Optional[str] = Field(
        None,
        alias="cvss-metrics",
        description="CVSS vector string (e.g., CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)"
    )
    cvss_score: Optional[float] = Field(
        None,
        alias="cvss-score",
        description="CVSS base score (0.0-10.0)"
    )
    epss_score: Optional[float] = Field(
        None,
        alias="epss-score",
        description="EPSS (Exploit Prediction Scoring System) probability score"
    )
    epss_percentile: Optional[float] = Field(
        None,
        alias="epss-percentile",
        description="EPSS percentile ranking"
    )
    cpe: Optional[str] = Field(
        None,
        description="CPE (Common Platform Enumeration) identifier"
    )
    
    class Config:
        populate_by_name = True


class Metadata(BaseModel):
    """
    Vulnerability metadata including search queries and verification status.
    
    Contains information useful for vulnerability validation and reconnaissance.
    """
    verified: Optional[bool] = Field(
        None,
        description="Whether the vulnerability has been verified"
    )
    max_request: Optional[int] = Field(
        None,
        alias="max-request",
        description="Maximum number of requests for detection"
    )
    vendor: Optional[str] = Field(
        None,
        description="Software vendor name"
    )
    product: Optional[str] = Field(
        None,
        description="Product name"
    )
    shodan_query: Optional[List[str]] = Field(
        None,
        alias="shodan-query",
        description="Shodan search queries for finding vulnerable instances"
    )
    fofa_query: Optional[List[str]] = Field(
        None,
        alias="fofa-query",
        description="FOFA search queries"
    )
    google_query: Optional[str] = Field(
        None,
        alias="google-query",
        description="Google dork for finding vulnerable instances"
    )
    params: Optional[str] = Field(
        None,
        description="Additional detection parameters"
    )
    
    class Config:
        populate_by_name = True


class VulnerabilityInfo(BaseModel):
    """
    Detailed vulnerability information.
    
    Contains comprehensive details about the vulnerability including
    description, impact, remediation, and classification.
    """
    name: Optional[str] = Field(
        None,
        description="Vulnerability name/title"
    )
    author: Optional[List[str]] = Field(
        None,
        description="Detection template authors"
    )
    tags: Optional[List[str]] = Field(
        None,
        description="Vulnerability tags (e.g., cve, rce, apache, kev)"
    )
    description: Optional[str] = Field(
        None,
        description="Detailed vulnerability description"
    )
    impact: Optional[str] = Field(
        None,
        description="Impact analysis of the vulnerability"
    )
    reference: Optional[List[str]] = Field(
        None,
        description="Reference URLs for additional information"
    )
    severity: Optional[str] = Field(
        None,
        description="Severity level (critical, high, medium, low, info)"
    )
    metadata: Optional[Metadata] = Field(
        None,
        description="Additional metadata and search queries"
    )
    classification: Optional[Classification] = Field(
        None,
        description="CVE classification and scoring"
    )
    remediation: Optional[str] = Field(
        None,
        description="Remediation steps and recommendations"
    )


# =============================================================================
# Vulnerability Detection Models
# =============================================================================

class VulnerabilityMeta(BaseModel):
    """
    Metadata about the vulnerability detection.
    """
    params: Optional[str] = Field(
        None,
        description="Detection parameters used"
    )


class Vulnerability(BaseModel):
    """
    Detected vulnerability instance.
    
    Represents a specific vulnerability detection with all associated
    metadata, classification, and context.
    """
    template: Optional[str] = Field(
        None,
        description="Detection template path (e.g., http/cves/2017/CVE-2017-5638.yaml)"
    )
    template_id: Optional[str] = Field(
        None,
        alias="template-id",
        description="Template identifier (typically CVE ID)"
    )
    info: Optional[VulnerabilityInfo] = Field(
        None,
        description="Detailed vulnerability information"
    )
    type: Optional[str] = Field(
        None,
        description="Vulnerability type (e.g., http, network)"
    )
    host: Optional[str] = Field(
        None,
        description="Vulnerable host and port"
    )
    port: Optional[str] = Field(
        None,
        description="Vulnerable port number"
    )
    scheme: Optional[str] = Field(
        None,
        description="Protocol scheme (http, https)"
    )
    url: Optional[str] = Field(
        None,
        description="Full URL where vulnerability was detected"
    )
    meta: Optional[VulnerabilityMeta] = Field(
        None,
        description="Detection metadata"
    )
    ip: Optional[str] = Field(
        None,
        description="IP address of vulnerable host"
    )
    timestamp: Optional[str] = Field(
        None,
        description="Detection timestamp"
    )
    matcher_status: Optional[bool] = Field(
        None,
        alias="matcher-status",
        description="Whether the vulnerability matcher succeeded"
    )
    
    class Config:
        populate_by_name = True


# =============================================================================
# Service Models
# =============================================================================

class Service(BaseModel):
    """
    Network service running on a host.
    
    Represents a discovered service with port, protocol, version information,
    and any detected vulnerabilities.
    """
    Port: Optional[int] = Field(
        None,
        description="Port number (e.g., 80, 443, 8080)"
    )
    Protocol: Optional[str] = Field(
        None,
        description="Protocol (tcp, udp)"
    )
    State: Optional[str] = Field(
        None,
        description="Port state (open, closed, filtered)"
    )
    ServiceName: Optional[str] = Field(
        None,
        description="Service name (e.g., http, ssh, mysql)"
    )
    Product: Optional[str] = Field(
        None,
        description="Product name (e.g., Apache Tomcat, OpenSSH)"
    )
    Version: Optional[str] = Field(
        None,
        description="Product version (e.g., 5.5.23, 8.2p1)"
    )
    ExtraInfo: Optional[str] = Field(
        None,
        description="Additional service information (e.g., Java JDK 1.6.0_45)"
    )
    LastSeen: Optional[str] = Field(
        None,
        description="Timestamp when service was last detected"
    )
    Vulnerabilities: Optional[List[Vulnerability]] = Field(
        default=None,
        description="List of vulnerabilities detected on this service"
    )


# =============================================================================
# Host Models
# =============================================================================

class InputHost(BaseModel):
    """
    Input model for host exposure data from vulnerability scanners.
    
    This model represents a scanned host with network services and
    detected vulnerabilities. It supports hierarchical data from tools
    like Nmap, Nuclei, and other vulnerability scanners.
    
    Key Features:
        - Hierarchical structure (Host -> Services -> Vulnerabilities)
        - Rich vulnerability metadata (CVE, CVSS, EPSS, remediation)
        - Flexible optional fields for partial scan data
        - Type-safe nested models
    
    Example:
        >>> host = InputHost(
        ...     IpAddress="192.168.100.157",
        ...     Hostname="web-server",
        ...     Os="Linux 3.10 - 4.11",
        ...     Services=[
        ...         Service(
        ...             Port=8080,
        ...             ServiceName="http",
        ...             Product="Apache Tomcat",
        ...             Version="5.5.23",
        ...             Vulnerabilities=[...]
        ...         )
        ...     ]
        ... )
    """
    IpAddress: Optional[str] = Field(
        None,
        description="IP address of the host (IPv4 or IPv6)"
    )
    MacAddress: Optional[str] = Field(
        None,
        description="MAC address for network identification"
    )
    Os: Optional[str] = Field(
        None,
        description="Operating system detection (e.g., Linux 3.10 - 4.11, Windows Server 2019)"
    )
    Hostname: Optional[str] = Field(
        None,
        description="Hostname or FQDN"
    )
    LastSeen: Optional[str] = Field(
        None,
        description="Timestamp when host was last scanned"
    )
    Services: Optional[List[Service]] = Field(
        default=None,
        description="List of services running on the host"
    )
    
    class Config:
        """
        Pydantic model configuration with OpenAPI example.
        """
        json_schema_extra = {
            "example": {
                "IpAddress": "192.168.100.157",
                "MacAddress": "00:0C:29:3E:5B:4C",
                "Os": "Linux 3.10 - 4.11",
                "Hostname": "test-host",
                "LastSeen": "2025-11-07T07:28:14Z",
                "Services": [
                    {
                        "Port": 8080,
                        "Protocol": "tcp",
                        "State": "open",
                        "ServiceName": "http",
                        "Product": "Apache Tomcat/Coyote JSP engine 1.1",
                        "Version": "5.5.23",
                        "ExtraInfo": "Java JDK 1.6.0_45",
                        "LastSeen": "2025-11-07T07:28:14Z",
                        "Vulnerabilities": [
                            {
                                "template-id": "CVE-2017-5638",
                                "info": {
                                    "name": "Apache Struts 2 - Remote Command Execution",
                                    "severity": "critical",
                                    "classification": {
                                        "cve-id": ["cve-2017-5638"],
                                        "cvss-score": 10.0,
                                        "epss-score": 0.94267
                                    }
                                },
                                "host": "192.168.100.157:8080",
                                "port": "8080",
                                "matcher-status": True
                            }
                        ]
                    }
                ]
            }
        }

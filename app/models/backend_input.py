"""
Backend input models matching parameters.json EXACT structure.

All fields are Optional to support partial data from backend scanner.
Field aliases used for hyphenated names (template-id → template_id).
"""
from typing import List, Optional

from pydantic import BaseModel, Field


class VulnerabilityClassification(BaseModel):
    """CVE/CWE/CVSS classification data."""
    cve_id: Optional[List[str]] = Field(None, alias="cve-id")
    cwe_id: Optional[List[str]] = Field(None, alias="cwe-id")
    cvss_metrics: Optional[str] = Field(None, alias="cvss-metrics")
    cvss_score: Optional[float] = Field(None, alias="cvss-score")
    epss_score: Optional[float] = Field(None, alias="epss-score")
    epss_percentile: Optional[float] = Field(None, alias="epss-percentile")
    cpe: Optional[str] = None
    
    class Config:
        populate_by_name = True


class VulnerabilityMetadata(BaseModel):
    """Vulnerability metadata including search queries."""
    verified: Optional[bool] = None
    max_request: Optional[int] = Field(None, alias="max-request")
    vendor: Optional[str] = None
    product: Optional[str] = None
    shodan_query: Optional[List[str]] = Field(None, alias="shodan-query")
    fofa_query: Optional[List[str]] = Field(None, alias="fofa-query")
    google_query: Optional[str] = Field(None, alias="google-query")
    
    class Config:
        populate_by_name = True


class VulnerabilityInfo(BaseModel):
    """Detailed vulnerability information."""
    name: Optional[str] = None
    author: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    reference: Optional[List[str]] = None
    severity: Optional[str] = None
    metadata: Optional[VulnerabilityMetadata] = None
    classification: Optional[VulnerabilityClassification] = None
    remediation: Optional[str] = None


class VulnerabilityMeta(BaseModel):
    """Detection-specific metadata."""
    params: Optional[str] = None


class Vulnerability(BaseModel):
    """Full vulnerability detection matching parameters.json structure."""
    template: Optional[str] = None
    template_id: Optional[str] = Field(None, alias="template-id")
    info: Optional[VulnerabilityInfo] = None
    type: Optional[str] = None
    host: Optional[str] = None
    port: Optional[str] = None
    scheme: Optional[str] = None
    url: Optional[str] = None
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    matcher_status: Optional[bool] = Field(None, alias="matcher-status")
    meta: Optional[VulnerabilityMeta] = None
    
    class Config:
        populate_by_name = True


class Service(BaseModel):
    """Service information matching parameters.json structure."""
    Port: Optional[int] = None
    Protocol: Optional[str] = None
    State: Optional[str] = None
    ServiceName: Optional[str] = None
    Product: Optional[str] = None
    Version: Optional[str] = None
    ExtraInfo: Optional[str] = None
    LastSeen: Optional[str] = None
    Vulnerabilities: Optional[List[Vulnerability]] = None


class Target(BaseModel):
    """Target information matching parameters.json structure."""
    IpAddress: Optional[str] = None
    MacAddress: Optional[str] = None
    Os: Optional[str] = None
    Hostname: Optional[str] = None
    LastSeen: Optional[str] = None
    Services: Optional[List[Service]] = None


class BackendInput(BaseModel):
    """
    Root model - array of targets matching parameters.json.
    
    CONTRACT NOTE:
    - The engine supports multiple targets in the schema for future flexibility.
    - However, the collector contract is: one host per request (targets will contain exactly one item).
    - All attack paths will be generated for that single host unless the input explicitly contains multiple targets.
    """
    targets: List[Target] = Field(..., description="Array of target hosts")

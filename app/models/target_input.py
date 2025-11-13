"""
Simple target input model for attack path generation.

Matches the 5-parameter specification with no bias or hardcoded assumptions.
"""
from typing import List
from pydantic import BaseModel, Field


class VulnerabilityInfo(BaseModel):
    """Simple vulnerability information."""
    cve: str = Field(..., description="CVE identifier")
    score: str = Field(..., description="CVSS or severity score")


class ExposureInfo(BaseModel):
    """Target exposure information."""
    is_internet_exposed: str = Field(..., description="Whether target is internet-facing")
    has_legacy_os: str = Field(..., description="Whether running legacy OS")
    has_admin_shares: str = Field(..., description="Whether admin shares are accessible")


class TargetInput(BaseModel):
    """
    Simple input model for attack path generation.
    
    No bias, no hardcoded assumptions - just 5 clean parameters.
    """
    open_ports: List[str] = Field(
        ...,
        description="List of open ports on the target"
    )
    services: List[str] = Field(
        ...,
        description="List of running services"
    )
    applications: List[str] = Field(
        ...,
        description="List of applications detected"
    )
    vulnerabilities: List[VulnerabilityInfo] = Field(
        ...,
        description="List of identified vulnerabilities"
    )
    exposure: ExposureInfo = Field(
        ...,
        description="Target exposure information"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "open_ports": ["22", "80", "443"],
                "services": ["ssh", "http", "https"],
                "applications": ["apache", "openssh"],
                "vulnerabilities": [
                    {"cve": "CVE-2021-3156", "score": "7.8"},
                    {"cve": "CVE-2021-44228", "score": "10.0"}
                ],
                "exposure": {
                    "is_internet_exposed": "true",
                    "has_legacy_os": "false",
                    "has_admin_shares": "false"
                }
            }
        }

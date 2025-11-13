"""
Complete analysis data models.

This module defines data structures for the complete 7-stage attack path analysis.

Models:
    - StageAnalysis: Structured analysis of a single attack stage
    - CompleteAnalysisResponse: Complete analysis response with 7 stages
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class StageAnalysis(BaseModel):
    """
    Structured analysis of a single attack stage.
    
    Represents one stage of the 7-stage Cyber Kill Chain with all
    relevant context, techniques, tools, and detailed narrative content.
    
    This model enables both structured data consumption (JSON) and
    narrative-based consumption (Markdown conversion).
    
    Attributes:
        stage_index: Stage number in the kill chain (1-7)
        stage_name: Kill chain stage name (Reconnaissance, Weaponization, etc.)
        phase: Phase description (Information Gathering, Payload Creation, etc.)
        mitre_techniques: List of applicable MITRE ATT&CK technique IDs
        summary: One-sentence summary of what happens in this stage
        key_findings: Bulleted findings/discoveries specific to target
        tools_used: Tools employed in this stage (nmap, Metasploit, etc.)
        artifact_name: Name of any malware/tool deployed (if applicable)
        artifact_type: Type of artifact (Windows PE, shell script, etc.)
        commands: Shell/console commands executed in this stage
        content: Full detailed narrative content for this stage
    """
    stage_index: int = Field(
        ...,
        description="Stage number in the kill chain (1-7)",
        ge=1,
        le=7
    )
    stage_name: str = Field(
        ...,
        description="Name of the kill chain stage",
        examples=["Reconnaissance", "Weaponization", "Delivery", "Exploitation", 
                  "Installation", "Command & Control", "Actions on Objectives"]
    )
    phase: str = Field(
        ...,
        description="Phase description",
        examples=["Information Gathering", "Payload Creation", "Persistence"]
    )
    mitre_techniques: List[str] = Field(
        default=[],
        description="List of MITRE ATT&CK technique IDs (e.g., T1595, T1592)",
        examples=[["T1595", "T1592", "T1598"], ["T1203", "T1587.001"]]
    )
    summary: str = Field(
        ...,
        description="One-sentence summary of stage activity",
        examples=["Passive reconnaissance revealed open ports 139 and 445 exposing SMB service"]
    )
    key_findings: List[str] = Field(
        default=[],
        description="Bulleted findings specific to the target",
        examples=[["Port 139 exposed", "Port 445 exposed", "MS17-010 vulnerability identified"]]
    )
    tools_used: List[str] = Field(
        default=[],
        description="Tools employed in this stage",
        examples=[["nmap", "shodan"], ["msfconsole", "msfvenom"]]
    )
    artifact_name: Optional[str] = Field(
        default=None,
        description="Name of any malware/payload deployed (if applicable)",
        examples=["eternalblue_payload.exe", "reverse_shell.sh"]
    )
    artifact_type: Optional[str] = Field(
        default=None,
        description="Type of artifact",
        examples=["Windows PE Executable", "Shell Script", "Python Script"]
    )
    commands: List[str] = Field(
        default=[],
        description="Shell/console commands executed in this stage",
        examples=[["msfconsole", "use exploit/windows/smb/ms17_010_eternalblue"]]
    )
    content: str = Field(
        ...,
        description="Full detailed narrative content describing the stage",
        examples=["Full detailed stage content here..."]
    )


class CompleteAnalysisResponse(BaseModel):
    """
    Complete attack path analysis response.
    
    Output from POST /attack-path/main endpoint.
    Contains the primary 7-stage attack path with structured data and
    continuity validation results.
    
    This is the PRIMARY production endpoint response format.
    
    Attributes:
        request_id: Unique identifier for this analysis request
        primary_path: The 7-stage primary attack path (structured StageAnalysis objects)
        total_paths: Always 1 (primary path only)
        execution_time_seconds: Total time taken for analysis
        llm_calls: Breakdown of LLM calls made
        estimated_cost: Estimated cost in USD for this analysis
        validation_report: NEW - Continuity validation results across stages
    """
    request_id: str = Field(
        ...,
        description="Unique identifier for this analysis request (UUID)",
        examples=["550e8400-e29b-41d4-a716-446655440000"]
    )
    primary_path: List[StageAnalysis] = Field(
        ...,
        description="The 7-stage primary attack path (structured stage objects)",
        min_length=7,
        max_length=7
    )
    total_paths: int = Field(
        ...,
        description="Total number of attack paths (always 1 - primary path only)",
        ge=1,
        examples=[1]
    )
    execution_time_seconds: float = Field(
        ...,
        description="Total execution time in seconds",
        ge=0,
        examples=[23.4, 28.7, 31.2]
    )
    llm_calls: Dict[str, int] = Field(
        ...,
        description="Breakdown of LLM calls made during analysis",
        examples=[{
            "total": 7
        }]
    )
    estimated_cost: float = Field(
        ...,
        description="Estimated cost in USD for this complete analysis",
        ge=0,
        examples=[0.051, 0.068, 0.075]
    )
    validation_report: Optional[Dict[str, Any]] = Field(
        default=None,
        description="NEW - Continuity validation results across all stages",
        examples=[{
            "is_valid": True,
            "total_checks": 10,
            "passes": [{"stage": 3, "check": "artifact_continuity", "result": "PASS"}],
            "warnings": [],
            "stage_artifacts": {1: None, 2: "eternalblue_payload.exe", 3: "eternalblue_payload.exe", 4: None, 5: "eternalblue_payload.exe", 6: None, 7: None}
        }]
    )

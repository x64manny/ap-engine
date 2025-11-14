"""
Attack path output models with MITRE ATT&CK structure.

Defines the structured JSON schema that the LLM must return.
"""
from typing import List, Optional

from pydantic import BaseModel, Field


class AttackPathStep(BaseModel):
    """
    Single step in a MITRE ATT&CK chain.
    """
    stage: str = Field(
        ...,
        description="Attack stage, e.g. 'Initial Access', 'Execution', 'Privilege Escalation'"
    )
    tactic: Optional[str] = Field(
        None,
        description="MITRE ATT&CK tactic, e.g. 'TA0001 Initial Access'"
    )
    technique_id: str = Field(
        ...,
        description="MITRE ATT&CK technique ID, e.g. 'T1190'"
    )
    technique_name: Optional[str] = Field(
        None,
        description="MITRE ATT&CK technique name, e.g. 'Exploit Public-Facing Application'"
    )
    description: str = Field(
        ...,
        description="What the attacker does at this step, grounded in the environment"
    )
    defensive_context: Optional[str] = Field(
        None,
        description="How defenders can prevent or reduce this step"
    )
    detection_ideas: Optional[str] = Field(
        None,
        description="How defenders could detect this step"
    )


class AttackPath(BaseModel):
    """
    Complete attack path from initial access to objective.
    """
    id: str = Field(
        ...,
        description="Attack path identifier, e.g. 'AP-1', 'AP-2'"
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Risk score between 0.0 and 1.0"
    )
    risk_level: str = Field(
        ...,
        description="Risk level: 'Low', 'Medium', 'High', or 'Critical'"
    )
    justification: str = Field(
        ...,
        description="Why this path matters for this specific environment"
    )
    targets_involved: List[str] = Field(
        ...,
        description="Hostnames or IP addresses involved in this attack path"
    )
    mitre_chain: List[AttackPathStep] = Field(
        ...,
        description="Ordered sequence of MITRE ATT&CK techniques"
    )


class AttackPathResult(BaseModel):
    """
    Collection of attack paths generated for the environment.
    """
    attack_paths: List[AttackPath] = Field(
        ...,
        description="1 to 3 realistic attack paths for this environment"
    )

"""
Response models for attack path generation.
"""
from pydantic import BaseModel, Field

from app.models.attack_path_models import AttackPathResult


class AttackPathResponse(BaseModel):
    """
    Response containing structured attack paths with metadata.
    """
    request_id: str = Field(
        ...,
        description="Unique identifier for this request"
    )
    attack_path_result: AttackPathResult = Field(
        ...,
        description="Structured attack paths with MITRE ATT&CK mapping"
    )
    execution_time_seconds: float = Field(
        ...,
        description="Time taken to generate the attack paths"
    )
    estimated_cost_usd: float = Field(
        default=0.0,
        description="Estimated cost of the LLM call"
    )

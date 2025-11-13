"""
Simple response model for attack path generation.

No complex stage models or validation - just the attack path.
"""
from pydantic import BaseModel, Field


class AttackPathResponse(BaseModel):
    """
    Simple response containing the generated attack path.
    """
    request_id: str = Field(
        ...,
        description="Unique identifier for this request"
    )
    attack_path: str = Field(
        ...,
        description="Generated attack path based on target parameters"
    )
    execution_time_seconds: float = Field(
        ...,
        description="Time taken to generate the attack path"
    )
    estimated_cost_usd: float = Field(
        default=0.0,
        description="Estimated cost of the LLM call"
    )

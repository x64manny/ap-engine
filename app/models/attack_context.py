"""
Attack context model for stage-level prompting with continuity preservation.

Provides the shared context object that threads through all 7 Kill Chain stages,
accumulating outputs to maintain logical continuity across independent LLM calls.
"""
from pydantic import BaseModel
from typing import Optional, Dict, Any


class AttackContext(BaseModel):
    """
    Shared context threading through all 7 Cyber Kill Chain stages.
    
    Each stage reads all prior outputs before generating its own output,
    ensuring logical continuity and consistency across the attack path.
    
    This model serves as the continuity backbone - each stage reads it,
    adds its outputs, and passes the enriched context to the next stage.
    """
    
    # Host data (constant throughout all stages)
    host_data: Dict[str, Any]  # Serialized InputHost
    
    # Stage outputs accumulate here
    reconnaissance: Optional[str] = None
    weaponization: Optional[str] = None
    delivery: Optional[str] = None
    exploitation: Optional[str] = None
    installation: Optional[str] = None
    command_and_control: Optional[str] = None
    actions_on_objectives: Optional[str] = None
    
    # NEW: Track artifacts across stages for continuity validation
    stage_artifacts: Dict[int, Optional[str]] = {
        1: None,  # Reconnaissance (no artifacts)
        2: None,  # Weaponization (critical!)
        3: None,  # Delivery
        4: None,  # Exploitation
        5: None,  # Installation (must reference Stage 2)
        6: None,  # C2
        7: None   # Actions on Objectives
    }
    
    class Config:
        arbitrary_types_allowed = True

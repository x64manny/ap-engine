"""
Attack path generator service for backend scanner data.

Structured JSON output with MITRE ATT&CK alignment.
"""
import time
import uuid

from app.config import settings
from app.core.prompts import ATTACK_PATH_SYSTEM_PROMPT, build_attack_path_user_prompt
from app.models.attack_path_models import AttackPathResult
from app.models.backend_input import BackendInput
from app.models.response import AttackPathResponse
from app.services.llm_client import LLMClient
from app.utils.token_logger import get_token_logger


class AttackPathGenerator:
    """
    Attack path generator using structured JSON output with MITRE ATT&CK.
    
    Converts unstructured vulnerability data into validated attack path chains.
    """
    
    def __init__(self):
        """Initialize the generator."""
        self.llm_client = LLMClient()
        self.token_logger = get_token_logger()
    
    async def generate(self, backend_input: BackendInput) -> AttackPathResponse:
        """
        Generate structured attack paths for the given backend scanner data.
        
        Args:
            backend_input: Backend input with array of targets
            
        Returns:
            AttackPathResponse with validated attack paths
        """
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        print(f"\n{'='*60}")
        print("Generating Attack Paths")
        print(f"Request ID: {request_id}")
        print(f"{'='*60}\n")
        
        # Build structured prompts
        system_message = ATTACK_PATH_SYSTEM_PROMPT
        user_prompt = build_attack_path_user_prompt(backend_input)
        
        # Call LLM with JSON mode enabled
        print("Calling LLM (JSON mode enabled)...")
        response = await self.llm_client.complete(
            system_message=system_message,
            user_prompt=user_prompt,
            json_mode=True
        )
        
        # Extract and validate attack paths
        print("Validating attack path structure...")
        try:
            # Debug: Log raw LLM response
            print(f"DEBUG: RAW LLM JSON:\n{response}\n")
            
            # Parse and validate against Pydantic model
            attack_path_result = AttackPathResult.model_validate(response)
            
            print(f"✓ Generated {len(attack_path_result.attack_paths)} attack path(s)")
            for ap in attack_path_result.attack_paths:
                print(f"  - {ap.id}: {ap.risk_level} risk, {len(ap.mitre_chain)} steps")
            
        except Exception as e:
            print(f"✗ Validation failed: {e}")
            print(f"DEBUG: Response keys: {response.keys() if isinstance(response, dict) else type(response)}")
            raise ValueError(f"LLM returned invalid attack path structure: {e}")
        
        execution_time = time.time() - start_time
        
        # Extract token usage
        usage = response.get("usage", {})
        tokens_input = usage.get("prompt_tokens", 0)
        tokens_output = usage.get("completion_tokens", 0)
        
        # Log the call
        self.token_logger.log_call(
            request_id=request_id,
            call_type="attack_path_generation",
            model=settings.LLM_MODEL,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            response_time_ms=int(execution_time * 1000)
        )
        
        # Estimate cost (simple approximation)
        estimated_cost = (tokens_input / 1000 * 0.00015) + (tokens_output / 1000 * 0.0006)
        
        print(f"\n{'='*60}")
        print("Attack Paths Generated!")
        print(f"  Execution Time: {execution_time:.2f}s")
        print(f"  Tokens: {tokens_input + tokens_output}")
        print(f"  Estimated Cost: ${estimated_cost:.4f}")
        print(f"{'='*60}\n")
        
        return AttackPathResponse(
            request_id=request_id,
            attack_path_result=attack_path_result,
            execution_time_seconds=round(execution_time, 2),
            estimated_cost_usd=round(estimated_cost, 4)
        )

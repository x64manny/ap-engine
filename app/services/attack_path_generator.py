"""
Simple attack path generator service.

Single LLM call - no complex multi-stage workflows, no continuity validation.
"""
import time
import uuid
from app.models.target_input import TargetInput
from app.models.response import AttackPathResponse
from app.core.prompts import PromptBuilder
from app.services.llm_client import LLMClient
from app.utils.token_logger import get_token_logger
from app.config import settings


class AttackPathGenerator:
    """
    Simple attack path generator using a single LLM call.
    
    No bias, no hardcoded stages, no complex workflows.
    """
    
    def __init__(self):
        """Initialize the generator."""
        self.prompt_builder = PromptBuilder()
        self.llm_client = LLMClient()
        self.token_logger = get_token_logger()
    
    async def generate(self, target: TargetInput) -> AttackPathResponse:
        """
        Generate an attack path for the given target.
        
        Args:
            target: Target input with 5 parameters
            
        Returns:
            AttackPathResponse with generated attack path
        """
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        print(f"\n{'='*60}")
        print("Generating Attack Path")
        print(f"Request ID: {request_id}")
        print(f"{'='*60}\n")
        
        # Build prompt
        prompt = self.prompt_builder.build_prompt(target)
        
        # Simple system message - no bias
        system_message = (
            "You are a cybersecurity expert specialized in attack path analysis. "
            "Generate realistic, detailed attack paths based on the provided target information."
        )
        
        # Single LLM call
        print("Calling LLM...")
        response = await self.llm_client.complete(
            system_message=system_message,
            user_prompt=prompt,
            json_mode=False
        )
        
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
        print("Attack Path Generated!")
        print(f"  Execution Time: {execution_time:.2f}s")
        print(f"  Tokens: {tokens_input + tokens_output}")
        print(f"  Estimated Cost: ${estimated_cost:.4f}")
        print(f"{'='*60}\n")
        
        return AttackPathResponse(
            request_id=request_id,
            attack_path=response.get("content", ""),
            execution_time_seconds=round(execution_time, 2),
            estimated_cost_usd=round(estimated_cost, 4)
        )

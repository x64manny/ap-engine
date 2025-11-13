"""
LLM client for communication with language models.

This module provides a unified interface for interacting with multiple LLM
providers through LiteLLM. It abstracts away provider-specific details and
provides a consistent API for AI model calls.

Architecture Role:
    - Infrastructure Layer component
    - Handles all external LLM API interactions
    - Isolates LLM-specific logic from business logic
    - Makes the application provider-agnostic

Supported Providers (via LiteLLM):
    - OpenAI (GPT-4, GPT-4o, GPT-3.5)
    - Anthropic (Claude 3 Opus, Sonnet, Haiku)
    - Google (Gemini Pro, Gemini 1.5 Pro)
    - Azure OpenAI
    - AWS Bedrock
    - Cohere
    - Ollama (local models)
    - And 100+ more providers

Usage:
    >>> client = LLMClient()
    >>> result = await client.complete(
    ...     system_message="You are a security expert",
    ...     user_prompt="Analyze this vulnerability...",
    ...     json_mode=True
    ... )
    >>> print(result["attack_path"])
"""
import json
from typing import Dict, Any
import litellm
from app.config import settings


# =============================================================================
# LLM Client Class
# =============================================================================

class LLMClient:
    """
    Client for interacting with LLM providers via LiteLLM.
    
    This class serves as an abstraction layer over LiteLLM, providing a
    clean interface for sending prompts to AI models and receiving structured
    responses. It handles configuration, request formatting, and response parsing.
    
    The client is provider-agnostic - simply change the LLM_MODEL environment
    variable to switch between OpenAI, Anthropic, Google, or any other provider.
    
    Attributes:
        model (str): LLM model identifier (e.g., "gpt-4o-mini", "claude-3-sonnet")
        temperature (float): Sampling temperature for generation (0.0-2.0)
    
    Example:
        >>> client = LLMClient()
        >>> print(client.model)
        'gpt-4o-mini'
        >>> print(client.temperature)
        0.7
    """
    
    def __init__(self):
        """
        Initialize the LLM client with configuration from settings.
        
        Loads model and temperature settings from environment variables
        via the Settings class. This allows runtime configuration without
        code changes.
        
        Configuration:
            - Model: Set via LLM_MODEL env var (default: gpt-4o-mini)
            - Temperature: Set via LLM_TEMPERATURE env var (default: 0.7)
        
        Note:
            API keys are automatically loaded by LiteLLM from environment
            variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
        """
        # Load model identifier from configuration
        # Examples: "gpt-4o-mini", "claude-3-5-sonnet-20241022", "gemini/gemini-pro"
        self.model = settings.LLM_MODEL
        
        # Load temperature for controlling response creativity
        # 0.0 = deterministic, 0.7 = balanced, 2.0 = highly creative
        self.temperature = settings.LLM_TEMPERATURE
    
    async def complete(
        self, 
        system_message: str, 
        user_prompt: str,
        json_mode: bool = True
    ) -> Dict[str, Any]:
        """
        Send a completion request to the LLM and return the response.
        
        This method handles the entire LLM interaction workflow:
        1. Formats messages in the chat completion format
        2. Configures request parameters (model, temperature, JSON mode)
        3. Calls LiteLLM's async completion API
        4. Extracts and parses the response
        5. Returns structured data
        
        The method uses async/await for non-blocking I/O, allowing the
        application to handle multiple concurrent requests efficiently.
        
        Args:
            system_message (str): System role message that defines the AI's behavior
                and expertise. This sets the context for the entire conversation.
                Example: "You are a MITRE ATT&CK expert specializing in..."
                
            user_prompt (str): The actual prompt containing the task and data.
                This is the dynamic, request-specific content built by PromptBuilder.
                Example: "Generate attack path for: Linux Ubuntu 20.04 with..."
                
            json_mode (bool, optional): Whether to request JSON-formatted response.
                When True, instructs the LLM to return valid JSON that can be parsed.
                Defaults to True for structured attack path responses.
        
        Returns:
            Dict[str, Any]: Parsed response from the LLM
                - If json_mode=True: Returns parsed JSON dict (e.g., {"attack_path": [...], "risk_level": "..."})
                - If json_mode=False: Returns dict with "content" key containing raw text
        
        Raises:
            json.JSONDecodeError: If json_mode=True but LLM returns invalid JSON.
                This can happen if the model doesn't support JSON mode or fails
                to generate valid JSON.
                
            litellm.exceptions.APIError: If the LLM API call fails (network error,
                rate limit, authentication error, etc.)
                
            Exception: For other unexpected errors during LLM interaction
        
        Example:
            >>> client = LLMClient()
            >>> result = await client.complete(
            ...     system_message="You are a security expert",
            ...     user_prompt="Analyze vulnerability: CVE-2023-12345",
            ...     json_mode=True
            ... )
            >>> print(result["risk_level"])
            'Critical'
        
        Notes:
            - Typical response time: 2-5 seconds (varies by model and prompt size)
            - Token limits vary by model (see LiteLLM docs for specifics)
            - JSON mode is supported by most modern models (GPT-4, Claude 3, etc.)
            - Some models may ignore json_mode - handle parsing errors gracefully
        """
        # =================================================================
        # Step 1: Format messages for chat completion API
        # =================================================================
        
        # Structure messages in OpenAI chat format (used by most providers)
        # System message establishes the AI's role and expertise
        # User message contains the actual task and context
        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_prompt}
        ]
        
        # =================================================================
        # Step 2: Build request parameters
        # =================================================================
        
        # Configure the LLM API request
        # LiteLLM automatically routes to the correct provider based on model name
        request_params = {
            "model": self.model,           # Which AI model to use
            "messages": messages,          # The conversation messages
            "temperature": self.temperature # Creativity/randomness level
        }
        
        # =================================================================
        # Step 3: Add JSON mode if requested
        # =================================================================
        
        # JSON mode instructs the LLM to return valid JSON
        # This is crucial for structured responses like attack paths
        # Format follows OpenAI's response_format specification
        if json_mode:
            request_params["response_format"] = {"type": "json_object"}
        
        # =================================================================
        # Step 4: Call LLM API (async, non-blocking)
        # =================================================================
        
        # LiteLLM handles provider-specific API differences
        # Automatically uses the correct API endpoint, auth, and format
        # The 'await' keyword makes this non-blocking - other requests can proceed
        response = await litellm.acompletion(**request_params)
        
        # =================================================================
        # Step 5: Extract content from response
        # =================================================================
        
        # LLM responses follow the OpenAI format:
        # response.choices[0].message.content contains the actual text
        # [0] gets the first (and usually only) completion
        content = response.choices[0].message.content
        
        # =================================================================
        # Step 6: Parse and return response
        # =================================================================
        
        # Extract token usage if available
        tokens_used = {}
        if hasattr(response, 'usage') and response.usage:
            tokens_used = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens
            }
        
        # If JSON mode was requested, parse the JSON string
        # This converts the string response into a Python dict
        if json_mode:
            parsed = json.loads(content)
            parsed["usage"] = tokens_used
            return parsed
        
        # If JSON mode wasn't requested, wrap raw text in a dict
        # This ensures a consistent return type (always a dict)
        return {"content": content, "usage": tokens_used}

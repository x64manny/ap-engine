"""
Configuration management for the Attack Path Engine.

This module centralizes all environment variables and application settings,
following the 12-factor app methodology for configuration management.

Environment Variables:
    - OPENAI_API_KEY: Required LLM API key (or provider-specific key)
    - LLM_MODEL: AI model to use (default: gpt-4o-mini)
    - LLM_TEMPERATURE: Creativity level 0.0-2.0 (default: 0.7)

Usage:
    >>> from app.config import settings
    >>> print(settings.LLM_MODEL)
    'gpt-4o-mini'
    
Notes:
    - Settings are loaded once at application startup
    - Uses .env file for local development
    - Environment variables override .env values
    - Supports multiple LLM providers via LiteLLM
"""
import os
from dotenv import load_dotenv

# =============================================================================
# Environment Loading
# =============================================================================

# Load environment variables from .env file (if it exists)
# In production, use actual environment variables instead of .env
# The .env file is gitignored and should never be committed
load_dotenv()


# =============================================================================
# Settings Class
# =============================================================================

class Settings:
    """
    Application settings loaded from environment variables.
    
    This class serves as a centralized configuration store for the entire
    application. All settings are loaded from environment variables to
    support different deployment environments (dev, staging, prod).
    
    Attributes:
        API_TITLE (str): FastAPI application title
        API_VERSION (str): API version for documentation
        LLM_MODEL (str): Language model identifier for LiteLLM
        LLM_TEMPERATURE (float): Temperature for LLM generation (0.0-2.0)
        OPENAI_API_KEY (str): API key for LLM provider
    
    Example:
        >>> settings = Settings()
        >>> settings.validate()  # Raises ValueError if required keys missing
    """
    
    # =========================================================================
    # API Configuration
    # =========================================================================
    
    # FastAPI application metadata
    # These appear in the OpenAPI docs at /docs
    API_TITLE: str = "Attack Path Engine"
    API_VERSION: str = "1.0.0"
    
    # =========================================================================
    # LLM Configuration
    # =========================================================================
    
    # Model identifier for LiteLLM
    # Supports 100+ providers with different model formats:
    # - OpenAI: "gpt-4o", "gpt-4o-mini", "gpt-4-turbo"
    # - Anthropic: "claude-3-5-sonnet-20241022", "claude-3-opus-20240229"
    # - Google: "gemini/gemini-pro", "gemini/gemini-1.5-pro"
    # - Azure: "azure/gpt-4", "azure/gpt-35-turbo"
    # - Ollama (local): "ollama/llama2", "ollama/mistral"
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o-mini")
    
    # Temperature controls randomness/creativity in LLM responses
    # - 0.0 = Deterministic, focused, consistent (good for production)
    # - 0.7 = Balanced creativity and consistency (recommended)
    # - 1.0+ = More creative and varied (good for diverse scenarios)
    # - 2.0 = Maximum creativity (may be less accurate)
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.7"))
    
    # =========================================================================
    # API Keys (Provider-Specific)
    # =========================================================================
    
    # OpenAI API Key (required by default)
    # Get your key from: https://platform.openai.com/api-keys
    # Format: sk-proj-...
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    
    # Alternative providers (uncomment if using):
    # ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    # GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY", "")
    # AZURE_API_KEY: str = os.getenv("AZURE_API_KEY", "")
    # COHERE_API_KEY: str = os.getenv("COHERE_API_KEY", "")
    
    # =========================================================================
    # Validation
    # =========================================================================
    
    @classmethod
    def validate(cls):
        """
        Validate that all required configuration is present.
        
        This method should be called at application startup to fail fast
        if critical configuration is missing.
        
        Raises:
            ValueError: If OPENAI_API_KEY is not set
            
        Example:
            >>> settings.validate()  # Raises if API key missing
            
        Notes:
            - Only validates OpenAI key by default
            - Add validation for other providers if using them
            - Consider using pydantic-settings for more robust validation
        """
        if not cls.OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY environment variable is required. "
                "Get your API key from https://platform.openai.com/api-keys "
                "and set it in your .env file or environment variables."
            )


# =============================================================================
# Global Settings Instance
# =============================================================================

# Create a singleton settings instance that's imported throughout the app
# This ensures configuration is loaded once and shared across all modules
settings = Settings()

# Optionally validate at import time (commented out to allow testing without keys)
# Uncomment for production to fail fast on missing configuration:
# settings.validate()

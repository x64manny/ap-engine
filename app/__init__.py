"""
Attack Path Engine - AI-powered vulnerability to attack path analysis.

This package implements a complete attack path generation system that transforms
vulnerability and asset data into realistic 7-stage attack sequences using AI.

Architecture:
    - Clean architecture pattern (Presentation → Services → Core → Models → Utils)
    - FastAPI for REST API
    - LiteLLM for multi-provider LLM support
    - Pydantic for data validation
    - Token logging for cost tracking

Main Entry Point:
    - app.main: FastAPI application with REST endpoints
    
Key Components:
    - app.services.complete_analyzer: PRIMARY production service for 7-stage analysis
    - app.services.llm_client: LLM provider abstraction (LiteLLM)
    - app.models: Data validation models (InputHost, CompleteAnalysisResponse)
    - app.utils.token_logger: Token usage tracking for cost analysis
    - app.core.prompts: Dynamic prompt building

Usage:
    >>> from app.main import app
    >>> # Start server: uvicorn app.main:app --reload

See Also:
    - FINAL_PASS_SUMMARY.md: Recent fixes and verification results
    - docs/: API documentation and integration guides
"""

__version__ = "1.0.0"
__author__ = "Security Team"
__all__ = ["main"]

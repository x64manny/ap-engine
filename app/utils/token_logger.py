"""
Token usage logger for LLM API calls.

Logs all LLM API calls with token usage, cost estimates, and performance metrics
to JSON Lines format for analysis and monitoring.

Features:
    - Per-request tracking with unique request_id
    - Call type categorization (primary_path, bifurcation_detection, branch_X)
    - Token usage tracking (input/output/total)
    - Cost estimation per model
    - Response time tracking
    - Automatic log rotation (10MB files, 5 backups)

Log Format:
    JSON Lines (.jsonl) with one JSON object per line:
    {
        "timestamp": "2025-01-15T10:30:45.123Z",
        "request_id": "550e8400-e29b-41d4-a716-446655440000",
        "call_type": "primary_path",
        "model": "gpt-4",
        "tokens_input": 2500,
        "tokens_output": 850,
        "tokens_total": 3350,
        "response_time_ms": 5432,
        "cost_estimate_usd": 0.0201
    }
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict
from logging.handlers import RotatingFileHandler


class TokenLogger:
    """
    Logs token usage and cost estimates for LLM API calls.
    
    Writes structured JSON Lines logs with automatic rotation.
    Designed for easy parsing, analysis, and cost monitoring.
    """
    
    # Cost per 1K tokens (as of 2025, approximate)
    MODEL_COSTS = {
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        "claude-3-opus": {"input": 0.015, "output": 0.075},
        "claude-3-sonnet": {"input": 0.003, "output": 0.015},
    }
    
    def __init__(
        self,
        log_dir: str = "logs",
        log_file: str = "token_usage.jsonl",
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5
    ):
        """
        Initialize the token logger.
        
        Args:
            log_dir: Directory for log files
            log_file: Log filename
            max_bytes: Maximum file size before rotation (default 10MB)
            backup_count: Number of backup files to keep (default 5)
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.log_path = self.log_dir / log_file
        
        # Set up rotating file handler
        self.logger = logging.getLogger("token_usage")
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        self.logger.handlers.clear()
        
        # Add rotating file handler
        handler = RotatingFileHandler(
            self.log_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)
    
    def log_call(
        self,
        request_id: str,
        call_type: str,
        model: str,
        tokens_input: int,
        tokens_output: int,
        response_time_ms: int,
        metadata: Optional[Dict] = None
    ) -> None:
        """
        Log an LLM API call with token usage and cost estimate.
        
        Args:
            request_id: Unique identifier for the request (UUID)
            call_type: Type of call (primary_path, bifurcation_detection, branch_B1, etc.)
            model: Model name (gpt-4, gpt-3.5-turbo, etc.)
            tokens_input: Number of input tokens
            tokens_output: Number of output tokens
            response_time_ms: Response time in milliseconds
            metadata: Optional additional metadata to include
        """
        tokens_total = tokens_input + tokens_output
        cost_estimate = self._estimate_cost(model, tokens_input, tokens_output)
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "request_id": request_id,
            "call_type": call_type,
            "model": model,
            "tokens_input": tokens_input,
            "tokens_output": tokens_output,
            "tokens_total": tokens_total,
            "response_time_ms": response_time_ms,
            "cost_estimate_usd": round(cost_estimate, 4)
        }
        
        if metadata:
            log_entry["metadata"] = metadata
        
        self.logger.info(json.dumps(log_entry))
    
    def _estimate_cost(
        self,
        model: str,
        tokens_input: int,
        tokens_output: int
    ) -> float:
        """
        Estimate cost for an LLM API call.
        
        Args:
            model: Model name
            tokens_input: Number of input tokens
            tokens_output: Number of output tokens
        
        Returns:
            Estimated cost in USD
        """
        # Get model costs (default to gpt-4 if unknown)
        costs = self.MODEL_COSTS.get(model, self.MODEL_COSTS["gpt-4"])
        
        # Calculate cost: (input_tokens / 1000) * input_cost + (output_tokens / 1000) * output_cost
        input_cost = (tokens_input / 1000) * costs["input"]
        output_cost = (tokens_output / 1000) * costs["output"]
        
        return input_cost + output_cost


# Global logger instance
_token_logger: Optional[TokenLogger] = None


def get_token_logger() -> TokenLogger:
    """
    Get the global token logger instance.
    
    Returns:
        TokenLogger instance (singleton)
    """
    global _token_logger
    if _token_logger is None:
        _token_logger = TokenLogger()
    return _token_logger

"""
FastAPI application - Simple attack path generation API.

Single endpoint with no bias or hardcoded methodologies.
"""
from fastapi import FastAPI
from app.config import settings
from app.models import TargetInput, AttackPathResponse
from app.services.attack_path_generator import AttackPathGenerator


# Initialize FastAPI app
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="Simple AI-powered attack path generator"
)


@app.get("/health")
def health():
    """
    Health check endpoint.
    
    Returns:
        Service status and configuration
    """
    return {
        "status": "ok",
        "version": settings.API_VERSION,
        "model": settings.LLM_MODEL
    }


@app.post("/generate", response_model=AttackPathResponse)
async def generate_attack_path(target: TargetInput) -> AttackPathResponse:
    """
    Generate attack path for a target.
    
    Args:
        target: Target with 5 parameters (open_ports, services, applications, 
                vulnerabilities, exposure)
    
    Returns:
        AttackPathResponse with generated attack path
        
    Example:
        >>> response = requests.post("/generate", json={
        ...     "open_ports": ["22", "80", "443"],
        ...     "services": ["ssh", "http", "https"],
        ...     "applications": ["apache", "openssh"],
        ...     "vulnerabilities": [
        ...         {"cve": "CVE-2021-3156", "score": "7.8"}
        ...     ],
        ...     "exposure": {
        ...         "is_internet_exposed": "true",
        ...         "has_legacy_os": "false",
        ...         "has_admin_shares": "false"
        ...     }
        ... })
    """
    generator = AttackPathGenerator()
    result = await generator.generate(target)
    return result

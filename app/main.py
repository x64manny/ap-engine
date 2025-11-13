"""
FastAPI application - Attack path generation API for backend scanner data.
"""
from fastapi import FastAPI

from app.config import settings
from app.models import AttackPathResponse, BackendInput
from app.services.attack_path_generator import AttackPathGenerator

# Initialize FastAPI app
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="AI-powered attack path generator for backend scanner data"
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
async def generate_attack_path(backend_input: BackendInput) -> AttackPathResponse:
    """
    Generate attack path for targets from backend scanner.
    
    Accepts array of targets matching parameters.json structure.
    
    Args:
        backend_input: Backend scanner data with array of targets
    
    Returns:
        AttackPathResponse with generated attack path
        
    Example:
        >>> response = requests.post("/generate", json={
        ...     "targets": [
        ...         {
        ...             "IpAddress": "192.168.100.157",
        ...             "Hostname": "test-host",
        ...             "Os": "Linux 3.10 - 4.11",
        ...             "Services": [
        ...                 {
        ...                     "Port": 8080,
        ...                     "ServiceName": "http",
        ...                     "Product": "Apache Tomcat",
        ...                     "Version": "5.5.23",
        ...                     "Vulnerabilities": [
        ...                         {
        ...                             "template-id": "CVE-2017-5638",
        ...                             "info": {
        ...                                 "name": "Apache Struts 2 - RCE",
        ...                                 "severity": "critical",
        ...                                 "classification": {
        ...                                     "cvss-score": 10.0
        ...                                 }
        ...                             }
        ...                         }
        ...                     ]
        ...                 }
        ...             ]
        ...         }
        ...     ]
        ... })
    """
    generator = AttackPathGenerator()
    result = await generator.generate(backend_input)
    return result

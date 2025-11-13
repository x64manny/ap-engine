"""
FastAPI application entry point.

This module defines the REST API routes for the Attack Path Engine.
It serves as the Presentation Layer in the clean architecture pattern,
handling HTTP requests/responses and delegating business logic to services.

Routes:
    - GET /health: Health check endpoint for monitoring
    - POST /attack-path/main: Complete 7-stage attack path analysis (PRIMARY) - JSON
    - POST /attack-path/markdown: Complete 7-stage attack path analysis - Markdown
"""
from fastapi import FastAPI
from fastapi.responses import Response
from app.config import settings
from app.models import InputHost
from app.models.complete_analysis import CompleteAnalysisResponse
from app.services.complete_analyzer import CompleteAnalyzer

# =============================================================================
# FastAPI Application Initialization
# =============================================================================

# Initialize FastAPI app with metadata from configuration
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="AI-powered attack path engine - transforms vulnerability data into attack sequences"
)


# =============================================================================
# API Endpoints
# =============================================================================

@app.get("/health")
def health():
    """
    Health check endpoint for monitoring and service discovery.
    
    This endpoint is used by:
    - Docker health checks
    - Kubernetes liveness/readiness probes
    - Load balancers
    - Monitoring systems
    
    Returns:
        dict: Service status, version, and LLM model configuration
        
    Example:
        >>> curl http://localhost:8000/health
        {"status": "ok", "version": "1.0.0", "model": "gpt-4o-mini"}
    """
    return {
        "status": "ok",
        "version": settings.API_VERSION,
        "model": settings.LLM_MODEL
    }


@app.post("/attack-path/main", response_model=CompleteAnalysisResponse)
async def generate_complete_attack_path(host: InputHost) -> CompleteAnalysisResponse:
    """
    Generate complete attack path analysis (returns JSON).
    
    This is the PRIMARY production endpoint. It generates a complete 7-stage
    attack path with stage-level continuity preservation.
    
    Args:
        host (InputHost): Complete host parameters (same as /attack-path endpoint)
    
    Returns:
        CompleteAnalysisResponse (JSON): Contains:
            - request_id: Unique identifier for this analysis
            - primary_path: 7-stage primary attack path
            - bifurcations: Always empty list (no bifurcations)
            - total_paths: Always 1 (primary path only)
            - execution_time_seconds: Total time taken
            - llm_calls: Breakdown of LLM calls made
            - estimated_cost: Estimated cost in USD
    
    Response Time: 15-25 seconds
    Cost: ~$0.015 per request
    
    Example:
        >>> response = requests.post("/attack-path/main", json={
        ...     "platform": "Linux",
        ...     "open_ports": [22, 80, 3306],
        ...     "services": ["SSH", "Apache", "MySQL"]
        ... })
        >>> print(response.json()["primary_path"])
    """
    # Create complete analyzer instance
    complete_analyzer = CompleteAnalyzer()
    
    # Perform complete analysis
    result = await complete_analyzer.analyze(host)
    
    return result


@app.post("/attack-path/markdown")
async def generate_attack_path_markdown(host: InputHost) -> Response:
    """
    Generate complete attack path analysis in Markdown format.
    
    This endpoint generates the same 7-stage attack path as /attack-path/main
    but returns the response formatted as Markdown instead of JSON.
    
    Args:
        host (InputHost): Complete host parameters (same as /attack-path/main)
    
    Returns:
        Response: Markdown-formatted attack path with all stages
        Content-Type: text/markdown; charset=utf-8
    
    Response Time: 15-25 seconds (same as /attack-path/main)
    Cost: ~$0.015 per request
    
    Example:
        >>> # Save to file
        >>> curl -X POST http://localhost:8000/attack-path/markdown \\
        ...      -H "Content-Type: application/json" \\
        ...      -d '{"platform": "Windows", "open_ports": [80]}' \\
        ...      -o attack_path.md
        
        >>> # View with less
        >>> curl -X POST http://localhost:8000/attack-path/markdown \\
        ...      -H "Content-Type: application/json" \\
        ...      -d '{"platform": "Windows", "open_ports": [80]}' | less
    """
    # Create complete analyzer instance
    complete_analyzer = CompleteAnalyzer()
    
    # Perform complete analysis
    result = await complete_analyzer.analyze(host)
    
    # Convert JSON response to Markdown
    markdown_output = []
    
    # Header
    markdown_output.append(f"# Attack Path Analysis\n\n")
    markdown_output.append(f"**Request ID:** `{result.request_id}`\n\n")
    markdown_output.append(f"**Execution Time:** {result.execution_time_seconds:.2f} seconds\n\n")
    markdown_output.append(f"**Estimated Cost:** ${result.estimated_cost:.4f}\n\n")
    markdown_output.append(f"**Total Paths:** {result.total_paths}\n\n")
    markdown_output.append("---\n\n")
    
    # Target Information Summary
    markdown_output.append("## Target Summary\n\n")
    if host.platform:
        markdown_output.append(f"- **Platform:** {host.platform}\n")
    if host.version_os:
        markdown_output.append(f"- **OS Version:** {host.version_os}\n")
    if host.ip_addresses:
        markdown_output.append(f"- **IP Addresses:** {', '.join(host.ip_addresses)}\n")
    if host.open_ports:
        markdown_output.append(f"- **Open Ports:** {', '.join(map(str, host.open_ports))}\n")
    if host.services:
        markdown_output.append(f"- **Services:** {', '.join(host.services)}\n")
    if host.vulnerabilities:
        markdown_output.append(f"- **Vulnerabilities:**\n")
        for vuln in host.vulnerabilities:
            markdown_output.append(f"  - {vuln}\n")
    markdown_output.append("\n---\n\n")
    
    # Primary Attack Path - Each Stage
    markdown_output.append("## Primary Attack Path\n\n")
    
    for stage in result.primary_path:
        # Stage Header
        markdown_output.append(f"### Stage {stage.stage_index}: {stage.stage_name}\n\n")
        markdown_output.append(f"**Phase:** {stage.phase}\n\n")
        
        # MITRE Techniques
        if stage.mitre_techniques:
            markdown_output.append(f"**MITRE ATT&CK Techniques:**\n\n")
            for technique in stage.mitre_techniques:
                markdown_output.append(f"- `{technique}`\n")
            markdown_output.append("\n")
        
        # Summary
        if stage.summary:
            markdown_output.append(f"**Summary:** {stage.summary}\n\n")
        
        # Key Findings
        if stage.key_findings:
            markdown_output.append(f"**Key Findings:**\n\n")
            for finding in stage.key_findings:
                markdown_output.append(f"- {finding}\n")
            markdown_output.append("\n")
        
        # Tools Used
        if stage.tools_used:
            markdown_output.append(f"**Tools Used:** {', '.join(stage.tools_used)}\n\n")
        
        # Artifact Details
        if stage.artifact_name:
            markdown_output.append(f"**Artifact:**\n\n")
            markdown_output.append(f"- **Name:** `{stage.artifact_name}`\n")
            if stage.artifact_type:
                markdown_output.append(f"- **Type:** {stage.artifact_type}\n")
            markdown_output.append("\n")
        
        # Commands
        if stage.commands:
            markdown_output.append(f"**Commands:**\n\n")
            for cmd in stage.commands:
                # Check if command already contains code block markers
                if "```" in cmd:
                    markdown_output.append(f"{cmd}\n\n")
                elif "\n" in cmd and len(cmd) > 100:
                    # Multi-line command or description
                    markdown_output.append(f"```bash\n{cmd}\n```\n\n")
                else:
                    # Single-line command
                    markdown_output.append(f"```bash\n{cmd}\n```\n\n")
        
        # Full Content
        markdown_output.append(f"#### Detailed Description\n\n")
        markdown_output.append(f"{stage.content}\n\n")
        
        markdown_output.append("---\n\n")
    
    # Validation Report (if exists)
    if result.validation_report:
        markdown_output.append("## Validation Report\n\n")
        markdown_output.append(f"**Valid:** {'✅ Yes' if result.validation_report.get('is_valid', True) else '❌ No'}\n\n")
        
        if result.validation_report.get('warnings'):
            markdown_output.append(f"### Warnings\n\n")
            for warning in result.validation_report.get('warnings', []):
                markdown_output.append(f"- **Stage {warning.get('stage')}**: {warning.get('message', 'No message')}\n")
            markdown_output.append("\n")
        
        if result.validation_report.get('passes'):
            markdown_output.append(f"### Passed Checks\n\n")
            for check in result.validation_report.get('passes', []):
                markdown_output.append(f"- ✅ **Stage {check.get('stage')}**: {check.get('message', check.get('check', 'Check passed'))}\n")
            markdown_output.append("\n")
    
    # LLM Metadata
    markdown_output.append("## Analysis Metadata\n\n")
    markdown_output.append(f"- **Total LLM Calls:** {result.llm_calls.get('total', 0)}\n")
    markdown_output.append(f"- **Execution Time:** {result.execution_time_seconds:.2f}s\n")
    markdown_output.append(f"- **Estimated Cost:** ${result.estimated_cost:.4f}\n")
    
    # Join all markdown lines
    markdown_content = "".join(markdown_output)
    
    # Return as text/markdown response
    return Response(
        content=markdown_content,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'inline; filename="attack_path_{result.request_id}.md"'
        }
    )





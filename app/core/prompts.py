"""
Simple prompt builder for attack path generation.

No bias, no hardcoded methodologies, no specific frameworks.
Just a clean prompt based on the 5 input parameters.
"""
from app.models.target_input import TargetInput


class PromptBuilder:
    """Builds simple prompts for attack path generation."""
    
    @staticmethod
    def build_prompt(target: TargetInput) -> str:
        """
        Build a simple, unbiased prompt for attack path generation.
        
        Args:
            target: Target input with 5 parameters
            
        Returns:
            Clean prompt string with no hardcoded methodologies
        """
        # Format vulnerabilities
        vuln_list = "\n".join([
            f"  - {v.cve} (Score: {v.score})"
            for v in target.vulnerabilities
        ]) if target.vulnerabilities else "  - None detected"
        
        # Format exposure
        exposure_info = (
            f"  - Internet Exposed: {target.exposure.is_internet_exposed}\n"
            f"  - Legacy OS: {target.exposure.has_legacy_os}\n"
            f"  - Admin Shares: {target.exposure.has_admin_shares}"
        )
        
        prompt = f"""Generate a realistic attack path for a target with the following characteristics:

TARGET INFORMATION:

Open Ports:
{chr(10).join([f'  - {port}' for port in target.open_ports]) if target.open_ports else '  - None detected'}

Services:
{chr(10).join([f'  - {service}' for service in target.services]) if target.services else '  - None detected'}

Applications:
{chr(10).join([f'  - {app}' for app in target.applications]) if target.applications else '  - None detected'}

Vulnerabilities:
{vuln_list}

Exposure:
{exposure_info}

TASK:
Based on the above information, generate a detailed attack path that describes:
1. How an attacker could exploit the identified vulnerabilities
2. What techniques could be used to gain access
3. How the attack could progress through the system
4. What the potential objectives and outcomes would be

Provide a clear, step-by-step attack sequence with technical details where appropriate.
Focus on realistic attack scenarios based on the actual vulnerabilities and services present."""
        
        return prompt

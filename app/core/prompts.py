"""
Prompt builder for attack path generation from backend scanner data.
"""
from app.models.backend_input import BackendInput


class PromptBuilder:
    """Builds prompts for attack path generation from backend data."""
    
    @staticmethod
    def build_prompt(backend_input: BackendInput) -> str:
        """
        Build prompt from backend scanner data.
        
        Args:
            backend_input: Backend input with array of targets
            
        Returns:
            Formatted prompt string
        """
        if not backend_input.targets:
            raise ValueError("No targets provided in backend input")
        
        # Build sections for each target
        target_sections = []
        for idx, target in enumerate(backend_input.targets, 1):
            target_section = PromptBuilder._build_target_section(target, idx)
            target_sections.append(target_section)
        
        # Combine all targets
        all_targets = "\n\n".join(target_sections)
        
        prompt = f"""Generate a realistic attack path for the following target(s):

{all_targets}

TASK:
Based on the above information, generate a detailed attack path that describes:
1. How an attacker could exploit the identified vulnerabilities
2. What techniques could be used to gain access
3. How the attack could progress through the system
4. What the potential objectives and outcomes would be

Provide a clear, step-by-step attack sequence with technical details where appropriate.
Focus on realistic attack scenarios based on the actual vulnerabilities and services present."""
        
        return prompt
    
    @staticmethod
    def _build_target_section(target, index: int) -> str:
        """Build formatted section for a single target."""
        # Host information
        host_parts = []
        if target.IpAddress:
            host_parts.append(f"IP: {target.IpAddress}")
        if target.Hostname:
            host_parts.append(f"Hostname: {target.Hostname}")
        if target.Os:
            host_parts.append(f"OS: {target.Os}")
        if target.MacAddress:
            host_parts.append(f"MAC: {target.MacAddress}")
        if target.LastSeen:
            host_parts.append(f"Last Seen: {target.LastSeen}")
        
        host_section = "\n".join([f"  - {part}" for part in host_parts]) if host_parts else "  - No host information"
        
        # Services with vulnerabilities
        services_section = ""
        if target.Services:
            service_entries = []
            for svc in target.Services:
                # Service header
                svc_line = f"Port {svc.Port}"
                if svc.Protocol:
                    svc_line += f"/{svc.Protocol}"
                if svc.State:
                    svc_line += f" ({svc.State})"
                if svc.ServiceName:
                    svc_line += f" - {svc.ServiceName}"
                if svc.Product:
                    svc_line += f" [{svc.Product}"
                    if svc.Version:
                        svc_line += f" {svc.Version}"
                    svc_line += "]"
                if svc.ExtraInfo:
                    svc_line += f" ({svc.ExtraInfo})"
                
                service_entries.append(f"  - {svc_line}")
                
                # Add vulnerabilities for this service
                if svc.Vulnerabilities:
                    for vuln in svc.Vulnerabilities:
                        vuln_line = "    └─ "
                        
                        # Vulnerability name
                        if vuln.info and vuln.info.name:
                            vuln_line += vuln.info.name
                        elif vuln.template_id:
                            vuln_line += vuln.template_id
                        else:
                            vuln_line += "Unknown Vulnerability"
                        
                        # CVE ID
                        if vuln.template_id and vuln.template_id.startswith("CVE"):
                            vuln_line += f" ({vuln.template_id})"
                        
                        # Severity
                        if vuln.info and vuln.info.severity:
                            vuln_line += f" [Severity: {vuln.info.severity}]"
                        
                        # CVSS score
                        if vuln.info and vuln.info.classification and vuln.info.classification.cvss_score:
                            vuln_line += f" [CVSS: {vuln.info.classification.cvss_score}]"
                        
                        service_entries.append(vuln_line)
            
            services_section = "\n".join(service_entries)
        else:
            services_section = "  - No services detected"
        
        # Build complete target section
        section = f"""TARGET {index}:

Host:
{host_section}

Services and Vulnerabilities:
{services_section}"""
        
        return section

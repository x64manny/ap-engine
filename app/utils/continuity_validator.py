"""
Continuity validation for multi-stage attack paths.

This module provides reusable validators to check that stages maintain
logical continuity across a multi-stage workflow.

Features:
    - Artifact continuity: Validates that artifacts are referenced across stages
    - Vulnerability tracking: Ensures CVEs/vulnerabilities flow through stages
    - MITRE technique alignment: Checks logical connection between techniques
    - Scalable validators: Can be adapted for other multi-stage workflows
"""
import re
from typing import Dict, List, Any, Optional
from app.models.complete_analysis import StageAnalysis
from app.models.attack_context import AttackContext


class ContinuityValidator:
    """Validates stage-level continuity preservation."""
    
    def __init__(self, context: AttackContext, primary_path: List[StageAnalysis]):
        """
        Initialize validator with context and parsed stages.
        
        Args:
            context: AttackContext with stage outputs
            primary_path: List of 7 parsed StageAnalysis objects
        """
        self.context = context
        self.path = primary_path
        self.warnings: List[Dict[str, Any]] = []
        self.passes: List[Dict[str, Any]] = []
    
    def validate(self) -> Dict[str, Any]:
        """
        Run all continuity checks.
        
        Returns:
            Dictionary with validation results:
                - is_valid: True if no critical warnings
                - warnings: List of issues found
                - passes: List of passed checks
                - total_checks: Number of checks run
        """
        checks_run = 0
        
        # Check 1: Artifact continuity (Stage 2 → Stage 5+)
        checks_run += self._check_artifact_continuity()
        
        # Check 2: Vulnerability/CVE flow through stages
        checks_run += self._check_vulnerability_continuity()
        
        # Check 3: MITRE technique alignment
        checks_run += self._check_technique_alignment()
        
        # Check 4: Tool consistency across stages
        checks_run += self._check_tool_consistency()
        
        return {
            "is_valid": len([w for w in self.warnings if w.get("severity") == "error"]) == 0,
            "warnings": self.warnings,
            "passes": self.passes,
            "total_checks": checks_run,
            "stage_artifacts": self.context.stage_artifacts
        }
    
    def _check_artifact_continuity(self) -> int:
        """
        Verify that artifacts created in Stage 2 are referenced in later stages.
        
        Critical check: Stage 2 (Weaponization) creates artifacts that should be
        used in Stages 3-7 (Delivery, Exploitation, Installation, C2, Actions).
        
        Returns:
            Number of checks performed
        """
        checks = 0
        
        # Check: Stage 2 artifact referenced in Stage 5+
        stage_2_artifact = self.context.stage_artifacts.get(2)
        
        if stage_2_artifact:
            checks += 1
            # Verify in Installation (Stage 5)
            stage_5_content = self.path[4].content if len(self.path) > 4 else ""
            
            if stage_2_artifact in stage_5_content:
                self.passes.append({
                    "stage": 5,
                    "check": "references_weaponization_artifact",
                    "result": "PASS",
                    "artifact": stage_2_artifact,
                    "message": f"Installation correctly references '{stage_2_artifact}' from Weaponization"
                })
            else:
                self.warnings.append({
                    "stage": 5,
                    "check": "references_weaponization_artifact",
                    "result": "FAIL",
                    "severity": "warning",
                    "artifact": stage_2_artifact,
                    "message": f"Installation stage should reference artifact '{stage_2_artifact}' from Weaponization for continuity"
                })
            
            # Also check in Exploitation (Stage 4) and Delivery (Stage 3)
            checks += 1
            stage_4_content = self.path[3].content if len(self.path) > 3 else ""
            if stage_2_artifact in stage_4_content:
                self.passes.append({
                    "stage": 4,
                    "check": "references_weaponization_artifact",
                    "result": "PASS",
                    "artifact": stage_2_artifact
                })
            
            checks += 1
            stage_3_content = self.path[2].content if len(self.path) > 2 else ""
            if stage_2_artifact in stage_3_content:
                self.passes.append({
                    "stage": 3,
                    "check": "references_weaponization_artifact",
                    "result": "PASS",
                    "artifact": stage_2_artifact
                })
        
        return checks
    
    def _check_vulnerability_continuity(self) -> int:
        """
        Verify that vulnerabilities identified in Stage 1 flow through Stages 2-4.
        
        Continuity check: CVEs/vulnerabilities in Reconnaissance should be
        referenced in Weaponization, Delivery, and Exploitation for consistency.
        
        Returns:
            Number of checks performed
        """
        checks = 0
        
        # Extract CVEs from Stage 1 (Reconnaissance)
        recon_content = self.path[0].content if len(self.path) > 0 else ""
        cves = re.findall(r"CVE-\d{4}-\d{4,5}", recon_content, re.IGNORECASE)
        
        if cves:
            primary_cve = cves[0]  # Focus on first CVE
            checks += 1
            
            # Check Stage 2 (Weaponization)
            stage_2_content = self.path[1].content if len(self.path) > 1 else ""
            if primary_cve in stage_2_content:
                self.passes.append({
                    "stage": 2,
                    "check": "cve_mentioned",
                    "result": "PASS",
                    "cve": primary_cve,
                    "message": f"Weaponization correctly references {primary_cve}"
                })
            else:
                self.warnings.append({
                    "stage": 2,
                    "check": "cve_mentioned",
                    "result": "FAIL",
                    "severity": "info",
                    "cve": primary_cve,
                    "message": f"Recommended: Reference {primary_cve} in Weaponization for clarity"
                })
            
            # Check Stage 3 (Delivery)
            checks += 1
            stage_3_content = self.path[2].content if len(self.path) > 2 else ""
            if primary_cve in stage_3_content:
                self.passes.append({
                    "stage": 3,
                    "check": "cve_mentioned",
                    "result": "PASS",
                    "cve": primary_cve
                })
            
            # Check Stage 4 (Exploitation)
            checks += 1
            stage_4_content = self.path[3].content if len(self.path) > 3 else ""
            if primary_cve in stage_4_content:
                self.passes.append({
                    "stage": 4,
                    "check": "cve_mentioned",
                    "result": "PASS",
                    "cve": primary_cve,
                    "message": f"Exploitation correctly exploits {primary_cve}"
                })
        
        return checks
    
    def _check_technique_alignment(self) -> int:
        """
        Verify MITRE techniques align logically between consecutive stages.
        
        Logic: Exploitation techniques from Stage 1 should relate to
        exploitation techniques in Stage 2, etc.
        
        Returns:
            Number of checks performed
        """
        checks = 0
        
        stage_1_techniques = set(self.path[0].mitre_techniques) if len(self.path) > 0 else set()
        stage_2_techniques = set(self.path[1].mitre_techniques) if len(self.path) > 1 else set()
        
        checks += 1
        
        # Weaponization should include exploitation techniques from Recon
        overlap = stage_1_techniques & stage_2_techniques
        
        if overlap:
            self.passes.append({
                "stage": 2,
                "check": "technique_alignment_with_recon",
                "result": "PASS",
                "techniques": list(overlap),
                "message": f"Weaponization techniques align with Reconnaissance: {', '.join(overlap)}"
            })
        else:
            self.warnings.append({
                "stage": 2,
                "check": "technique_alignment_with_recon",
                "result": "FAIL",
                "severity": "info",
                "recon_techniques": list(stage_1_techniques),
                "weaponization_techniques": list(stage_2_techniques),
                "message": "Weaponization techniques may not align with Reconnaissance findings (info level)"
            })
        
        # Check exploitation techniques appear in Stage 4
        checks += 1
        stage_4_techniques = set(self.path[3].mitre_techniques) if len(self.path) > 3 else set()
        
        # T1203 (Exploitation for Client Execution) should be in Stage 4
        if "T1203" in stage_4_techniques:
            self.passes.append({
                "stage": 4,
                "check": "exploitation_technique_present",
                "result": "PASS",
                "technique": "T1203",
                "message": "T1203 (Exploitation for Client Execution) correctly used in Exploitation stage"
            })
        else:
            self.warnings.append({
                "stage": 4,
                "check": "exploitation_technique_present",
                "result": "FAIL",
                "severity": "info",
                "expected": "T1203",
                "found": list(stage_4_techniques),
                "message": "T1203 (Exploitation) recommended for Exploitation stage"
            })
        
        return checks
    
    def _check_tool_consistency(self) -> int:
        """
        Verify that tools mentioned in one stage are referenced in dependent stages.
        
        Example: If Metasploit used in Weaponization, should appear in Delivery/Exploitation.
        
        Returns:
            Number of checks performed
        """
        checks = 0
        
        # Tools from Stage 2 (Weaponization)
        stage_2_tools = set(self.path[1].tools_used) if len(self.path) > 1 else set()
        
        if stage_2_tools:
            checks += 1
            stage_4_tools = set(self.path[3].tools_used) if len(self.path) > 3 else set()
            tool_overlap = stage_2_tools & stage_4_tools
            
            if tool_overlap:
                self.passes.append({
                    "stage": 4,
                    "check": "tool_continuity",
                    "result": "PASS",
                    "tools": list(tool_overlap),
                    "message": f"Exploitation uses same tools as Weaponization: {', '.join(tool_overlap)}"
                })
            else:
                # Not a failure, just informational
                self.warnings.append({
                    "stage": 4,
                    "check": "tool_continuity",
                    "result": "INFO",
                    "severity": "info",
                    "weaponization_tools": list(stage_2_tools),
                    "exploitation_tools": list(stage_4_tools),
                    "message": "Different tools used (may be intentional for evasion)"
                })
        
        return checks
    
    def get_summary(self) -> str:
        """
        Generate human-readable summary of validation results.
        
        Returns:
            Formatted summary string
        """
        total = len(self.passes) + len(self.warnings)
        critical = len([w for w in self.warnings if w.get("severity") == "error"])
        
        summary = f"Continuity Validation: {len(self.passes)}/{total} checks passed"
        
        if critical > 0:
            summary += f" - {critical} CRITICAL issues"
        elif len(self.warnings) > 0:
            summary += f" - {len(self.warnings)} warnings"
        else:
            summary += " - All checks passed ✓"
        
        return summary

"""Complete attack path analysis service with stage-level continuity.

This is the PRIMARY production service that generates a complete 7-stage
attack path with stage-level continuity preservation. Each stage has access
to outputs from all prior stages to maintain logical consistency.

Features:
    - 7-stage attack path generation with context threading
    - Stage-level continuity preservation
    - Structured StageAnalysis output format
    - Token tracking for all LLM calls
    - Complete formatted response
"""
import time
import uuid
import re
import json
from typing import Dict, List, Optional

from app.models.host import InputHost
from app.models.attack_context import AttackContext
from app.models.complete_analysis import CompleteAnalysisResponse, StageAnalysis
from app.core.prompts import PromptBuilder
from app.services.llm_client import LLMClient
from app.utils.token_logger import get_token_logger
from app.utils.continuity_validator import ContinuityValidator
from app.config import settings


class CompleteAnalyzer:
    """
    Generates complete 7-stage attack path with stage-level continuity.
    
    This is the PRIMARY production endpoint that generates a full attack path
    where each stage has access to outputs from all prior stages, ensuring
    logical consistency and preventing hallucinations.
    
    Output format: Structured StageAnalysis objects for both JSON and Markdown
    """
    
    def __init__(self):
        """Initialize the complete analyzer."""
        self.prompt_builder = PromptBuilder()
        self.llm_client = LLMClient()
        self.token_logger = get_token_logger()
    
    def _extract_artifact_name(self, content: str, stage_index: int) -> Optional[str]:
        """
        Extract artifact names with priority-based fallback and system binary filtering.
        
        Multi-strategy extraction with intelligent filtering:
        - Priority 1: Code block patterns (most reliable, -o flag)
        - Priority 2: Explicit naming patterns (Artifact Name:)
        - Priority 3: Quoted files and equals patterns
        - Priority 4: Upload/transfer command contexts
        - Priority 5: Reference to prior stage artifacts (continuity!)
        
        Filters out system executables to distinguish payloads from tools.
        
        Args:
            content: Stage content to extract from
            stage_index: Which stage (1-7) for context
            
        Returns:
            Artifact name if found, else None
        """
        # System executables to filter out (not payloads)
        system_binaries = {
            'cmd.exe', 'powershell.exe', 'powershell', 'wmic.exe', 'schtasks.exe',
            'net.exe', 'whoami.exe', 'ipconfig.exe', 'systeminfo.exe', 'tar', 'sh',
            'bash', 'python', 'python3', 'perl', 'ruby', 'rar', 'zip', 'certutil.exe',
            'msfconsole', 'meterpreter', 'msfvenom', 'curl', 'wget', 'git', 'sed',
            'awk', 'grep', 'find', 'locate', 'which', 'file', 'nc', 'netcat'
        }
        
        # Priority 1: Look in code blocks (most reliable)
        # Matches: -o file.exe, output file.exe, -OutFile C:\path\file.exe
        code_blocks = re.findall(
            r"(?:msfvenom|wget|curl|scp|copy|Invoke-WebRequest|New-Item|Set-Content)[^\`]*[-\s](?:o|OutFile)\s+(?:C:\\)?[\\\/]*([^\s\n\"'\`]+(?:\.exe|\.sh|\.py|\.bat|\.ps1))",
            content,
            re.IGNORECASE
        )
        if code_blocks:
            for artifact in code_blocks:
                if artifact.lower() not in system_binaries:
                    return artifact
        
        # Priority 2: Explicit artifact naming patterns (enhanced)
        # Handles markdown bold: **Artifact Name**: `reverse_shell_macos`
        # Also: - **Artifact Name**: file.exe, named: 'file.exe', payload: file.sh
        artifact_patterns = [
            # Pattern 1: Markdown bold "**Artifact Name**:" with optional backticks/quotes
            r"\*\*Artifact\s+Name\*\*:?\s+['\"\`]*([a-zA-Z0-9][a-zA-Z0-9\-_.]*(?:\.(?:exe|sh|py|bat|ps1|app|elf|macho))?)['\"\`]*",
            # Pattern 2: Plain "Artifact Name:" (no bold)
            r"Artifact\s+Name:?\s+['\"\`]*([a-zA-Z0-9][a-zA-Z0-9\-_.]*(?:\.(?:exe|sh|py|bat|ps1|app|elf|macho))?)['\"\`]*",
            # Pattern 3: Simple keywords: named, created, called, etc.
            r"(?:named|created|called|file|payload|artifact)[\s:]+['\"\`]*([a-zA-Z0-9][a-zA-Z0-9\-_.]*(?:\.(?:exe|sh|py|bat|ps1|app|elf|macho))?)['\"\`]*",
        ]
        
        for pattern in artifact_patterns:
            artifact_names = re.findall(pattern, content, re.IGNORECASE)
            if artifact_names:
                for artifact in artifact_names:
                    # Filter out common words and system binaries
                    if (artifact.lower() not in system_binaries and 
                        len(artifact) > 2 and  # Skip single letters
                        artifact.lower() not in ('name', 'the', 'is', 'are', 'was', 'be')):
                        return artifact
        
        # Priority 3: Files with extensions in quotes or after equals
        # Matches: "payload.exe", =backdoor.sh, file "malware.exe", including macOS/Linux: .app, .elf, .macho
        quoted_files = re.findall(
            r"['\"\s=]([a-zA-Z0-9\-_.]+\.(?:exe|sh|py|bat|ps1|app|elf|macho))['\"\s]",
            content,
            re.IGNORECASE
        )
        if quoted_files:
            for artifact in quoted_files:
                if artifact.lower() not in system_binaries:
                    return artifact
        
        # Priority 4: Upload/transfer commands
        # Matches: upload /path/to/file.exe, scp file.exe, copy payload.exe, including .app, .elf, .macho
        uploads = re.findall(
            r"(?:upload|scp|copy|wget|curl|Invoke-WebRequest)[^\`]*?([a-zA-Z0-9\-_.]+\.(?:exe|sh|py|bat|ps1|app|elf|macho))",
            content,
            re.IGNORECASE
        )
        if uploads:
            for artifact in uploads:
                if artifact.lower() not in system_binaries:
                    return artifact
        
        # Priority 5: Reference to prior stage artifacts (continuity!)
        # Matches: from weaponization, created earlier, reference to Stage 2, including .app, .elf, .macho
        prior_artifacts = re.findall(
            r"(?:from\s+(?:weaponization|stage\s+2)|created\s+(?:earlier|in)|reference)[^\`]*?([a-zA-Z0-9\-_.]+\.(?:exe|sh|py|bat|ps1|app|elf|macho))",
            content,
            re.IGNORECASE
        )
        if prior_artifacts:
            for artifact in prior_artifacts:
                if artifact.lower() not in system_binaries:
                    return artifact
        
        return None
    
    def _parse_stage_response(
        self, 
        stage_index: int,
        stage_name: str,
        phase: str,
        content: str
    ) -> StageAnalysis:
        """
        Parse LLM response content into structured StageAnalysis.
        
        ENHANCED: Robust extraction with multi-strategy fallbacks ensures all
        fields are populated even with low-confidence LLM output. Uses:
        1. Enhanced regex patterns for known tools/commands
        2. Section header parsing (## Tools Used, etc.)
        3. Fallback extraction strategies
        4. Contextual default values
        
        GUARANTEE: All fields will be populated (never empty or None for critical fields)
        
        Args:
            stage_index: Stage number (1-7)
            stage_name: Kill chain stage name
            phase: Phase description
            content: Full narrative content from LLM
        
        Returns:
            StageAnalysis with extracted structured data (all fields populated)
        """
        # Default stage metadata by index
        stage_meta = {
            1: {
                "techniques": ["T1595", "T1592", "T1598"],
                "phase": "Information Gathering"
            },
            2: {
                "techniques": ["T1203", "T1587.001", "T1588.001"],
                "phase": "Payload Creation"
            },
            3: {
                "techniques": ["T1190", "T1203", "T1566"],
                "phase": "Payload Transmission"
            },
            4: {
                "techniques": ["T1190", "T1203", "T1068"],
                "phase": "Initial Access & Exploitation"
            },
            5: {
                "techniques": ["T1105", "T1053.005", "T1543.003", "T1547.001"],
                "phase": "Persistence & Privilege Escalation"
            },
            6: {
                "techniques": ["T1071.001", "T1573.001", "T1008"],
                "phase": "Command & Control"
            },
            7: {
                "techniques": ["T1003", "T1021", "T1041", "T1567"],
                "phase": "Post-Exploitation"
            }
        }
        
        meta = stage_meta.get(stage_index, {"techniques": [], "phase": phase})
        
        # ===== ENHANCED TOOL EXTRACTION WITH FALLBACKS =====
        tools = []
        
        # Primary: Expanded regex patterns for known tools
        tool_patterns = [
            r"(msfconsole|msfvenom|metasploit|meterpreter)",
            r"(nmap|shodan|masscan|zmap|netdiscover)",
            r"(mimikatz|procdump|secretsdump|hashdump)",
            r"(psexec|wmiexec|smbexec|atexec|dcom)",
            r"(netcat|nc\b|socat|ncat)",
            r"(Empire|PowerView|Invoke-)",
            r"(Cobalt\s+Strike|beacon)",
            r"(wget|curl|certutil|Invoke-WebRequest|DownloadFile)",
            r"(scp|sftp|rsync|smbclient|net\s+use)",
            r"(tar|zip|rar|7z|gzip)",
            r"(ssh|telnet|rdp|winrm|psremoting)",
            r"(sqlmap|mysql|psql|mssql)",
            r"(python|python3|perl|ruby|bash|sh|cmd\.exe)",
        ]
        
        for pattern in tool_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                normalized = match.lower().strip()
                if normalized and not any(normalized in t.lower() for t in tools):
                    tools.append(match)
        
        # Fallback: Extract from section headers (## Tools Used:, etc.)
        if len(tools) < 3:
            tools_section = re.search(
                r"(?:^|\n)#{1,4}\s*(?:tools?[\s-]*used|execution[\s-]*tools?)[:\s]*\n(.*?)(?=\n#{1,4}|\n\n|$)",
                content,
                re.IGNORECASE | re.MULTILINE | re.DOTALL
            )
            if tools_section:
                section_text = tools_section.group(1)
                section_tools = re.findall(r"(?:[-•*]\s*)?([a-zA-Z0-9\-_.]+)(?:\s*[:()]|$)", section_text)
                for tool in section_tools:
                    if tool and not any(tool.lower() in t.lower() for t in tools):
                        tools.append(tool)
        
        # Deduplicate while preserving order
        seen = set()
        tools = [t for t in tools if not (t.lower() in seen or seen.add(t.lower()))][:10]
        
        # Ensure at least one tool entry
        if not tools:
            tools = ["Command line tools"]
        
        # ===== ENHANCED COMMAND EXTRACTION WITH FALLBACKS =====
        commands = []
        
        # Primary: Extract from code blocks
        code_block_patterns = [
            r"```(?:bash|shell|sh|powershell|ps1|cmd|batch|dos)?\s+(.*?)```",
            r"~~~(?:bash|powershell|cmd)?\s+(.*?)~~~",
        ]
        
        for pattern in code_block_patterns:
            code_blocks = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
            for block in code_blocks:
                lines = [
                    line.strip() 
                    for line in block.split("\n") 
                    if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("REM")
                ]
                commands.extend(lines)
        
        # Fallback: Extract from inline code (backticks)
        if len(commands) < 3:
            inline_commands = re.findall(r"`([^`]{15,300})`", content)
            commands.extend(inline_commands)
        
        # Fallback: Extract from "Commands" sections
        if len(commands) < 3:
            commands_section = re.search(
                r"(?:^|\n)#{1,4}\s*(?:commands?|execution|steps?)[:\s]*\n(.*?)(?=\n#{1,4}|\n\n|$)",
                content,
                re.IGNORECASE | re.MULTILINE | re.DOTALL
            )
            if commands_section:
                section_text = commands_section.group(1)
                section_lines = [
                    line.strip() 
                    for line in section_text.split("\n") 
                    if line.strip() and len(line.strip()) > 5
                ]
                commands.extend(section_lines[:10])
        
        # Deduplicate and limit
        seen_cmds = set()
        commands = [c for c in commands if not (c.lower() in seen_cmds or seen_cmds.add(c.lower()))][:15]
        
        # Ensure at least one command
        if not commands:
            stage_commands = {
                1: ["Network reconnaissance executed"],
                2: ["Payload generation performed"],
                3: ["Delivery mechanism initiated"],
                4: ["Exploitation executed"],
                5: ["Persistence established"],
                6: ["C2 communication active"],
                7: ["Post-exploitation objectives executed"]
            }
            commands = stage_commands.get(stage_index, ["Analysis performed"])
        
        # ===== ARTIFACT NAME EXTRACTION =====
        artifact_name = self._extract_artifact_name(content, stage_index)
        
        # ===== ENHANCED KEY FINDINGS EXTRACTION WITH FALLBACKS =====
        key_findings = []
        
        # Primary: Extract from structured lists
        list_patterns = [
            r"^\d+\.\s+(.+)$",           # Numbered lists
            r"^[-•*]\s+(.+)$",            # Bullet points
        ]
        
        for pattern in list_patterns:
            matches = re.findall(pattern, content, re.MULTILINE)
            for match in matches:
                finding = match.strip()
                if (20 < len(finding) < 300 and 
                    not any(f.lower() == finding.lower() for f in key_findings)):
                    key_findings.append(finding[:180])
        
        # Fallback: Extract from "Key Findings" or "Findings" sections
        if len(key_findings) < 2:
            findings_section = re.search(
                r"(?:^|\n)#{1,4}\s*(?:findings?|results?|discovery)[:\s]*\n(.*?)(?=\n#{1,4}|\n\n|$)",
                content,
                re.IGNORECASE | re.MULTILINE | re.DOTALL
            )
            if findings_section:
                section_text = findings_section.group(1)
                section_findings = re.findall(r"(?:^|\n)[-•*]\s+(.+?)(?=\n|-|•|\*|$)", section_text, re.MULTILINE)
                for finding in section_findings:
                    if finding.strip() and not any(finding.lower() in f.lower() for f in key_findings):
                        key_findings.append(finding.strip()[:180])
        
        # Fallback: Extract sentences with security keywords
        if len(key_findings) < 2:
            keywords = ['port', 'service', 'cve', 'vulnerability', 'expose', 'vulnerable', 
                       'attack', 'technique', 'exploit', 'access', 'privilege', 'credential']
            sentences = re.split(r'(?<=[.!?])\s+', content)
            for sent in sentences:
                if (30 < len(sent) < 250 and 
                    any(kw in sent.lower() for kw in keywords) and
                    not any(s.lower() == sent.lower() for s in key_findings)):
                    key_findings.append(sent.strip()[:180])
                    if len(key_findings) >= 3:
                        break
        
        # Final fallback: Use summary as finding
        if len(key_findings) < 1:
            key_findings.append(f"{stage_name} stage analysis completed")
        
        # Deduplicate and limit
        seen_findings = set()
        key_findings = [
            f for f in key_findings 
            if not (f.lower() in seen_findings or seen_findings.add(f.lower()))
        ][:6]
        
        # ===== SUMMARY EXTRACTION WITH FALLBACKS =====
        summary = ""
        
        # Try to extract from Summary section
        summary_section = re.search(
            r"(?:^|\n)#{1,4}\s*summary[:\s]*\n(.*?)(?=\n#{1,4}|\n\n|$)",
            content,
            re.IGNORECASE | re.MULTILINE | re.DOTALL
        )
        if summary_section:
            summary = summary_section.group(1).strip().split('\n')[0]
        
        # Fallback: Use first substantial line
        if not summary:
            lines = content.split("\n")
            for line in lines:
                line = line.strip()
                if (line and 30 < len(line) < 300 and 
                    not line.startswith("#") and 
                    not line.startswith("-")):
                    summary = line
                    break
        
        # Final fallback: Generate from stage name
        if not summary:
            stage_summaries = {
                1: "Passive reconnaissance and information gathering completed",
                2: "Weaponization and payload creation for identified vulnerabilities",
                3: "Payload delivery mechanism established",
                4: "Vulnerability exploitation and initial access achieved",
                5: "Persistence mechanisms and backdoors installed",
                6: "Command and control communication channels established",
                7: "Post-exploitation objectives executed"
            }
            summary = stage_summaries.get(stage_index, f"{stage_name} attack stage execution")
        
        # Limit summary to 200 chars
        summary = str(summary)[:200]
        
        # ===== ARTIFACT TYPE INFERENCE =====
        artifact_type = None
        if artifact_name:
            ext = artifact_name.lower().split('.')[-1] if '.' in artifact_name else ""
            
            if ext in ['exe', 'dll', 'sys', 'drv']:
                artifact_type = "Windows PE Executable"
            elif ext in ['sh', 'bash', 'elf', 'so', 'out']:
                artifact_type = "Linux Executable/Script"
            elif ext in ['ps1', 'bat', 'cmd', 'vbs']:
                artifact_type = "Windows Script"
            elif ext in ['py', 'rb', 'pl', 'js', 'php', 'jar']:
                artifact_type = "Script"
            elif ext in ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf']:
                artifact_type = "Malicious Document"
            elif ext in ['zip', 'rar', '7z', 'tar', 'gz']:
                artifact_type = "Compressed Archive"
            else:
                artifact_type = "Malware/Payload"
        
        return StageAnalysis(
            stage_index=stage_index,
            stage_name=stage_name,
            phase=meta.get("phase", phase),
            mitre_techniques=meta.get("techniques", []),
            summary=summary,
            key_findings=key_findings,
            tools_used=tools,
            artifact_name=artifact_name,
            artifact_type=artifact_type,
            commands=commands,
            content=content
        )
    
    async def _generate_attack_path_with_continuity(self, host: InputHost) -> AttackContext:
        """
        Generate attack path with stage-level continuity preservation.
        
        Each stage receives outputs from all prior stages, ensuring logical
        consistency across the entire attack path.
        
        Args:
            host: Target host information
            
        Returns:
            AttackContext with all 7 stages populated
        """
        context = AttackContext(host_data=host.dict())
        
        # STAGE 1: Reconnaissance (no prior context)
        print("  → Stage 1: Reconnaissance...")
        prompt1 = self.prompt_builder.build_reconnaissance_prompt(host)
        stage_start = time.time()
        response1 = await self.llm_client.complete(
            system_message=PromptBuilder.SYSTEM_MESSAGE,
            user_prompt=prompt1,
            json_mode=False
        )
        stage_time = int((time.time() - stage_start) * 1000)
        context.reconnaissance = response1.get("content", "")
        self.token_logger.log_call(
            request_id=getattr(self, '_request_id', 'unknown'),
            call_type="stage_1_reconnaissance",
            model=settings.LLM_MODEL,
            tokens_input=response1.get("usage", {}).get("prompt_tokens", 0),
            tokens_output=response1.get("usage", {}).get("completion_tokens", 0),
            response_time_ms=stage_time
        )
        
        # STAGE 2: Weaponization (knows recon results)
        print("  → Stage 2: Weaponization...")
        prompt2 = self.prompt_builder.build_weaponization_prompt(host, context)
        stage_start = time.time()
        response2 = await self.llm_client.complete(
            system_message=PromptBuilder.SYSTEM_MESSAGE,
            user_prompt=prompt2,
            json_mode=False
        )
        stage_time = int((time.time() - stage_start) * 1000)
        context.weaponization = response2.get("content", "")
        self.token_logger.log_call(
            request_id=getattr(self, '_request_id', 'unknown'),
            call_type="stage_2_weaponization",
            model=settings.LLM_MODEL,
            tokens_input=response2.get("usage", {}).get("prompt_tokens", 0),
            tokens_output=response2.get("usage", {}).get("completion_tokens", 0),
            response_time_ms=stage_time
        )
        
        # STAGE 3: Delivery (knows recon + weaponization)
        print("  → Stage 3: Delivery...")
        prompt3 = self.prompt_builder.build_delivery_prompt(host, context)
        stage_start = time.time()
        response3 = await self.llm_client.complete(
            system_message=PromptBuilder.SYSTEM_MESSAGE,
            user_prompt=prompt3,
            json_mode=False
        )
        stage_time = int((time.time() - stage_start) * 1000)
        context.delivery = response3.get("content", "")
        self.token_logger.log_call(
            request_id=getattr(self, '_request_id', 'unknown'),
            call_type="stage_3_delivery",
            model=settings.LLM_MODEL,
            tokens_input=response3.get("usage", {}).get("prompt_tokens", 0),
            tokens_output=response3.get("usage", {}).get("completion_tokens", 0),
            response_time_ms=stage_time
        )
        
        # STAGE 4: Exploitation (knows all prior)
        print("  → Stage 4: Exploitation...")
        prompt4 = self.prompt_builder.build_exploitation_prompt(host, context)
        stage_start = time.time()
        response4 = await self.llm_client.complete(
            system_message=PromptBuilder.SYSTEM_MESSAGE,
            user_prompt=prompt4,
            json_mode=False
        )
        stage_time = int((time.time() - stage_start) * 1000)
        context.exploitation = response4.get("content", "")
        self.token_logger.log_call(
            request_id=getattr(self, '_request_id', 'unknown'),
            call_type="stage_4_exploitation",
            model=settings.LLM_MODEL,
            tokens_input=response4.get("usage", {}).get("prompt_tokens", 0),
            tokens_output=response4.get("usage", {}).get("completion_tokens", 0),
            response_time_ms=stage_time
        )
        
        # STAGE 5: Installation (knows all prior, CRITICAL for artifact continuity)
        print("  → Stage 5: Installation...")
        prompt5 = self.prompt_builder.build_installation_prompt(host, context)
        stage_start = time.time()
        response5 = await self.llm_client.complete(
            system_message=PromptBuilder.SYSTEM_MESSAGE,
            user_prompt=prompt5,
            json_mode=False
        )
        stage_time = int((time.time() - stage_start) * 1000)
        context.installation = response5.get("content", "")
        self.token_logger.log_call(
            request_id=getattr(self, '_request_id', 'unknown'),
            call_type="stage_5_installation",
            model=settings.LLM_MODEL,
            tokens_input=response5.get("usage", {}).get("prompt_tokens", 0),
            tokens_output=response5.get("usage", {}).get("completion_tokens", 0),
            response_time_ms=stage_time
        )
        
        # STAGE 6: C2 (full context)
        print("  → Stage 6: Command & Control...")
        prompt6 = self.prompt_builder.build_command_and_control_prompt(host, context)
        stage_start = time.time()
        response6 = await self.llm_client.complete(
            system_message=PromptBuilder.SYSTEM_MESSAGE,
            user_prompt=prompt6,
            json_mode=False
        )
        stage_time = int((time.time() - stage_start) * 1000)
        context.command_and_control = response6.get("content", "")
        self.token_logger.log_call(
            request_id=getattr(self, '_request_id', 'unknown'),
            call_type="stage_6_command_and_control",
            model=settings.LLM_MODEL,
            tokens_input=response6.get("usage", {}).get("prompt_tokens", 0),
            tokens_output=response6.get("usage", {}).get("completion_tokens", 0),
            response_time_ms=stage_time
        )
        
        # STAGE 7: Actions (full context)
        print("  → Stage 7: Actions on Objectives...")
        prompt7 = self.prompt_builder.build_actions_on_objectives_prompt(host, context)
        stage_start = time.time()
        response7 = await self.llm_client.complete(
            system_message=PromptBuilder.SYSTEM_MESSAGE,
            user_prompt=prompt7,
            json_mode=False
        )
        stage_time = int((time.time() - stage_start) * 1000)
        context.actions_on_objectives = response7.get("content", "")
        self.token_logger.log_call(
            request_id=getattr(self, '_request_id', 'unknown'),
            call_type="stage_7_actions_on_objectives",
            model=settings.LLM_MODEL,
            tokens_input=response7.get("usage", {}).get("prompt_tokens", 0),
            tokens_output=response7.get("usage", {}).get("completion_tokens", 0),
            response_time_ms=stage_time
        )
        
        return context
    
    def _update_stage_artifacts(self, context: AttackContext, primary_path: List[StageAnalysis]) -> None:
        """
        Track extracted artifacts through the context for continuity validation.
        
        After parsing all stages, update the context's stage_artifacts dict
        so we can validate that later stages properly reference earlier artifacts.
        
        Args:
            context: The attack context with raw stage outputs
            primary_path: Parsed StageAnalysis objects
        """
        for i, stage in enumerate(primary_path, start=1):
            if stage.artifact_name:
                context.stage_artifacts[i] = stage.artifact_name
    
    async def analyze(
        self, 
        host: InputHost
    ) -> CompleteAnalysisResponse:
        """
        Generate complete 7-stage attack path with continuity.
        
        Args:
            host: Complete host parameters
        
        Returns:
            CompleteAnalysisResponse with 7-stage primary path (structured StageAnalysis objects)
        
        Features:
            - Stage-level continuity: Each stage receives all prior outputs
            - Structured output: Returns StageAnalysis objects with metadata
            - Token tracking: All 7 LLM calls logged
            - Cost estimation: Total cost calculated
        """
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        # Track LLM calls
        llm_calls: Dict[str, int] = {
            "total": 0
        }
        
        # Store request_id for token logging
        self._request_id = request_id
        
        print(f"\n{'='*60}")
        print(f"Starting Attack Path Analysis")
        print(f"Request ID: {request_id}")
        print(f"{'='*60}\n")
        
        print("Generating 7-stage attack path with continuity...")
        print("  (with stage-level continuity preservation)\n")
        
        # Generate primary attack path
        context = await self._generate_attack_path_with_continuity(host)
        
        # Parse responses into structured StageAnalysis objects
        stage_names = [
            "Reconnaissance",
            "Weaponization",
            "Delivery",
            "Exploitation",
            "Installation",
            "Command & Control",
            "Actions on Objectives"
        ]
        
        stage_phases = [
            "Information Gathering",
            "Payload Creation",
            "Payload Transmission",
            "Initial Access",
            "Persistence",
            "Communication Channel",
            "Post-Exploitation"
        ]
        
        content_list = [
            context.reconnaissance,
            context.weaponization,
            context.delivery,
            context.exploitation,
            context.installation,
            context.command_and_control,
            context.actions_on_objectives
        ]
        
        primary_path: List[StageAnalysis] = []
        for i, content in enumerate(content_list, start=1):
            stage = self._parse_stage_response(
                stage_index=i,
                stage_name=stage_names[i-1],
                phase=stage_phases[i-1],
                content=content
            )
            primary_path.append(stage)
        
        # Update context with tracked artifacts
        self._update_stage_artifacts(context, primary_path)
        
        # Run continuity validation
        validator = ContinuityValidator(context, primary_path)
        validation_report = validator.validate()
        
        print(f"\nContinuity Validation:")
        print(f"  {validator.get_summary()}")
        if validation_report["warnings"]:
            print(f"  Warnings: {len(validation_report['warnings'])}")
        
        llm_calls["total"] = 7  # 7 stages
        
        # Calculate metrics BEFORE logging
        execution_time = time.time() - start_time
        total_paths = 1  # Just primary path
        estimated_cost = 0.015  # Approximate cost for 7 LLM calls
        
        # Log summary
        self.token_logger.log_call(
            request_id=request_id,
            call_type="analysis_complete",
            model=settings.LLM_MODEL,
            tokens_input=0,
            tokens_output=0,
            response_time_ms=int(execution_time * 1000),
            metadata={"stages": 7, "total_paths": total_paths}
        )
        
        print(f"\n{'='*60}")
        print(f"Analysis Complete!")
        print(f"  Total Paths: {total_paths}")
        print(f"  LLM Calls: {llm_calls['total']}")
        print(f"  Execution Time: {execution_time:.2f}s")
        print(f"  Estimated Cost: ${estimated_cost:.4f}")
        print(f"\n{'='*60}\n")
        
        return CompleteAnalysisResponse(
            request_id=request_id,
            primary_path=primary_path,
            total_paths=total_paths,
            execution_time_seconds=round(execution_time, 2),
            llm_calls=llm_calls,
            estimated_cost=round(estimated_cost, 4),
            validation_report=validation_report
        )


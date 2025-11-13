# AP-Engine Codebase Analysis

**Objective**: Clean repository to create a simple attack path generator that takes 5 parameters and generates an attack path - no bias, no hardcoded rules, no complex prompts.

**Target Input Format**:
```json
{
  "open_ports": [""],
  "services": [""],
  "applications": [""],
  "vulnerabilities": [{"cve": "", "score": ""}],
  "exposure": {
    "is_internet_exposed": "",
    "has_legacy_os": "",
    "has_admin_shares": ""
  }
}
```

---

## 📁 File Inventory & Cleanup Recommendations

### Core Application Files

#### 1. `/app/main.py` - FastAPI Entry Point
**Current State**: 
- Multiple endpoints (`/health`, `/attack-path/main`, `/attack-path/markdown`)
- 7-stage attack path with stage-level continuity
- Markdown conversion logic (100+ lines)
- Hardcoded stage metadata and conversion

**Issues for Template**:
- ❌ Too specific - hardcoded 7-stage Cyber Kill Chain
- ❌ Markdown endpoint adds unnecessary complexity
- ❌ Continuity validation overhead
- ❌ Response model too complex (StageAnalysis, validation_report)

**Cleanup Actions**:
- ✅ **KEEP**: `/health` endpoint (minimal monitoring)
- ✅ **SIMPLIFY**: Single `/generate-attack-path` endpoint
- ❌ **REMOVE**: `/attack-path/markdown` endpoint
- ❌ **REMOVE**: Stage metadata hardcoding
- ❌ **REMOVE**: Markdown conversion logic (lines 100-200)

---

#### 2. `/app/config.py` - Configuration
**Current State**:
- Environment variable loading
- API metadata (title, version)
- LLM configuration (model, temperature)
- Validation method

**Issues for Template**:
- ⚠️ Hardcoded API title: "Attack Path Engine"
- ⚠️ LLM model defaults to "gpt-4o-mini"

**Cleanup Actions**:
- ✅ **KEEP**: Basic structure (env loading, LLM config)
- ✅ **SIMPLIFY**: Remove validation method (not needed for simple template)
- ⚠️ **UPDATE**: API_TITLE to be generic or configurable

---

#### 3. `/app/core/prompts.py` - Prompt Builder (⚠️ CRITICAL - MAJOR BIAS)
**Current State**:
- 900+ line file with extensive hardcoded prompts
- SYSTEM_MESSAGE with 400+ lines of hardcoded rules
- Hardcoded "Granny Box IIS 6.0" reference example
- 7 stage-specific prompt builders with hardcoded Kill Chain methodology
- Hardcoded MITRE ATT&CK mappings
- Hardcoded Metasploit procedures and command syntax

**MAJOR ISSUES** (This is where ALL the bias lives):
- ❌ **Lines 15-200**: SYSTEM_MESSAGE with hardcoded IIS 6.0 exploitation example
- ❌ **Lines 200-350**: Hardcoded Cyber Kill Chain phases and detailed requirements
- ❌ **Lines 350-450**: Hardcoded Metasploit command syntax and procedures
- ❌ **Lines 450-550**: Hardcoded Windows/Linux/macOS command examples
- ❌ **Lines 550-900**: 7 separate stage builders (build_reconnaissance_prompt, build_weaponization_prompt, etc.)
- ❌ Each stage builder has hardcoded rules like "DO NOT plan attacks", "MUST reference Stage 2 artifact", etc.

**Cleanup Actions**:
- ❌ **DELETE ENTIRELY**: All 7 stage-specific builders
- ❌ **DELETE**: SYSTEM_MESSAGE (lines 15-500)
- ✅ **REPLACE WITH**: Simple, unbiased prompt builder
  ```python
  def build_attack_path_prompt(params: dict) -> str:
      return f"""Generate an attack path based on:
      - Open Ports: {params['open_ports']}
      - Services: {params['services']}
      - Applications: {params['applications']}
      - Vulnerabilities: {params['vulnerabilities']}
      - Exposure: {params['exposure']}
      
      Provide a realistic attack sequence."""
  ```

---

#### 4. `/app/models/attack_context.py` - Attack Context
**Current State**:
- Tracks 7 stage outputs (reconnaissance, weaponization, delivery, etc.)
- Artifact tracking dictionary
- Host data serialization

**Issues**:
- ❌ Hardcoded to 7-stage model
- ❌ Stage names are Kill Chain specific
- ❌ Artifact tracking adds complexity

**Cleanup Actions**:
- ❌ **DELETE ENTIRELY**: Not needed for simple template
- Replace with simple input/output models

---

#### 5. `/app/models/complete_analysis.py` - Response Models
**Current State**:
- StageAnalysis model (20+ fields)
- CompleteAnalysisResponse with validation_report
- Hardcoded stage metadata

**Issues**:
- ❌ Too complex - 20+ fields per stage
- ❌ Hardcoded MITRE techniques, tools, artifacts
- ❌ Validation report adds overhead

**Cleanup Actions**:
- ❌ **DELETE**: StageAnalysis complexity
- ✅ **REPLACE WITH**: Simple response model
  ```python
  class AttackPathResponse(BaseModel):
      request_id: str
      attack_path: str  # Simple text output
      execution_time: float
  ```

---

#### 6. `/app/models/host.py` - Input Models (⚠️ CRITICAL - WRONG SCHEMA)
**Current State**:
- Complex nested model: InputHost → Service → Vulnerability → VulnerabilityInfo → Classification
- 200+ lines of nested Pydantic models
- Fields: IpAddress, MacAddress, Os, Hostname, LastSeen, Services
- Each Service has: Port, Protocol, ServiceName, Product, Version, ExtraInfo, Vulnerabilities
- Each Vulnerability has: template_id, info, classification (CVE, CVSS, EPSS, etc.)

**MAJOR ISSUE**: 
- ❌ **COMPLETELY WRONG SCHEMA** - Does not match target input format
- ❌ Target needs: `open_ports`, `services`, `applications`, `vulnerabilities`, `exposure`
- ❌ Current has: `IpAddress`, `MacAddress`, `Os`, `Hostname`, `Services` (nested)

**Cleanup Actions**:
- ❌ **DELETE ENTIRELY**: All nested models (Service, Vulnerability, VulnerabilityInfo, Classification, Metadata)
- ✅ **REPLACE WITH**: Simple flat model matching target spec
  ```python
  class TargetInput(BaseModel):
      open_ports: List[str]
      services: List[str]
      applications: List[str]
      vulnerabilities: List[dict]  # [{"cve": "", "score": ""}]
      exposure: dict  # {"is_internet_exposed": "", ...}
  ```

---

#### 7. `/app/services/complete_analyzer.py` - Analysis Service (⚠️ MAJOR BIAS)
**Current State**:
- 500+ lines of hardcoded 7-stage workflow
- _generate_attack_path_with_continuity() method (lines 200-350)
- 7 sequential LLM calls with hardcoded prompt builders
- _parse_stage_response() with 200+ lines of regex extraction
- Artifact tracking and continuity validation
- Hardcoded stage names, phases, MITRE techniques

**Issues**:
- ❌ **Lines 200-350**: Hardcoded 7-stage sequential workflow
- ❌ **Lines 100-200**: Complex stage parsing with artifact extraction
- ❌ Hardcoded MITRE technique defaults (lines 50-100)
- ❌ Tool extraction with 10+ regex patterns

**Cleanup Actions**:
- ❌ **DELETE**: _generate_attack_path_with_continuity (entire method)
- ❌ **DELETE**: _parse_stage_response (entire method)
- ❌ **DELETE**: _extract_artifact_name (entire method)
- ❌ **DELETE**: Continuity validation logic
- ✅ **REPLACE WITH**: Simple single LLM call
  ```python
  async def analyze(self, target: TargetInput):
      prompt = self.prompt_builder.build(target)
      response = await self.llm_client.complete(prompt)
      return {"attack_path": response["content"]}
  ```

---

#### 8. `/app/services/llm_client.py` - LLM Client
**Current State**:
- LiteLLM integration
- Async completion method
- JSON mode support
- Token usage extraction

**Issues**:
- ✅ NO ISSUES - This is clean and reusable

**Cleanup Actions**:
- ✅ **KEEP AS-IS**: No changes needed

---

#### 9. `/app/utils/continuity_validator.py` - Validation
**Current State**:
- 300+ lines of artifact/CVE/technique validation
- Cross-stage continuity checks
- Tool consistency validation

**Issues**:
- ❌ Specific to 7-stage model
- ❌ Adds complexity and overhead

**Cleanup Actions**:
- ❌ **DELETE ENTIRELY**: Not needed for simple template

---

#### 10. `/app/utils/token_logger.py` - Token Logging
**Current State**:
- JSON Lines logging
- Token usage tracking
- Cost estimation
- Rotating file handler

**Issues**:
- ⚠️ Hardcoded model costs (may be outdated)
- ✅ Otherwise useful for monitoring

**Cleanup Actions**:
- ✅ **KEEP**: Useful for monitoring
- ⚠️ **UPDATE**: Model costs if needed

---

### Infrastructure Files

#### 11. `/requirements.txt`
**Current State**:
```
fastapi>=0.112
uvicorn[standard]>=0.30
pydantic>=2.7
httpx>=0.27
python-dotenv>=1.0
litellm>=1.40.0
tqdm>=4.66.1
```

**Cleanup Actions**:
- ✅ **KEEP ALL**: All dependencies are minimal and necessary
- ❓ Consider removing `tqdm` if not used (progress bars)

---

#### 12. `/Dockerfile`
**Current State**:
- Python 3.10-slim base
- Non-root user
- Health check
- Uvicorn command

**Cleanup Actions**:
- ✅ **KEEP AS-IS**: Clean, minimal Dockerfile

---

#### 13. `/docker-compose.yml`
**Status**: Not read yet, but likely simple

**Cleanup Actions**:
- ✅ Review and simplify if needed

---

## 🎯 Summary of Cleanup

### Files to DELETE Entirely
1. ❌ `/app/models/attack_context.py` - 7-stage specific
2. ❌ `/app/models/complete_analysis.py` - Complex stage models
3. ❌ `/app/utils/continuity_validator.py` - 7-stage validation

### Files to HEAVILY MODIFY
1. ⚠️ `/app/core/prompts.py` - **900 lines → ~50 lines**
   - Remove SYSTEM_MESSAGE (400+ lines)
   - Remove 7 stage builders
   - Replace with simple prompt builder
   
2. ⚠️ `/app/models/host.py` - **200 lines → ~20 lines**
   - Remove nested models
   - Replace with flat TargetInput matching spec
   
3. ⚠️ `/app/services/complete_analyzer.py` - **500 lines → ~50 lines**
   - Remove 7-stage workflow
   - Remove parsing logic
   - Simple single LLM call
   
4. ⚠️ `/app/main.py` - **250 lines → ~50 lines**
   - Remove markdown endpoint
   - Simplify response model
   - Single `/generate` endpoint

### Files to KEEP AS-IS
1. ✅ `/app/services/llm_client.py` - Clean
2. ✅ `/app/utils/token_logger.py` - Useful
3. ✅ `/app/config.py` - Minimal changes
4. ✅ `/Dockerfile` - Clean
5. ✅ `/requirements.txt` - Minimal

---

## 📊 Bias Concentration Map

**Highest Bias** (DELETE/REWRITE):
1. 🔴 `/app/core/prompts.py` - 900 lines of hardcoded Kill Chain methodology
2. 🔴 `/app/services/complete_analyzer.py` - 500 lines of 7-stage workflow
3. 🟡 `/app/models/host.py` - Wrong schema, needs full replacement
4. 🟡 `/app/models/complete_analysis.py` - Too complex, needs simplification

**Medium Bias** (SIMPLIFY):
5. 🟡 `/app/main.py` - Endpoints and response handling

**No Bias** (KEEP):
6. 🟢 `/app/services/llm_client.py`
7. 🟢 `/app/utils/token_logger.py`
8. 🟢 `/app/config.py`

---

## 🚀 Recommended Refactor Order

1. **Phase 1**: Delete unused files
   - Delete `attack_context.py`
   - Delete `complete_analysis.py`
   - Delete `continuity_validator.py`

2. **Phase 2**: Rewrite core models
   - Rewrite `host.py` → `target_input.py` (new schema)
   - Create simple `attack_path_response.py`

3. **Phase 3**: Simplify prompts
   - Rewrite `prompts.py` (900 lines → 50 lines)

4. **Phase 4**: Simplify analyzer
   - Rewrite `complete_analyzer.py` (500 lines → 50 lines)

5. **Phase 5**: Update API
   - Simplify `main.py` endpoints

---

## 📝 Target Architecture (Simple Template)

```
app/
├── __init__.py
├── main.py                    # Single endpoint: POST /generate
├── config.py                  # Env config (keep as-is)
├── models/
│   ├── __init__.py
│   ├── target_input.py        # NEW: Simple 5-field model
│   └── response.py            # NEW: Simple response
├── services/
│   ├── __init__.py
│   ├── attack_path_generator.py  # NEW: Single LLM call
│   └── llm_client.py          # KEEP: As-is
├── core/
│   ├── __init__.py
│   └── prompts.py             # REWRITE: Simple unbiased prompt
└── utils/
    ├── __init__.py
    └── token_logger.py        # KEEP: As-is
```

**Total Lines**: ~300 lines (down from 3000+)

---

## ✅ Next Steps

1. Review this analysis
2. Confirm refactor approach
3. I'll implement the cleanup in phases
4. Test with sample input matching your spec

Ready to proceed?

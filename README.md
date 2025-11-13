# AP-Engine - Attack Path Generator

A clean, unbiased template for AI-powered attack path generation.

## 🎯 Overview

Simple API that takes 5 parameters and generates attack paths using LLM - no hardcoded methodologies, no biased prompts, no complex workflows.

**Input**: 5 clean parameters  
**Process**: Single LLM call  
**Output**: Attack path text

## 📊 Stats

- **~320 lines** of clean code
- **1 endpoint**: `POST /generate`
- **1 LLM call** per request
- **No bias** or hardcoded attack frameworks

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- OpenAI API key (or other LLM provider)

### Setup

```bash
# Clone
git clone https://github.com/x64manny/ap-engine.git
cd ap-engine

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# Run
uvicorn app.main:app --reload
```

### Test

```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d @examples/requests/sample_target.json
```

## 📥 Input Format

```json
{
  "open_ports": ["22", "80", "443"],
  "services": ["ssh", "http", "https"],
  "applications": ["apache", "openssh"],
  "vulnerabilities": [{ "cve": "CVE-2021-3156", "score": "7.8" }],
  "exposure": {
    "is_internet_exposed": "true",
    "has_legacy_os": "false",
    "has_admin_shares": "false"
  }
}
```

## 📤 Output Format

```json
{
  "request_id": "uuid",
  "attack_path": "Generated attack path...",
  "execution_time_seconds": 2.5,
  "estimated_cost_usd": 0.0012
}
```

## 🏗️ Architecture

```
app/
├── main.py                         # Single endpoint: POST /generate
├── models/
│   ├── target_input.py             # 5-parameter input model
│   └── response.py                 # Simple response model
├── services/
│   ├── attack_path_generator.py    # Single LLM call
│   └── llm_client.py               # LiteLLM wrapper
├── core/
│   └── prompts.py                  # Simple prompt builder
└── utils/
    └── token_logger.py             # Token tracking
```

## 🔧 Customization

### Modify the Prompt

Edit `app/core/prompts.py` - the `build_prompt()` method formats your 5 parameters into the LLM prompt.

### Change LLM Provider

Set `LLM_MODEL` in `.env`:

```bash
# OpenAI
LLM_MODEL=gpt-4o-mini

# Anthropic
LLM_MODEL=claude-3-5-sonnet-20241022

# Google
LLM_MODEL=gemini/gemini-pro

# Local (Ollama)
LLM_MODEL=ollama/llama2
```

### Adjust System Message

Edit `app/services/attack_path_generator.py` - the `system_message` variable sets the AI's behavior.

## 📚 Documentation

- [Codebase Analysis](docs/CODEBASE_ANALYSIS.md) - Detailed file-by-file breakdown
- [Cleanup Summary](docs/CLEANUP_SUMMARY.md) - What was changed and why

## 🐳 Docker

```bash
# Build
docker build -t ap-engine .

# Run
docker run -p 8000:8000 --env-file .env ap-engine
```

Or use docker-compose:

```bash
docker-compose up
```

## 🔒 Environment Variables

```bash
# Required
OPENAI_API_KEY=sk-proj-...

# Optional
LLM_MODEL=gpt-4o-mini          # Default: gpt-4o-mini
LLM_TEMPERATURE=0.7            # Default: 0.7
```

## 📝 API Endpoints

### `GET /health`

Health check

**Response:**

```json
{
  "status": "ok",
  "version": "1.0.0",
  "model": "gpt-4o-mini"
}
```

### `POST /generate`

Generate attack path

**Request:** See [Input Format](#-input-format)  
**Response:** See [Output Format](#-output-format)

## 🧪 Examples

See `examples/requests/` for sample inputs.

## 📊 Token Tracking

Token usage is logged to `logs/token_usage.jsonl` for cost monitoring.

## 🤝 Contributing

This is a template - customize it for your needs!

## 📄 License

MIT

## 🙏 Credits

Built with:

- [FastAPI](https://fastapi.tiangolo.com/)
- [LiteLLM](https://github.com/BerriAI/litellm)
- [Pydantic](https://pydantic-docs.helpmanual.io/)

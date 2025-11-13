# AP-Engine - Attack Path Generator

Clean, unbiased AI-powered attack path generation from backend scanner data.

## 🎯 Overview

Simple API that accepts vulnerability scanner output and generates attack paths using LLM.

**Input**: Backend scanner data (Nuclei/Nmap format)  
**Process**: Single LLM call  
**Output**: Attack path text

## 📊 Stats

- **~400 lines** of clean code
- **1 endpoint**: `POST /generate`
- **1 LLM call** per request
- **No bias** or hardcoded attack frameworks
- **Matches parameters.json** structure exactly

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
# Wrap parameters.json into correct format
python3 wrap_parameters.py parameters.json backend_request.json

# Send request
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d @backend_request.json
```

## 📥 Input Format

Matches **parameters.json** structure exactly:

```json
{
  "targets": [
    {
      "IpAddress": "192.168.100.157",
      "Os": "Linux 3.10 - 4.11",
      "Hostname": "test-host",
      "Services": [
        {
          "Port": 8080,
          "ServiceName": "http",
          "Product": "Apache Tomcat",
          "Version": "5.5.23",
          "Vulnerabilities": [
            {
              "template-id": "CVE-2017-5638",
              "info": {
                "name": "Apache Struts 2 - RCE",
                "severity": "critical",
                "classification": {
                  "cve-id": ["CVE-2017-5638"],
                  "cvss-score": 10.0
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### Field Names (EXACT from parameters.json)

**Target Level:**
- `IpAddress`, `MacAddress`, `Os`, `Hostname`, `LastSeen`, `Services`

**Service Level:**
- `Port`, `Protocol`, `State`, `ServiceName`, `Product`, `Version`, `ExtraInfo`, `Vulnerabilities`

**Vulnerability Level:**
- `template`, `template-id`, `info`, `type`, `host`, `port`, `scheme`, `url`, `matcher-status`

**Info Object:**
- `name`, `author`, `tags`, `description`, `impact`, `reference`, `severity`, `metadata`, `classification`, `remediation`

All fields are **Optional** - backend can send partial data.

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

```plaintext
app/
├── main.py                    # Single endpoint: POST /generate
├── models/
│   ├── backend_input.py       # Matches parameters.json structure
│   └── response.py            # Response model
├── services/
│   ├── attack_path_generator.py  # Single LLM call
│   └── llm_client.py          # LiteLLM wrapper
├── core/
│   └── prompts.py             # Prompt builder for backend data
└── utils/
    └── token_logger.py        # Token tracking
```

## 🔧 Usage

### Convert parameters.json

Your backend scanner outputs an array. Wrap it:

```bash
python3 wrap_parameters.py parameters.json backend_request.json
```

This converts:
```json
[{"IpAddress": "...", "Services": [...]}]
```

To:
```json
{"targets": [{"IpAddress": "...", "Services": [...]}]}
```

### Send Request

```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d @backend_request.json
```

### Change LLM Provider

Set `LLM_MODEL` in `.env`:

```bash
# OpenAI
LLM_MODEL=gpt-4o-mini

# Anthropic
LLM_MODEL=claude-3-5-sonnet-20241022

# Google
LLM_MODEL=gemini/gemini-1.5-flash

# Local (Ollama)
LLM_MODEL=ollama/llama2
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

**Request:** Array of targets (see Input Format)  
**Response:** See Output Format

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

## 📊 Token Tracking

Token usage is logged to `logs/token_usage.jsonl`:

```bash
tail -f logs/token_usage.jsonl
```

## 🔒 Environment Variables

```bash
# Required
OPENAI_API_KEY=sk-proj-...

# Optional
LLM_MODEL=gpt-4o-mini          # Default: gpt-4o-mini
LLM_TEMPERATURE=0.7            # Default: 0.7
```

## 🤝 Contributing

This is a template - customize it for your needs!

## 📄 License

MIT

## 🙏 Credits

Built with:
- [FastAPI](https://fastapi.tiangolo.com/)
- [LiteLLM](https://github.com/BerriAI/litellm)
- [Pydantic](https://pydantic-docs.helpmanual.io/)

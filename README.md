# AI Function Renamer for IDA Pro

AI-powered IDA Pro plugin for automatic function renaming using decompiled code analysis. Supports batch processing and parallel execution for high-performance workflows.

## Features

- AI-powered function name suggestions (Ollama, OpenAI, Anthropic)
- Batch processing: 5-10 functions per API request
- Parallel execution: Multiple simultaneous workers
- Automatic duplicate name prevention
- Modern dark-themed UI
- Performance: Up to 200x faster than sequential analysis

## Performance

| Mode | Speed | Time for 200K functions |
|------|-------|------------------------|
| Sequential | 0.3 func/s | 7 days |
| Batch (5x3) | 5 func/s | 11 hours |
| Aggressive (10x5) | 16 func/s | 3.3 hours |
| Local Ollama (20x10) | 66 func/s | 50 min |

## Installation

### Method 1: Plugin (Auto-load)

1. Copy `auto_re.py` to IDA plugins folder:
   ```
   Windows: C:\Program Files\IDA Professional 9.2\plugins\
   macOS: /Applications/IDA Professional 9.2/idabin/plugins/
   Linux: /opt/ida-9.2/plugins/
   ```

2. Restart IDA - plugin will auto-load on startup

### Method 2: Script (Manual)

1. Run via `File > Script file > auto_re.py`

### Dependencies

```bash
pip install requests
```

## Quick Start

1. Open binary in IDA Pro
2. Plugin auto-loads or run script manually
3. Configure AI settings:
   - API URL: `http://localhost:11434/v1/chat/completions` (Ollama)
   - Model: `qwen2.5-coder:7b`
4. Click "Load All sub_* Functions"
5. Set performance: Batch Size=5, Workers=3
6. Click "Analyze Selected"
7. Review and click "Apply Renames"

## Configuration

Config saved to: `%APPDATA%/ida_ai_rename_config.json`

```json
{
  "api_url": "http://localhost:11434/v1/chat/completions",
  "api_key": "",
  "model": "qwen2.5-coder:7b",
  "batch_size": 5,
  "parallel_workers": 3
}
```

## API Setup

### Ollama (Recommended - Free, Local)

```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Pull model
ollama pull qwen2.5-coder:7b

# Config
API URL: http://localhost:11434/v1/chat/completions
API Key: (leave empty)
Model: qwen2.5-coder:7b
```

### OpenAI

```
API URL: https://api.openai.com/v1/chat/completions
API Key: sk-...
Model: gpt-4
```

### Anthropic

```
API URL: https://api.anthropic.com/v1/messages
API Key: sk-ant-...
Model: claude-3-5-sonnet-20241022
```

## Advanced Usage

**Performance Tuning**
- Batch Size: Functions per request (5-10 recommended)
- Workers: Parallel threads (3-5 for cloud, 8-10 for local)

**Filtering**
- Use filter box to search functions
- "Select Filtered" to batch select

**Bulk Operations**
- Ctrl+Click or Shift+Click for multi-select
- "Select All" / "Deselect All"

## How It Works

1. Extracts decompiled code, strings, and function calls
2. Builds context with existing function names
3. Sends batch to AI model
4. Validates response and prevents duplicates
5. Applies unique names to IDA database

**Thread Safety**: Main thread prepares IDA data, worker threads handle AI requests only.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Slow performance | Increase batch size and workers |
| API errors | Check URL, key, rate limits |
| Threading errors | Update to latest version (v4.2+) |
| Duplicate names | Auto-handled with _1, _2 suffixes |

## License

MIT License

## Version

v4.2 - Batch processing, parallel execution, duplicate prevention

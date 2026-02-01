# AI Function Renamer for IDA Pro

An intelligent IDA Pro plugin that leverages AI models to automatically suggest meaningful names for functions in reverse engineering workflows. Supports multiple AI providers and features advanced batch processing with parallel execution for high-performance analysis.

## Features

- **AI-Powered Renaming**: Uses decompiled code, strings, and call references to suggest meaningful function names
- **Multiple AI Provider Support**: Compatible with Ollama, OpenAI, Anthropic, and OpenAI-compatible APIs
- **Batch Processing**: Analyze multiple functions in a single API request (5-10x speedup)
- **Parallel Execution**: Run multiple worker threads simultaneously (3-5x additional speedup)
- **Duplicate Prevention**: Automatic detection and prevention of naming conflicts
- **Modern UI**: Clean, professional dark-themed interface with collapsible settings
- **Bulk Operations**: Load, analyze, and rename thousands of functions efficiently
- **Flexible Filtering**: Filter by function name patterns and selection controls

## Performance

- **Sequential Mode**: ~0.3 functions/second
- **Batch Mode (5)**: ~1.7 functions/second (5x faster)
- **Batch + Parallel (5x3)**: ~5 functions/second (15x faster)
- **Aggressive (10x5)**: ~16 functions/second (50x faster)
- **Local Ollama (20x10)**: ~66 functions/second (200x faster)

Example: Analyzing 200,000 functions
- Sequential: 7 days
- Batch + Parallel: 10-11 hours
- Local Ollama: 1-2 hours

## Requirements

- IDA Pro 7.x or later
- Python 3.x
- PyQt5 or PySide6 (depending on IDA SDK version)
- Access to an AI API (Ollama, OpenAI, Anthropic, or compatible)

## Installation

1. Copy `auto_re.py` to your IDA Pro scripts directory
2. Install required dependencies (if not already available):
   ```
   pip install requests
   ```
3. Configure your AI API endpoint and credentials

## Usage

### Basic Workflow

1. **Load Functions**
   - Open your target binary in IDA Pro
   - Run the script: `File > Script file > auto_re.py`
   - Click "Load All sub_* Functions" to load all unnamed functions
   - Or click "Load Current Function" for single-function analysis

2. **Configure AI Settings**
   - Enter API URL (e.g., `http://localhost:11434/v1/chat/completions` for Ollama)
   - Enter API Key (if required)
   - Enter Model Name (e.g., `qwen2.5-coder:7b`)
   - Click "Save Configuration"

3. **Optimize Performance** (Optional)
   - Set Batch Size: 5-10 for balanced performance
   - Set Parallel Workers: 3-5 for cloud APIs, 8-10 for local
   - Click "Save Configuration"

4. **Analyze Functions**
   - Select functions to analyze (or "Select All")
   - Click "Analyze Selected"
   - Choose quantity if analyzing large batches

5. **Review and Apply**
   - Review suggested names in the table
   - Deselect any unwanted suggestions
   - Click "Apply Renames" to rename functions in IDA

### Advanced Features

**Filtering**
- Use the filter box to search for specific function names
- Click "Select Filtered" to select only visible functions

**Batch Operations**
- Select multiple functions using Ctrl+Click or Shift+Click
- Use "Select All" / "Deselect All" for bulk operations

**Performance Tuning**
- Batch Size: Number of functions per API request
  - Higher = faster but less accurate
  - Recommended: 5-10
- Parallel Workers: Number of simultaneous requests
  - Higher = faster but more API load
  - Recommended: 3-5 for cloud, 8-10 for local

## Configuration

Settings are saved to `%APPDATA%/ida_ai_rename_config.json` or `/tmp/ida_ai_rename_config.json`

```json
{
  "api_url": "http://localhost:11434/v1/chat/completions",
  "api_key": "",
  "model": "qwen2.5-coder:7b",
  "batch_size": 5,
  "parallel_workers": 3
}
```

## API Provider Setup

### Ollama (Local - Recommended)

```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Pull a code model
ollama pull qwen2.5-coder:7b

# API URL: http://localhost:11434/v1/chat/completions
# API Key: (leave empty)
# Model: qwen2.5-coder:7b
```

### OpenAI

```
API URL: https://api.openai.com/v1/chat/completions
API Key: sk-...
Model: gpt-4 or gpt-3.5-turbo
```

### Anthropic

```
API URL: https://api.anthropic.com/v1/messages
API Key: sk-ant-...
Model: claude-3-5-sonnet-20241022
```

## How It Works

1. **Code Extraction**
   - Decompiles function using Hex-Rays (if available) or extracts disassembly
   - Collects string references within the function
   - Identifies function calls and API usage

2. **Context Building**
   - Constructs prompt with code, strings, and call information
   - Includes sample of existing function names to avoid conflicts
   - Provides naming guidelines and patterns

3. **AI Analysis**
   - Sends request to configured AI model
   - Receives suggested function name
   - Validates and cleans the response

4. **Duplicate Prevention**
   - Checks against existing function names
   - Automatically appends suffix (_1, _2, etc.) if conflict detected
   - Ensures uniqueness across the entire database

5. **Application**
   - User reviews suggestions
   - Selected names are applied to IDA database
   - Updates propagate through cross-references

## Performance Optimization

### Batch Processing

Instead of analyzing one function at a time, the plugin can batch multiple functions into a single API request:

```
Traditional: 1 request = 1 function = 3s
Batch Mode:  1 request = 5 functions = 3s total (0.6s each)
```

### Parallel Execution

Multiple worker threads make simultaneous API requests:

```
Sequential:  Request 1 -> Request 2 -> Request 3
Parallel:    Request 1
             Request 2  (at the same time)
             Request 3
```

### Thread Safety

The plugin is designed to be IDA-thread-safe:
- Main thread: Prepares all IDA API calls (get_code, get_strings, etc.)
- Worker threads: Only handle network I/O (AI requests)
- No IDA API calls are made from worker threads

## Troubleshooting

**"Function can be called from the main thread only"**
- This should be fixed in the latest version
- Ensure you're using the updated code that prepares IDA data in the main thread

**Slow performance**
- Increase batch size (5-10)
- Increase parallel workers (3-5)
- Consider using local Ollama instead of cloud APIs

**API errors**
- Check API URL and key
- Verify model name is correct
- Check API rate limits
- Reduce batch size and parallel workers

**Duplicate names**
- The plugin automatically prevents duplicates
- Check the "Suggested" column for suffix indicators (_1, _2, etc.)

## License

MIT License - Feel free to use and modify

## Credits

Developed for reverse engineering workflows requiring efficient bulk function renaming. Optimized for large-scale binary analysis with support for modern AI models.

## Version History

- v4.2: Added batch processing and parallel execution
- v4.1: Implemented duplicate name prevention
- v4.0: Major UI redesign with modern dark theme
- v3.x: Multi-provider support
- v2.x: Initial AI integration
- v1.x: Basic functionality

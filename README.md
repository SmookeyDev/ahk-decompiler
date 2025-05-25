## 📝 Table of Contents

- [🧐 About](#-about)
- [⚡ Features](#-features)
- [📁 Project Structure](#-project-structure)
- [💻 Installation](#-installation)
- [🚀 How to Use](#-how-to-use)
- [🔧 Technical Details](#-technical-details)
- [🔒 Security Considerations](#-security-considerations)
- [🎯 Supported Formats](#-supported-formats)
- [💬 Support](#-support)

## 🧐 About

This repository contains an AutoHotkey (AHK) Decompiler/Dumper developed by SmookeyDev. The tool allows you to extract and recover AutoHotkey scripts from compiled executables by analyzing process memory and identifying script patterns.

## ⚡ Features

| Feature                    | Status | Description                                    |
| -------------------------- | ------ | ---------------------------------------------- |
| Script Extraction         | ✅     | Extracts AHK scripts from compiled executables |
| Memory Analysis           | ✅     | Scans process memory for script patterns       |
| Auto Unpack Detection     | ✅     | Waits for packed executables to unpack         |
| GUI Interface             | ✅     | User-friendly graphical interface              |
| Multi-Process Support     | ✅     | Monitors and extracts from child processes     |
| Multi-Script Support      | ✅     | Extracts multiple scripts from single executable |
| Progress Tracking         | ✅     | Real-time progress indicator                   |
| Parallel Processing       | ✅     | Concurrent script extraction from multiple processes |
| Activity Logging          | ✅     | Timestamped logs with color coding             |
| Process Monitoring        | ✅     | Enhanced process list with status tracking     |
| Enhanced Subprocess Support | ✅ | Advanced detection and extraction for subprocesses |

## 📁 Project Structure

The project has been organized into a modular structure for better maintainability:

```
ahk-decompiler/
├── gui/
│   ├── __init__.py
│   └── main_window.py         # GUI interface with modern design
│
├── core/
│   ├── __init__.py
│   ├── extractor.py           # Script extraction logic
│   ├── memory.py              # Memory manipulation utilities
│   └── monitor.py             # Process monitoring functionality
│
├── utils/
│   ├── __init__.py
│   └── constants.py           # Project constants and configuration
│
├── dump_scripts/              # Output directory for extracted scripts
├── main.py                    # Application entry point
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
└── .gitignore                # Git ignore file
```

### 🏗️ Module Overview

#### `gui/` Package
- **`main_window.py`**: Complete GUI implementation using tkinter
  - Multi-phase progress tracking with visual feedback
  - Timestamped, color-coded activity logging
  - Enhanced process monitoring with TreeView
  - Modern design with organized sections and styling

#### `core/` Package
- **`memory.py`**: Low-level memory operations
  - Memory region enumeration (`enum_memory`)
  - Process memory reading (`read_region`)
  - Process handle management (`open_process`, `close_process`)
  - Unpacking detection (`wait_for_unpack`)

- **`extractor.py`**: Core script extraction algorithms
  - Main extraction function (`extract_scripts`)
  - Single process handling (`process_single_pid`)
  - Pattern matching for AHK script signatures
  - UTF-8 decoding and file output

- **`monitor.py`**: Process monitoring and management
  - Child process detection (`monitor_child_processes`)
  - Process information retrieval (`get_process_info`)
  - Safe process termination (`terminate_process_safely`)
  - Active process filtering (`get_active_pids`)

#### `utils/` Package
- **`constants.py`**: Project-wide constants
  - Memory protection flags and access rights
  - Default timeout and configuration values
  - Script detection patterns and heuristics
  - GUI settings and dimensions

#### Root Files
- **`main.py`**: Application entry point with error handling
- **`requirements.txt`**: Python package dependencies
- **`.gitignore`**: Git ignore patterns for Python projects

## 💻 Installation

### Prerequisites

```bash
pip install -r requirements.txt
```

### Dependencies

- Python 3.6+
- psutil (Process and system utilities)
- pywin32 (Windows API access)
- tkinter (GUI framework - usually included with Python)

### Download and Setup

```bash
git clone https://github.com/SmookeyDev/ahk-decompiler.git
cd ahk-decompiler
pip install -r requirements.txt
```

## 🚀 How to Use

### GUI Mode (Recommended)

1. **Launch the application:**
```bash
python main.py
```

2. **Configure extraction settings:**
   - Click "Browse..." to select your compiled AHK executable
   - Enable "Monitor child processes" for comprehensive extraction
   - Enable "Auto-open output folder" for convenience

3. **Start extraction:**
   - Click "🚀 Start Extraction" to begin the process
   - Monitor real-time progress through the multi-phase progress bar
   - Watch detailed activity logs with timestamps and color coding

4. **Monitor progress:**
   - **Phase 1**: 🚀 Initializing - Starting target process
   - **Phase 2**: 👁 Setting up monitoring - Child process detection
   - **Phase 3**: ⏳ Waiting for unpacking - Memory analysis
   - **Phase 4**: 🔍 Detecting child processes - Process enumeration
   - **Phase 5**: 📜 Extracting scripts - Script extraction
   - **Phase 6**: 🧹 Cleanup - Process termination
   - **Phase 7**: ✅ Complete - Results summary

5. **Review results:**
   - Check the activity log for detailed extraction information
   - Click "📁 Open Output Folder" to view extracted scripts
   - Review process status in the monitored processes table

### Advanced Features

- **Stop/Resume**: Use the "⏹ Stop" button to halt extraction at any time
- **Log Management**: Clear logs with the "Clear Log" button for new sessions
- **Real-time Monitoring**: Watch process status updates in real-time
- **Error Handling**: Detailed error messages with troubleshooting suggestions

### Command Line Integration

The modular structure allows for easy integration into other projects:

```python
from core.extractor import extract_scripts, process_single_pid
from core.monitor import get_active_pids
from core.memory import wait_for_unpack

# Extract from a specific PID
scripts_count = extract_scripts(pid, 'output_directory')

# Process with full analysis
result = process_single_pid(pid, is_main_process=True)

# Wait for process unpacking
unpacked = wait_for_unpack(pid, timeout=60)
```

### Advanced Usage

```python
# Import core modules for custom implementations
from core import extract_scripts, monitor_child_processes
from utils.constants import DEFAULT_OUTPUT_DIR, MAX_WORKER_THREADS

# Use individual components
from core.memory import enum_memory, read_region
from core.monitor import get_process_info, terminate_process_safely
```

## 🔧 Technical Details

The decompiler works through several key phases:

### 1. 🔍 **Memory Scanning** (`core.memory`)
- Analyzes process memory regions for readable content
- Uses Windows API (`VirtualQueryEx`, `ReadProcessMemory`)
- Filters by memory protection flags (readable regions only)

### 2. 🎯 **Pattern Matching** (`core.extractor`)
- Searches for "COMPILER" signatures in memory
- Locates script boundaries using null byte patterns
- Applies heuristics to validate script content

### 3. 📝 **Script Extraction** (`core.extractor`)
- Extracts text between signature boundaries
- Handles UTF-8 decoding with error tolerance
- Saves as individual `.ahk` files

### 4. 🔄 **Process Management** (`core.monitor`)
- Monitors parent and child processes
- Handles process lifecycle (startup, unpacking, termination)
- Implements safe process termination

### 5. ⚡ **Parallel Processing** (`gui.main_window`)
- Uses ThreadPoolExecutor for concurrent extraction
- Limits worker threads to prevent system overload
- Provides real-time progress updates

### Memory Permissions

The tool scans memory regions with the following permissions:
- `PAGE_READABLE` (0x02): Read access
- `PAGE_READWRITE` (0x04): Read/Write access  
- `PAGE_EXECUTE_READ` (0x20): Execute/Read access
- `PAGE_EXECUTE_READWRITE` (0x40): Execute/Read/Write access

## 🔒 Security Considerations

- ⚠️ **Administrator Rights**: May require elevated privileges for some processes
- 🛡️ **Antivirus Detection**: Some antivirus software may flag memory analysis tools
- 🔐 **Process Access**: Only works on processes the user has permission to access
- 📊 **Memory Safety**: Uses safe memory reading with error handling

## 🎯 Supported Formats

- ✅ Standard AutoHotkey compiled executables (.exe)
- ✅ MPRESS packed executables (with auto-unpack detection)
- ✅ Multi-script executables
- ⚠️ Encrypted/obfuscated scripts (limited support)

### File Output

Extracted scripts are saved as:
```
dump_scripts/
├── script_1.ahk
├── script_2.ahk
└── script_n.ahk
```

## 💬 Support

For more information and support:

- 🐛 Issues: Create an issue on GitHub
- 💡 Feature Requests: Submit via GitHub issues
- 📚 AutoHotkey Documentation: https://autohotkey.com/docs/

---

<div align="center">
  <sub>Developed with ❤️ by SmookeyDev</sub>
</div> 
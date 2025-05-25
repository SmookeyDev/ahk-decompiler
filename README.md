<p align="center">
  <h1 align="center">AHK Decompiler</h1>
  <p align="center">🔍 Extract and recover AutoHotkey scripts from compiled executables.</p>
  <p align="center">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
    <img src="https://img.shields.io/badge/python-3.13+-blue.svg" alt="Python">
    <img src="https://img.shields.io/badge/platform-Windows-lightgrey.svg" alt="Platform">
    <img src="https://img.shields.io/badge/status-Active-green.svg" alt="Status">
  </p>
</p>

---

## 📝 Table of Contents

- [🧐 About](#-about)
- [⚡ Features](#-features)
- [💻 Installation](#-installation)
- [🚀 How to Use](#-how-to-use)
- [📁 Project Structure](#-project-structure)
- [🔧 Technical Details](#-technical-details)
- [🔒 Security Considerations](#-security-considerations)
- [🎯 Supported Formats](#-supported-formats)
- [💬 Support](#-support)

## 🧐 About

This repository contains an AutoHotkey (AHK) Decompiler/Dumper developed by SmookeyDev. The tool allows you to extract and recover AutoHotkey scripts from compiled executables by analyzing process memory and identifying script patterns.

## ⚡ Features

| Feature                     | Status | Description                                          |
| --------------------------- | ------ | ---------------------------------------------------- |
| Script Extraction           | ✅     | Extracts AHK scripts from compiled executables       |
| Memory Analysis             | ✅     | Scans process memory for script patterns             |
| Resource Extraction         | ✅     | Extracts scripts from RCDATA resources in PE files   |
| Auto Unpack Detection       | ✅     | Waits for packed executables to unpack               |
| GUI Interface               | ✅     | User-friendly graphical interface                    |
| Multi-Process Support       | ✅     | Monitors and extracts from child processes           |
| Multi-Script Support        | ✅     | Extracts multiple scripts from single executable     |
| Progress Tracking           | ✅     | Real-time progress indicator                         |
| Parallel Processing         | ✅     | Concurrent script extraction from multiple processes |
| Activity Logging            | ✅     | Timestamped logs with color coding                   |
| Process Monitoring          | ✅     | Enhanced process list with status tracking           |
| Enhanced Subprocess Support | ✅     | Advanced detection and extraction for subprocesses   |

## 💻 Installation

### Option 1: Pre-built Executable (Recommended for most users)

1. **Download** the latest `ahk-decompiler.exe` from [Releases](https://github.com/SmookeyDev/ahk-decompiler/releases)
2. **Run** the executable directly - no installation needed!
3. **Optional**: Run as administrator for enhanced process access

### Option 2: From Source

#### Prerequisites

- **Python 3.13.3+** (recommended)
- **Windows OS** (required for Windows API access)
- **Administrator privileges** (may be required for some processes)

#### Quick Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/SmookeyDev/ahk-decompiler.git
   cd ahk-decompiler
   ```
2. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```
3. **Run the application:**

   ```bash
   python main.py
   ```

#### Dependencies Overview

The project uses the following Python packages:

- **psutil>=7.0.0** - Process and system utilities
- **pywin32>=310** - Windows API access for memory operations
- **tkinter** - GUI framework (usually included with Python)

All dependencies are automatically installed via `requirements.txt`.

## 🚀 How to Use

### GUI Mode (Recommended)

1. **Launch the application:**

   - **Pre-built Executable**: Double-click `ahk-decompiler.exe`
   - **From Source**: Run `python main.py`
2. **Configure extraction settings:**

   - Click "Browse..." to select your compiled AHK executable
   - Enable "Monitor child processes" for comprehensive extraction
   - Enable "Extract from RCDATA resources" for packed executables
   - Enable "Auto-open output folder" for convenience
3. **Start extraction:**

   - Click "🚀 Start Extraction" to begin the process
   - Monitor real-time progress through the multi-phase progress bar
   - Watch detailed activity logs with timestamps and color coding
4. **Monitor progress phases:**

   - **Phase 0**: 📦 Extracting resources - Analyzing RCDATA resources (if enabled)
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

### Programmatic Usage

The modular structure allows for easy integration into other projects:

```python
from core.extractor import extract_scripts, process_single_pid
from core.monitor import get_active_pids
from core.memory import wait_for_unpack
from core.resources import extract_scripts_from_resources

# Extract from a specific PID
scripts_count = extract_scripts(pid, 'output_directory')

# Extract from RCDATA resources
resource_scripts = extract_scripts_from_resources('executable.exe', 'output_directory')

# Process with full analysis
result = process_single_pid(pid, is_main_process=True)

# Wait for process unpacking
unpacked = wait_for_unpack(pid, timeout=60)
```

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
│   ├── monitor.py             # Process monitoring functionality
│   └── resources.py           # PE resource extraction utilities
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
- **`resources.py`**: PE resource extraction functionality

  - RCDATA resource extraction (`extract_scripts_from_resources`)
  - PE file parsing and analysis (`PEResourceExtractor`)
  - Script detection in resource data
  - Support for multiple encodings and formats

#### `utils/` Package

- **`constants.py`**: Project-wide constants
  - Memory protection flags and access rights
  - Default timeout and configuration values
  - Script detection patterns and heuristics
  - GUI settings and dimensions

## 🔧 Technical Details

The decompiler works through several key phases:

### Memory Scanning & Pattern Matching

- **Memory Analysis**: Scans process memory regions for readable content using Windows API (`VirtualQueryEx`, `ReadProcessMemory`)
- **Pattern Detection**: Searches for "COMPILER" signatures and script boundaries using null byte patterns
- **Script Validation**: Applies heuristics to validate and extract script content

### Resource Extraction

- **PE Analysis**: Parses PE file structure to locate RCDATA resources
- **Multi-Encoding Support**: Handles UTF-8, UTF-16, Latin-1, and CP1252 encodings
- **Pattern Recognition**: Detects AutoHotkey-specific syntax and commands
- **Detection Patterns**: Identifies AutoHotkey directives (`#NoEnv`, `#SingleInstance`), function calls (`SendInput`, `WinActivate`), and hotkey syntax
- **Advantages**: Works without executing the target process, ideal for packed executables

### Process Management

- **Lifecycle Handling**: Manages process startup, unpacking detection, and safe termination
- **Child Process Monitoring**: Tracks and extracts from spawned subprocesses
- **Parallel Processing**: Uses ThreadPoolExecutor for concurrent extraction

### Memory Permissions

The tool scans memory regions with these permissions:

- `PAGE_READABLE` (0x02): Read access
- `PAGE_READWRITE` (0x04): Read/Write access
- `PAGE_EXECUTE_READ` (0x20): Execute/Read access
- `PAGE_EXECUTE_READWRITE` (0x40): Execute/Read/Write access

## 🔒 Security Considerations

- ⚠️ **Administrator Rights**: May require elevated privileges for some processes
- 🛡️ **Antivirus Detection**: Some antivirus software may flag memory analysis tools
- 🔐 **Process Access**: Only works on processes the user has permission to access
- 📊 **Memory Safety**: Uses safe memory reading with comprehensive error handling

## 🎯 Supported Formats

- ✅ **Standard AutoHotkey compiled executables** (.exe)
- ✅ **MPRESS packed executables** (with auto-unpack detection)
- ✅ **Executables with RCDATA resources**
- ✅ **Multi-script executables**
- ⚠️ **Encrypted/obfuscated scripts** (limited support)

### Output Structure

Extracted scripts are saved with clear naming conventions:

```
dump_scripts/
├── script_[pid]_[number].ahk              # From memory analysis
├── script_resource_[number].ahk           # From RCDATA resources
└── script_[pid]_[number]_subprocess.ahk   # From child processes
```



## 💬 Support

For more information and support:

- 🐛 **Issues**: Create an issue on GitHub
- 💡 **Feature Requests**: Submit via GitHub issues
- 📚 **AutoHotkey Documentation**: https://autohotkey.com/docs/

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">
  <sub>Developed with ❤️ by SmookeyDev</sub>
</div>

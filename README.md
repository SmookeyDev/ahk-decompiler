## 📝 Table of Contents

- [🧐 About](#-about)
- [⚡ Features](#-features)
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
| Multi-Script Support      | ✅     | Extracts multiple scripts from single executable |
| Progress Tracking         | ✅     | Real-time progress indicator                   |

### 🔧 Core Functions

#### `extract_scripts(pid, out_dir, progress=None)`

- **Description**: Extracts AutoHotkey scripts from a running process
- **Parameters**:
  - `pid` (int): Process ID of the target executable
  - `out_dir` (string): Output directory for extracted scripts
  - `progress` (function): Optional progress callback function
- **Returns**: Number of scripts extracted

#### `enum_memory(proc)`

- **Description**: Enumerates memory regions of a process
- **Parameters**:
  - `proc` (handle): Process handle
- **Returns**: Generator yielding memory region information

#### `wait_for_unpack(pid, timeout=60, check_interval=1)`

- **Description**: Waits for packed executables to unpack in memory
- **Parameters**:
  - `pid` (int): Process ID
  - `timeout` (int): Maximum wait time in seconds
  - `check_interval` (int): Check interval in seconds
- **Returns**: Boolean indicating success

## 💻 Installation

### Prerequisites

```bash
pip install tkinter pywin32
```

### Dependencies

- Python 3.6+
- tkinter (GUI framework)
- pywin32 (Windows API access)
- ctypes (Memory access)
- subprocess (Process management)

### Download

```bash
git clone https://github.com/SmookeyDev/ahk-decompiler.git
cd ahk-decompiler
```

## 🚀 How to Use

### GUI Mode (Recommended)

1. Run the application:
```bash
python main.py
```

2. Click "Select EXE" and choose your compiled AHK executable

3. Click "Dump" to start the extraction process

4. Wait for the process to complete

5. Click "Open folder" to view extracted scripts

## 🔧 Technical Details

The decompiler works by:

- 🔍 **Memory Scanning**: Analyzes process memory regions for readable content
- 🎯 **Pattern Matching**: Searches for "COMPILER" signatures in memory
- 📝 **Script Extraction**: Extracts text between signature boundaries
- 🧹 **Data Cleaning**: Removes null bytes and decodes UTF-8 content
- 💾 **File Output**: Saves extracted scripts as .ahk files

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
## [v1.0.0] - 2025-01-25

### 🎉 Initial Release - AHK Decompiler

First stable version of AHK Decompiler, a comprehensive tool to extract and recover AutoHotkey scripts from compiled executables.

### ✨ Core Features
- **Script Extraction**: Extracts AHK scripts from compiled executables through memory analysis
- **Memory Analysis**: Scans process memory to identify script patterns
- **Resource Extraction**: Extracts scripts from RCDATA resources in PE files
- **Auto Unpack Detection**: Waits for packed executables to unpack automatically
- **Multi-Process Support**: Monitors and extracts from child processes
- **Multi-Script Support**: Extracts multiple scripts from single executable
- **Parallel Processing**: Concurrent script extraction from multiple processes

### 🎨 User Interface
- **GUI Interface**: Modern and intuitive graphical interface using tkinter
- **Progress Tracking**: Real-time progress indicator with 8 distinct phases
- **Activity Logging**: Detailed logs with timestamps and color coding
- **Process Monitoring**: Enhanced process list with status tracking
- **Real-time Updates**: Real-time status updates
- **Error Handling**: Detailed error messages with troubleshooting suggestions

### 🔧 Advanced Capabilities
- **Enhanced Subprocess Support**: Advanced detection and extraction for subprocesses
- **Multi-Encoding Support**: Support for UTF-8, UTF-16, Latin-1, and CP1252
- **Pattern Recognition**: Detects AutoHotkey-specific syntax and commands
- **Memory Safety**: Safe memory reading with comprehensive error handling
- **Process Lifecycle Management**: Manages initialization, unpacking detection, and safe termination

### 🎯 Supported Formats
- ✅ Standard AutoHotkey executables (.exe)
- ✅ MPRESS packed executables (with auto-unpack detection)
- ✅ Executables with RCDATA resources
- ✅ Multi-script executables
- ⚠️ Encrypted/obfuscated scripts (limited support)

### 🏗️ Technical Architecture
- **Modular Structure**: Modular architecture with clear separation of responsibilities
- **Python 3.13+**: Implemented in Python with minimal dependencies
- **Windows API Integration**: Direct access to Windows APIs for memory operations
- **Cross-Process Communication**: Secure communication between processes
- **Resource Management**: Efficient system resource management

### 📦 Build & Distribution
- **PyInstaller Build**: Automated build with PyInstaller for distribution
- **GitHub Actions CI/CD**: Complete continuous integration and delivery pipeline
- **Automated Releases**: Automatic release system with artifacts
- **Pre-built Executables**: Pre-compiled executables for ease of use

### 🔒 Security & Safety
- **Administrator Rights**: Support for elevated privileges when needed
- **Process Access Control**: Only works on processes the user has permission to access
- **Memory Protection**: Respects system memory permissions
- **Safe Termination**: Safe termination of monitored processes
- **Input Validation**: Robust input file validation

### 📚 Documentation & Support
- **Comprehensive README**: Complete documentation with usage examples
- **API Documentation**: API documentation for programmatic usage
- **Installation Guide**: Installation guides for different scenarios
- **Troubleshooting**: Common troubleshooting section

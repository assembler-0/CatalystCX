# CatalystCX

A modern, secure, and cross-platform C++ single-header library for executing system commands. (made to address `system()` injection vulnerabilities)

CatalystCX provides a fluent API for building and executing commands with security and performance as top priorities. It completely avoids shell-based execution (`system()`) in favor of direct process creation, eliminating injection vulnerabilities while providing comprehensive process monitoring and control.

## Status

![CI/CD](https://github.com/assembler-0/CatalystCX/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/assembler-0/CatalystCX/branch/main/graph/badge.svg)](https://codecov.io/gh/assembler-0/CatalystCX)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Version](https://img.shields.io/badge/Version-0.0.1-brightgreen.svg)

## Features
- **No Shell Execution:** Direct process creation prevents command injection
- **Argument Validation:** Built-in executable verification
- **Safe Defaults:** Secure by default configuration
- **Zero-Copy Operations:** Efficient memory management
- **Async I/O:** Non-blocking pipe reading with `poll()`/`WaitForMultipleObjects`
- **Platform-Specific Optimizations:** `posix_spawn()` on macOS, `CreateProcess` on Windows
- **Signal Handling:** Detailed process termination analysis
- **Resource Usage:** CPU time, memory usage, page faults, context switches
- **Execution Metrics:** Precise timing and performance data
- **Fluent Builder API:** Chainable, intuitive command construction
- **Modern C++20:** Uses latest language features and best practices
- **Single Header:** Easy integration, no external dependencies

## Requirements

- **C++20** compatible compiler:
  - GCC 11+ (Linux/macOS)
  - Clang 14+ (Linux/macOS)
  - MSVC 2022+ (Windows)
- **CMake 3.10+**
- **Platform Support:**
  - Linux (Ubuntu 20.04+, RHEL 8+)
  - macOS (10.15+)
  - Windows (10/11)

## Quick Start

### Single Header Integration

```cpp
#include <CatalystCX.hpp>

int main() {
    auto result = Command("echo").Arg("Hello, World!").Execute();
    std::cout << result.Stdout; // "Hello, World!\n"
    return result.ExitCode;
}
```

### Building from Source

```bash
# Clone and build
git clone https://github.com/assembler-0/CatalystCX.git
cd CatalystCX
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run tests
cmake --build build --target test
```

### Installation

```bash
# System-wide installation
sudo cmake --install build

# Or just copy the header
cp CatalystCX.hpp /your/project/include/
```

## API Usage Guide

### Basic Execution

```cpp
#include <CatalystCX.hpp>
#include <iostream>

int main() {
    CommandResult result = Command("ls").Arg("-l").Execute();

    std::cout << "Exit Code: " << result.ExitCode << std::endl;
    std::cout << "Stdout:\n" << result.Stdout << std::endl;
}
```

### Asynchronous Execution

```cpp
if (auto child = Command("sleep").Arg("5").Spawn()) {
    std::cout << "Process spawned with PID: " << child->GetPid() << std::endl;

    // ... do other work ...

    CommandResult result = child->Wait();
    std::cout << "Sleep command finished." << std::endl;
} else {
    std::cerr << "Failed to spawn process." << std::endl;
}
```

### Timeouts

```cpp
auto result = Command("ping").Arg("8.8.8.8")
                  .Timeout(std::chrono::seconds(2))
                  .Execute();

if (result.TimedOut) {
    std::cout << "Command timed out!" << std::endl;
}
```

### Environment Variables and Working Directory

```cpp
auto result = Command("printenv")
    .Arg("MY_VAR")
    .Environment("MY_VAR", "Hello")
    .WorkingDirectory("/tmp")
    .Execute();

std::cout << result.Stdout; // "Hello\n"
```

### Signal Handling and Process Information

```cpp
auto child = Command("sleep").Arg("10").Spawn();
if (child) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    child->Kill(SIGTERM);
    
    auto result = child->Wait();
    if (result.KilledBySignal) {
        std::cout << "Process killed by signal: " 
                  << SignalInfo::GetSignalName(result.TerminatingSignal) 
                  << std::endl;
    }
    
    // Get human-readable process info
    std::cout << SignalInfo::GetProcessInfo(result) << std::endl;
}
```

### Resource Monitoring

```cpp
CommandResult result = Command("your-intensive-command").Execute();

std::cout << "Exit Code: " << result.ExitCode << std::endl;
std::cout << "Execution Time: " << result.ExecutionTime.count() << "s" << std::endl;

#ifdef __linux__
std::cout << "CPU Usage:\n";
std::cout << "  User: " << result.Usage.UserCpuTime << "μs\n";
std::cout << "  System: " << result.Usage.SystemCpuTime << "μs\n";
std::cout << "Memory:\n";
std::cout << "  Peak RSS: " << result.Usage.MaxResidentSetSize << " KB\n";
std::cout << "  Page Faults: " << result.Usage.MajorPageFaults << std::endl;
#elif defined(_WIN32)
std::cout << "Peak Memory: " << result.Usage.PeakWorkingSetSize << " bytes\n";
std::cout << "Page Faults: " << result.Usage.PageFaultCount << std::endl;
#endif
```

## Advanced Usage

### Multiple Arguments
```cpp
std::vector<std::string> args = {"arg1", "arg2"};
cmd.Args(args);

std::array<std::string, 3> args = {"arg1", "arg2", "arg3"};
cmd.Args(args);

std::initializer_list<std::string> args = {"arg1", "arg2"};
cmd.Args(args);

cmd.Args(std::vector<std::string_view>{"arg1", "arg2"});

// Or C-style arrays:
const char* args[] = {"arg1", "arg2"};
cmd.Args(args);

// Or use builtin expansion:
cmd.Args(utils::Expand({"arg1", "arg2"}));
```

### Batch Processing

```cpp
std::vector<std::string> files = {"file1.txt", "file2.txt", "file3.txt"};
std::vector<std::future<CommandResult>> futures;

for (const auto& file : files) {
    futures.push_back(std::async(std::launch::async, [&file]() {
        return Command("wc").Args(Utils::Expand({"-l", file})).Execute();
    }));
}

for (auto& future : futures) {
    auto result = future.get();
    std::cout << "Lines: " << result.Stdout;
}
```

### Error Recovery

```cpp
CommandResult result;
int retries = 3;

while (retries-- > 0) {
    result = Command("flaky-command")
        .Timeout(std::chrono::seconds(30))
        .Execute();
    
    if (result.ExitCode == 0) break;
    
    std::cerr << "Attempt failed, retries left: " << retries << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));
}
```

## Testing

```bash
# Run full test suite
cmake --build build --target test

# Run with sanitizers
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined"
cmake --build build-debug --target test

# Generate coverage report
cmake -B build-coverage -DCMAKE_CXX_FLAGS="--coverage"
cmake --build build-coverage --target test
lcov --capture --directory build-coverage --output-file coverage.info
```


### Development Setup

```bash
# Install development dependencies
sudo apt-get install cppcheck clang-tidy valgrind lcov

# Run static analysis
cppcheck --enable=all --std=c++20 CatalystCX.hpp
clang-tidy CatalystCX.cpp -checks='*'
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request, open an issue, or contact me directly. :)

## License

This project is licensed under the [GPLv3 License—](LICENSE)see the LICENSE file for details.

---

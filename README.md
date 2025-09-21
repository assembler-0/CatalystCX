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
    std::cout << result.Vaule().Stdout; // "Hello, World!\n"
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
    CommandResult result = Command("ls").Arg("-l").Execute().Value();

    std::cout << "Exit Code: " << result.ExitCode << std::endl;
    std::cout << "Stdout:\n" << result.Stdout << std::endl;
}
```

### Asynchronous Execution

```cpp
#include <CatalystCX.hpp>
#include <iostream>

int main() {
    auto spawn = Command("sleep").Arg("5").Spawn(); // Errors::Result<Child>
    if (spawn.IsError()) {
        std::cerr << "Failed to spawn process: " << spawn.Error().FullMessage() << std::endl;
        return 1;
    }

    const auto& child = spawn.Value();
    std::cout << "Process spawned with PID: " << child.GetPid() << std::endl;

    // ... do other work ...

    auto wait = child.Wait(); // Errors::Result<CommandResult>
    if (wait.IsError()) {
        std::cerr << "Wait failed: " << wait.Error().FullMessage() << std::endl;
        return 1;
    }

    const auto& result = wait.Value();
    std::cout << "Sleep command finished. Exit: " << result.ExitCode << std::endl;
}
```

### Timeouts

```cpp
auto result = Command("ping").Arg("8.8.8.8")
                  .Timeout(std::chrono::seconds(2))
                  .Execute();

if (result.Value().TimedOut) {
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

std::cout << result.Value().Stdout; // "Hello\n"
```

### Signal Handling and Process Information

```cpp
#include <CatalystCX.hpp>
#include <thread>
#include <iostream>

int main() {
    auto spawn = Command("sleep").Arg("10").Spawn();
    if (spawn.IsError()) {
        std::cerr << "Spawn failed: " << spawn.Error().FullMessage() << std::endl;
        return 1;
    }
    Child child = spawn.Value();

    std::this_thread::sleep_for(std::chrono::seconds(1));

#ifndef _WIN32
    auto killRes = child.Kill(SIGTERM);
#else
    auto killRes = child.Kill(); // Windows ignores POSIX signals
#endif
    if (killRes.IsError()) {
        std::cerr << "Kill failed: " << killRes.Error().FullMessage() << std::endl;
    }

    auto wait = child.Wait();
    if (wait.IsError()) {
        std::cerr << "Wait failed: " << wait.Error().FullMessage() << std::endl;
        return 1;
    }

    const auto& result = wait.Value();
    if (result.KilledBySignal) {
        std::cout << "Process killed by signal: "
#ifndef _WIN32
                  << SignalInfo::GetSignalName(result.TerminatingSignal)
#else
                  << result.TerminatingSignal
#endif
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
Command cmd("myprog");

// std::vector
std::vector<std::string> v = {"arg1", "arg2"};
cmd.Args(v);

// std::array
std::array<std::string, 3> a = {"arg1", "arg2", "arg3"};
cmd.Args(a);

// initializer_list
cmd.Args({"arg1", "arg2"});

// std::vector<string_view>
cmd.Args(std::vector<std::string_view>{"arg1", "arg2"});

// C-style array
const char* cargs[] = {"arg1", "arg2"};
cmd.Args(cargs);

// Built-in expansion helper
cmd.Args(Utils::Expand({"arg1", "arg2"}));
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
    
    if (result.Vaule().ExitCode == 0) break;
    
    std::cerr << "Attempt failed, retries left: " << retries << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));
}
```

## Error Handling

CatalystCX uses a lightweight result type for robust, explicit error handling.

- Errors::Result<T>: holds either a value T or an Errors::ErrorInfo.
- Errors::Result<void>: holds success or an error.
- CommandResult also includes ExecutionError for issues that occurred during execution (e.g., timeouts).

Examples:

```cpp
// Spawning a process
auto spawn = Command("does-not-exist").Spawn();
if (spawn.IsError()) {
    const auto& e = spawn.Error();
    std::cerr << "Spawn failed: " << e.Message << "\nDetails: " << e.Details
              << "\nSuggestion: " << e.Suggestion << std::endl;
}

// Waiting on a child
auto spawn2 = Command("echo").Arg("hi").Spawn();
if (spawn2.IsOk()) {
    auto wait = spawn2.Value().Wait();
    if (wait.IsOk()) {
        const auto& res = wait.Value();
        if (res.HasExecutionError()) {
            std::cerr << res.ExecutionError.FullMessage() << std::endl;
        }
    } else {
        std::cerr << wait.Error().FullMessage() << std::endl;
    }
}

// Inspecting CommandResult for summary
auto res = Command("sh").Arg("-c").Arg("exit 7").Execute();
if (!res.IsSuccessful()) {
    std::cerr << res.GetErrorSummary() << std::endl;
}
```

### Error Codes and Categories

ErrorInfo contains:
- Code (ErrorCode): e.g., ExecutableNotFound, SpawnFailed, ExecutionTimeout
- Category (ErrorCategory): Validation, System, Process, Timeout, Permission, Resource, Platform
- Message, Details, Suggestion, and SystemErrorCode

## API Reference (Quick)

- Command
  - Arg(string), Args(range), Environment(key, value), WorkingDirectory(path), Timeout(duration)
  - Execute() -> Errors::Result<CommandResult>
  - Spawn() -> Errors::Result<Child>
- Child
  - GetPid()
  - Wait([timeout]) -> Errors::Result<CommandResult>
  - Kill([signal]) -> Errors::Result<void>
- CommandResult
  - ExitCode, Stdout, Stderr, ExecutionTime, TimedOut
  - Signal info: KilledBySignal, TerminatingSignal, CoreDumped, Stopped, StopSignal
  - Usage: platform-specific resource usage fields
  - ExecutionError: Errors::ErrorInfo
  - helpers: IsSuccessful(), HasOutput(), HasExecutionError(), GetErrorSummary()

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

This project is licensed under the GPLv3. See the [LICENSE](LICENSE) file for details.

---

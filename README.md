# CatalystCX

A modern, secure, and flexible C++ single-header library for executing system commands.

CatalystCX provides a staged pipeline for building and executing commands, designed with security and performance in mind. It avoids shell-based execution (`system()`) in favor of direct process creation, preventing injection vulnerabilities. The API is designed to be intuitive and chainable, following modern C++ best practices.

## Features

- **Secure by Design:** Commands and arguments are passed directly to the OS, avoiding shell interpretation and injection vulnerabilities.
- **Fluent Builder API:** A chainable, easy-to-use builder pattern for constructing commands.
- **Standard Stream Capture:** Capture `stdout` and `stderr` with ease.
- **Asynchronous Execution:** Spawn processes and manage them asynchronously.
- **Timeouts:** Set timeouts for commands to prevent them from running indefinitely.
- **Resource Monitoring (Linux):** Get detailed information about execution time, CPU usage, and memory consumption.
- **Robust Error Handling:** Uses `std::optional` to safely handle process spawning failures.
- **Single Header:** Easy to integrate into any project.

## Requirements

- C++20 compatible compiler (e.g., GCC 10+, Clang 11+)
- CMake 3.10+

## Building the Project

```bash
# Configure the project
cmake -B build

# Build the example executable
cmake --build build
```

## Running the Example

To run the example application included in `CatalystCX.cpp`, use the `run` target:

```bash
cmake --build build --target run
```

## Installation

To install the `CatalystCX.hpp` header to your system's include directory (e.g., `/usr/local/include`), use the `install` target:

```bash
# First, build the project
cmake --build build

# Then, install the header
sudo cmake --install build
```

## API Usage Guide

### Basic Execution

To execute a command and wait for it to complete, use the `Status()` method. It returns a `CommandResult` struct.

```cpp
#include "CatalystCX.hpp"
#include <iostream>

int main() {
    CommandResult result = Command("ls").Arg("-l").Status();

    std::cout << "Exit Code: " << result.ExitCode << std::endl;
    std::cout << "Stdout:\n" << result.Stdout << std::endl;
}
```

### Asynchronous Execution

To spawn a process without blocking, use the `Spawn()` method. This returns an `std::optional<Child>`. You can `Wait()` for the result later.

```cpp
if (auto child = Command("sleep").Arg("5").Spawn()) {
    std::cout << "Process spawned with PID: " << child->GetPid() << std::endl;

    // ... do other work ...

    CommandResult result = child->Wait();
    std::cout << "Sleep command finished."
 << std::endl;
} else {
    std::cerr << "Failed to spawn process."
 << std::endl;
}
```

### Timeouts

Set a timeout for a command using the `Timeout()` method. The `CommandResult` will indicate if the command timed out.

```cpp
auto result = Command("ping").Arg("8.8.8.8")
                  .Timeout(std::chrono::seconds(2))
                  .Status();

if (result.TimedOut) {
    std::cout << "Command timed out!"
 << std::endl;
}
```

### Error Handling

`Spawn()` returns a `std::optional<Child>`. Always check if it contains a value before using it.

```cpp
if (auto child = Command("this-command-does-not-exist").Spawn()) {
    // This block will not be executed
    child->Wait();
} else {
    std::cerr << "Failed to spawn command, as expected."
 << std::endl;
}
```

### Accessing Detailed Results

The `CommandResult` struct contains detailed information about the execution.

```cpp
CommandResult result = Command("your-command").Status();

std::cout << "Exit Code: " << result.ExitCode << std::endl;
std::cout << "Execution Time: " << result.ExecutionTime.count() << "s"
 << std::endl;

#ifdef __linux__
    std::cout << "User CPU Time: " << result.Usage.UserCpuTime << "us"
 << std::endl;
    std::cout << "System CPU Time: " << result.Usage.SystemCpuTime << "us"
 << std::endl;
    std::cout << "Max Memory Usage: " << result.Usage.MaxResidentSetSize << " KB"
 << std::endl;
#endif
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request.

## License

This project is licensed under the GPLv3 License.

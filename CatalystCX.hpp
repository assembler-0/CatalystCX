// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 assembler-0
// Licensed under GPL-3.0-or-later

/**
 * @brief CatalystCX - A cross-platform single-file C++ library/module for executing and managing external processes (or commands).
 * @file CatalystCX.hpp
 * @version 0.0.1
 * @date 20-09-25 (last modified)
 * @author assembler-0
 */

#pragma once
#ifndef CATALYSTCX_HPP
#define CATALYSTCX_HPP

#include <algorithm>
#include <array>
#include <chrono>
#include <concepts>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <future>
#include <optional>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <variant>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <io.h>
#include <fcntl.h>
#include <processthreadsapi.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef __APPLE__
#include <spawn.h>
extern char **environ;
#endif
#endif

#define CatalystCX_VERSION "0.0.1"
#define CatalystCX_VERSION_MAJOR 0
#define CatalystCX_VERSION_MINOR 0
#define CatalystCX_VERSION_PATCH 1

namespace fs = std::filesystem;

// Constants
namespace Constants {
    constexpr int EXIT_FAIL_EC = 127;
    constexpr size_t PIPE_BUFFER_SIZE = 8192;
    constexpr size_t STDERR_BUFFER_SIZE = 4096;
    constexpr int POLL_TIMEOUT_MS = 50;
    constexpr auto SLEEP_INTERVAL = std::chrono::milliseconds(10);
}

// Concepts
namespace Concepts {
    template<typename T>
    concept StringLike = std::convertible_to<T, std::string_view>;

    template<typename T>
    concept DurationLike = requires(T t) {
        std::chrono::duration_cast<std::chrono::duration<double>>(t);
    };
}

// Error Handling System
namespace Errors {
    enum class ErrorCategory : uint8_t {
        None = 0,
        Validation,     // Invalid arguments, missing executable, etc.
        System,         // System call failures (pipe, fork, etc.)
        Process,        // Process-related errors (spawn failure, etc.)
        Timeout,        // Timeout-related errors
        Permission,     // Permission-related errors
        Resource,       // Resource exhaustion (memory, file descriptors, etc.)
        Platform        // Platform-specific errors
    };

    enum class ErrorCode : uint16_t {
        // Success
        Success = 0,

        // Validation Errors (100-199)
        EmptyCommand = 100,
        ExecutableNotFound = 101,
        InvalidArguments = 102,
        InvalidWorkingDirectory = 103,

        // System Errors (200-299)
        PipeCreationFailed = 200,
        ForkFailed = 201,
        ExecFailed = 202,
        EnvironmentSetupFailed = 203,
        FileDescriptorError = 204,

        // Process Errors (300-399)
        SpawnFailed = 300,
        ProcessAlreadyFinished = 301,
        ProcessNotFound = 302,
        KillFailed = 303,
        WaitFailed = 304,

        // Timeout Errors (400-499)
        ExecutionTimeout = 400,
        WaitTimeout = 401,

        // Permission Errors (500-599)
        ExecutePermissionDenied = 500,
        DirectoryAccessDenied = 501,

        // Resource Errors (600-699)
        OutOfMemory = 600,
        TooManyOpenFiles = 601,
        ProcessLimitReached = 602,

        // Platform Errors (700-799)
        WindowsApiError = 700,
        PosixError = 701,
        MacOSError = 702,

        // Unknown
        Unknown = 999
    };

    struct ErrorInfo {
        ErrorCode Code = ErrorCode::Success;
        ErrorCategory Category = ErrorCategory::None;
        std::string Message;
        std::string Details;        // Platform-specific details
        std::string Suggestion;     // Recovery suggestion
        int SystemErrorCode = 0;    // Platform errno/GetLastError()

        [[nodiscard]] constexpr bool IsSuccess() const noexcept {
            return Code == ErrorCode::Success;
        }

        [[nodiscard]] constexpr bool IsFailure() const noexcept {
            return !IsSuccess();
        }

        [[nodiscard]] std::string FullMessage() const {
            std::string full = Message;
            if (!Details.empty()) {
                full += " (Details: " + Details + ")";
            }
            if (!Suggestion.empty()) {
                full += " Suggestion: " + Suggestion;
            }
            if (SystemErrorCode != 0) {
                full += " [System Error: " + std::to_string(SystemErrorCode) + "]";
            }
            return full;
        }
    };

    // Result-like type for better error handling
    template<typename T>
    class Result {
        std::variant<T, ErrorInfo> data_;
    public:
        constexpr explicit Result(T&& value) noexcept : data_(std::move(value)) {}
        constexpr explicit Result(const T& value) : data_(value) {}
        constexpr explicit Result(ErrorInfo error) noexcept : data_(std::move(error)) {}

        [[nodiscard]] constexpr bool IsOk() const noexcept {
            return std::holds_alternative<T>(data_);
        }

        [[nodiscard]] constexpr bool IsError() const noexcept {
            return !IsOk();
        }

        [[nodiscard]] constexpr const T& Value() const& {
            if (IsError()) {
                throw std::runtime_error("Attempted to access value of error result: " + Error().FullMessage());
            }
            return std::get<T>(data_);
        }

        [[nodiscard]] constexpr T&& Value() && {
            if (IsError()) {
                throw std::runtime_error("Attempted to access value of error result: " + Error().FullMessage());
            }
            return std::get<T>(std::move(data_));
        }

        [[nodiscard]] constexpr const ErrorInfo& Error() const& {
            if (IsOk()) {
                static const ErrorInfo success{};
                return success;
            }
            return std::get<ErrorInfo>(data_);
        }

        [[nodiscard]] constexpr T ValueOr(T&& default_value) const& {
            return IsOk() ? Value() : std::move(default_value);
        }

        // Monadic operations
        template<typename F>
        [[nodiscard]] constexpr auto Map(F&& func) const& -> Result<std::invoke_result_t<F, const T&>> {
            if (IsError()) {
                return Error();
            }
            return func(Value());
        }

        template<typename F>
        [[nodiscard]] constexpr auto AndThen(F&& func) const& -> std::invoke_result_t<F, const T&> {
            if (IsError()) {
                return Error();
            }
            return func(Value());
        }
    };

    // Specialization for void operations
    template<>
    class Result<void> {
        std::optional<ErrorInfo> error_;

    public:
        constexpr Result() noexcept : error_(std::nullopt) {}
        constexpr explicit Result(ErrorInfo error) noexcept : error_(std::move(error)) {}

        [[nodiscard]] constexpr bool IsOk() const noexcept {
            return !error_.has_value();
        }

        [[nodiscard]] constexpr bool IsError() const noexcept {
            return error_.has_value();
        }

        [[nodiscard]] constexpr const ErrorInfo& Error() const& {
            if (IsOk()) {
                static const ErrorInfo success{};
                return success;
            }
            return *error_;
        }

        constexpr void Value() const {
            if (IsError()) throw std::runtime_error("Attempted to access value of error result: " + Error().FullMessage());

        }

        template<typename F>
        [[nodiscard]] constexpr auto AndThen(F&& func) const -> std::invoke_result_t<F> {
            if (IsError()) return Error();
            return func();
        }
    };

    // Error creation helpers
    [[nodiscard]] inline ErrorInfo MakeError(ErrorCode code, std::string message, 
                                             std::string details = "", std::string suggestion = "") {
        ErrorInfo error;
        error.Code = code;
        error.Message = std::move(message);
        error.Details = std::move(details);
        error.Suggestion = std::move(suggestion);

        // Determine category from code
        if (const auto code_val = static_cast<uint16_t>(code); code_val >= 100 && code_val < 200) error.Category = ErrorCategory::Validation;
        else if (code_val >= 200 && code_val < 300) error.Category = ErrorCategory::System;
        else if (code_val >= 300 && code_val < 400) error.Category = ErrorCategory::Process;
        else if (code_val >= 400 && code_val < 500) error.Category = ErrorCategory::Timeout;
        else if (code_val >= 500 && code_val < 600) error.Category = ErrorCategory::Permission;
        else if (code_val >= 600 && code_val < 700) error.Category = ErrorCategory::Resource;
        else if (code_val >= 700 && code_val < 800) error.Category = ErrorCategory::Platform;

#ifdef _WIN32
        error.SystemErrorCode = static_cast<int>(GetLastError());
#else
        error.SystemErrorCode = errno;
#endif

        return error;
    }

    [[nodiscard]] inline ErrorInfo MakeSystemError(const ErrorCode code, std::string message) {
        std::string details;
        std::string suggestion;

#ifdef _WIN32
        const DWORD error_code = GetLastError();
        LPSTR message_buffer = nullptr;
        const size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                         nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                         reinterpret_cast<LPSTR>(&message_buffer), 0, nullptr);
        if (message_buffer) {
            details = std::string(message_buffer, size);
            LocalFree(message_buffer);
        }
#else
        const int err = errno; // snapshot
        details = std::strerror(err);
        switch (err) {
            case EACCES: suggestion = "Check file permissions and executable bit"; break;
            case ENOENT: suggestion = "Verify the executable path exists and is in PATH"; break;
            case ENOMEM: suggestion = "Free up system memory or increase limits"; break;
            case EMFILE: suggestion = "Close unused file descriptors or increase ulimits"; break;
            case EAGAIN: suggestion = "Retry the operation or check system process limits"; break;
            default: break;
        }
#endif

        return MakeError(code, std::move(message), std::move(details), std::move(suggestion));
    }
}

struct CommandResult {
    int ExitCode{};
    std::string Stdout;
    std::string Stderr;
    std::chrono::duration<double> ExecutionTime{};
    bool TimedOut = false;

    bool KilledBySignal = false;
    int TerminatingSignal = 0;
    bool CoreDumped = false;
    bool Stopped = false;
    int StopSignal = 0;

    // Enhanced error information
    Errors::ErrorInfo ExecutionError{};  // Details about any execution issues

    struct ResourceUsage {
#if defined(__linux__)
        long UserCpuTime = 0;
        long SystemCpuTime = 0;
        long MaxResidentSetSize = 0;
        long MinorPageFaults = 0;
        long MajorPageFaults = 0;
        long VoluntaryContextSwitches = 0;
        long InvoluntaryContextSwitches = 0;
#elif defined(_WIN32)
        FILETIME UserTime{};
        FILETIME KernelTime{};
        SIZE_T PeakWorkingSetSize = 0;
        SIZE_T PageFaultCount = 0;
#endif
    } Usage{};

    [[nodiscard]] constexpr bool IsSuccessful() const noexcept {
        return ExitCode == 0 && !TimedOut && !KilledBySignal && ExecutionError.IsSuccess();
    }

    [[nodiscard]] constexpr bool HasOutput() const noexcept {
        return !Stdout.empty() || !Stderr.empty();
    }

    [[nodiscard]] constexpr bool HasExecutionError() const noexcept {
        return ExecutionError.IsFailure();
    }

    [[nodiscard]] std::string GetErrorSummary() const {
        if (ExecutionError.IsFailure()) {
            return ExecutionError.FullMessage();
        }
        if (TimedOut) {
            return "Process execution timed out";
        }
        if (KilledBySignal) {
            return "Process was killed by signal " + std::to_string(TerminatingSignal);
        }
        if (ExitCode != 0) {
            return "Process exited with non-zero code: " + std::to_string(ExitCode);
        }
        return "No errors";
    }
};

class Child {
public:
#ifdef _WIN32
    Child(HANDLE process, HANDLE thread, HANDLE stdout_handle, HANDLE stderr_handle)
        : ProcessHandle(process), ThreadHandle(thread), StdoutHandle(stdout_handle), StderrHandle(stderr_handle), PipesClosed(false) {
        ProcessId = GetProcessId(process);
    }

    ~Child() {
        if (ProcessHandle != INVALID_HANDLE_VALUE) CloseHandle(ProcessHandle);
        if (ThreadHandle != INVALID_HANDLE_VALUE) CloseHandle(ThreadHandle);
        if (!PipesClosed) {
            if (StdoutHandle != INVALID_HANDLE_VALUE) CloseHandle(StdoutHandle);
            if (StderrHandle != INVALID_HANDLE_VALUE) CloseHandle(StderrHandle);
        }
    }
#else
    Child(const pid_t pid, const int stdout_fd, const int stderr_fd)
        : ProcessId(pid), StdoutFd(stdout_fd), StderrFd(stderr_fd) {}
#endif

    [[nodiscard]] Errors::Result<CommandResult> Wait(std::optional<std::chrono::duration<double>> timeout = std::nullopt) const;
    [[nodiscard]] pid_t GetPid() const { return ProcessId; }

#ifdef _WIN32
    [[nodiscard]] Errors::Result<void> Kill(int signal = 0) const;
#else
    [[nodiscard]] Errors::Result<void> Kill(int signal = SIGTERM) const;
#endif

private:
    pid_t ProcessId;
#ifdef _WIN32
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    HANDLE StdoutHandle;
    HANDLE StderrHandle;
    mutable bool PipesClosed;
#else
    int StdoutFd;
    int StderrFd;
#endif
};

class Command {
public:
    template<Concepts::StringLike T>
    explicit Command(T&& executable) : Executable(std::forward<T>(executable)) {
        Arguments.reserve(8); // Reserve space for typical argument count
    }

    template<Concepts::StringLike T>
    Command& Arg(T&& argument) {
        Arguments.emplace_back(std::forward<T>(argument));
        return *this;
    }

    template<std::ranges::range R>
    requires Concepts::StringLike<std::ranges::range_value_t<R>>
    Command& Args(R&& arguments) {
        if constexpr (std::ranges::sized_range<R>) {
            Arguments.reserve(static_cast<size_t>(std::ranges::size(arguments)));
        }
        std::ranges::copy(arguments, std::back_inserter(Arguments));
        return *this;
    }

    template<Concepts::StringLike T>
    Command& WorkingDirectory(T&& path) {
        WorkDir = std::forward<T>(path);
        return *this;
    }

    template<Concepts::StringLike K, Concepts::StringLike V>
    Command& Environment(K&& key, V&& value) {
        EnvVars.emplace(std::forward<K>(key), std::forward<V>(value));
        return *this;
    }

    template<Concepts::DurationLike D>
    Command& Timeout(D&& duration) {
        TimeoutDuration = std::chrono::duration_cast<std::chrono::duration<double>>(
            std::forward<D>(duration));
        return *this;
    }

    [[nodiscard]] Errors::Result<CommandResult> Execute();
    [[nodiscard]] Errors::Result<Child> Spawn();

private:
    std::string Executable;
    std::vector<std::string> Arguments;
    std::optional<std::string> WorkDir;
    std::unordered_map<std::string, std::string> EnvVars;
    std::optional<std::chrono::duration<double>> TimeoutDuration;
};

class AsyncPipeReader {
    struct PipeData {
#ifdef _WIN32
        HANDLE Handle;
#else
        int Fd;
#endif
        std::string Buffer;
        bool Finished = false;

        explicit PipeData(
#ifdef _WIN32
            HANDLE handle
#else
                const int fd
#endif
        ) :
#ifdef _WIN32
            Handle(handle)
#else
            Fd(fd)
#endif
        {
            Buffer.reserve(Constants::PIPE_BUFFER_SIZE);
        }
    };

    using Buffer = std::array<char, Constants::PIPE_BUFFER_SIZE>;

public:
#ifdef _WIN32
    [[nodiscard]] static std::pair<std::string, std::string> ReadPipes(HANDLE stdout_handle, HANDLE stderr_handle);
private:
    static bool ReadFromPipe(PipeData& pipe_data, Buffer& buffer) noexcept;
#else
    [[nodiscard]] static std::pair<std::string, std::string> ReadPipes(int stdout_fd, int stderr_fd);
private:
    static bool ReadFromPipe(PipeData& pipe_data, Buffer& buffer) noexcept;
    static bool IsPipeOpen(int fd) noexcept;
#endif
};

namespace Utils {
    template<Concepts::StringLike T>
    [[nodiscard]] constexpr bool IsEmpty(const T& str) noexcept {
        return std::string_view(str).empty();
    }

    template<std::ranges::range R>
    [[nodiscard]] constexpr bool IsEmpty(const R& range) noexcept {
        return std::ranges::empty(range);
    }

    [[nodiscard]] inline std::string QuoteArgumentWindows(const std::string_view arg) {
        if (const bool need_quotes = arg.find_first_of(" \t\"") != std::string_view::npos; !need_quotes) return std::string(arg);

        std::string result;
        result.reserve(arg.size() + 10); // Reserve space for quotes and escaping
        result.push_back('"');

        size_t backslash_count = 0;
        for (const char c : arg) {
            if (c == '\\') {
                ++backslash_count;
                continue;
            }
            if (c == '"') {
                result.append(backslash_count * 2 + 1, '\\');
                result.push_back('"');
                backslash_count = 0;
                continue;
            }
            if (backslash_count > 0) {
                result.append(backslash_count, '\\');
                backslash_count = 0;
            }
            result.push_back(c);
        }
        if (backslash_count > 0) {
            result.append(backslash_count * 2, '\\');
        }
        result.push_back('"');
        return result;
    }

    /**
     * @brief Expand initializer list or any range-like container into a std::vector
     * @details This helper allows passing braced-init-lists to Command::Args()
     * @example Command("git").Args(Utils::Expand({"commit", "-m", "message"}))
     */
    template<Concepts::StringLike T>
    [[nodiscard]] constexpr std::vector<std::string> Expand(std::initializer_list<T> args) {
        std::vector<std::string> result;
        result.reserve(args.size());
        for (const auto& arg : args) result.emplace_back(arg);
        return result;
    }

    /**
     * @brief Expand any range into a std::vector (for consistency)
     * @details Provides a uniform interface for all container types
     */
    template<std::ranges::range R>
    requires Concepts::StringLike<std::ranges::range_value_t<R>>
    [[nodiscard]] constexpr std::vector<std::string> Expand(R&& range) {
        std::vector<std::string> result;
        if constexpr (std::ranges::sized_range<R>) result.reserve(std::ranges::size(range));
        for (const auto& item : range) result.emplace_back(item);
        return result;
    }
}

class ExecutionValidator {
public:
    template<Concepts::StringLike T>
    [[nodiscard]] static bool IsFileExecutable(T&& path) {
        const std::string_view path_view(path);
#ifdef _WIN32
        const DWORD attrs = GetFileAttributesA(std::string(path_view).c_str());
        return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
#else
        return access(std::string(path_view).c_str(), X_OK) == 0;
#endif
    }

    template<Concepts::StringLike T>
    [[nodiscard]] static bool IsCommandExecutable(T&& command) {
        const std::string_view cmd_view(command);
#ifdef _WIN32
        const std::wstring wcommand(cmd_view.begin(), cmd_view.end());
        const DWORD needed = SearchPathW(nullptr, wcommand.c_str(), L".exe", 0, nullptr, nullptr);
        return needed > 0;
#else
        if (cmd_view.find('/') != std::string_view::npos) {
            return access(std::string(cmd_view).c_str(), X_OK) == 0;
        }

        const char* path_env = getenv("PATH");
        if (!path_env) return false;
        const std::string_view path_str(path_env);
        return std::ranges::any_of(
            std::views::split(path_str, ':'),
            [cmd_view](const auto& dir_range) {
                const std::string_view dir{dir_range.begin(), dir_range.end()};
                if (dir.empty()) return false;
                const auto full_path = std::filesystem::path(dir) / std::string(cmd_view);
                return access(full_path.c_str(), X_OK) == 0;
            });

#endif
    }

    template<std::ranges::range R>
    requires Concepts::StringLike<std::ranges::range_value_t<R>>
    [[nodiscard]] static bool CanExecuteCommand(const R& args) {
        return !Utils::IsEmpty(args) && IsCommandExecutable(*std::ranges::begin(args));
    }
};

// Windows implementations
#ifdef _WIN32
inline Errors::Result<CommandResult> Child::Wait(std::optional<std::chrono::duration<double>> timeout) const {
    const auto start_time = std::chrono::steady_clock::now();
    CommandResult result;

    // Start asynchronous pipe reader to avoid deadlocks on full pipes
    auto reader_future = std::async(std::launch::async, AsyncPipeReader::ReadPipes, StdoutHandle, StderrHandle);

    const DWORD wait_time = timeout ? static_cast<DWORD>(timeout->count() * 1000.0) : INFINITE;
    const DWORD wait_result = WaitForSingleObject(ProcessHandle, wait_time);

    if (wait_result == WAIT_TIMEOUT) {
        result.TimedOut = true;
        TerminateProcess(ProcessHandle, 1);
        WaitForSingleObject(ProcessHandle, INFINITE);
    }

    DWORD exit_code = 0;
    if (GetExitCodeProcess(ProcessHandle, &exit_code)) {
        result.ExitCode = static_cast<int>(exit_code);
    } else {
        result.ExitCode = Constants::EXIT_FAIL_EC;
    }

    FILETIME creation_time{}, exit_time{};
    GetProcessTimes(ProcessHandle, &creation_time, &exit_time,
                    &result.Usage.KernelTime, &result.Usage.UserTime);

    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(ProcessHandle, &pmc, sizeof(pmc))) {
        result.Usage.PeakWorkingSetSize = pmc.PeakWorkingSetSize;
        result.Usage.PageFaultCount = pmc.PageFaultCount;
    }

    // Gather output after process has exited (child should close pipes)
    auto [stdout_result, stderr_result] = reader_future.get();
    result.Stdout = std::move(stdout_result);
    result.Stderr = std::move(stderr_result);

    CloseHandle(StdoutHandle);
    CloseHandle(StderrHandle);
    PipesClosed = true;

    const auto end_time = std::chrono::steady_clock::now();
    result.ExecutionTime = end_time - start_time;

    return result;
}

inline Errors::Result<void> Child::Kill(int) const {
    if (!TerminateProcess(ProcessHandle, 1)) {
        return Errors::MakeSystemError(Errors::ErrorCode::KillFailed, 
                                      "Failed to terminate process");
    }
    return {};
}

inline Errors::Result<Child> Command::Spawn() {
    // Validate command
    if (Executable.empty()) {
        return Errors::MakeError(Errors::ErrorCode::EmptyCommand, 
                                "Command executable cannot be empty",
                                "", "Provide a valid executable name or path");
    }

    std::vector<std::string> args_vec;
    args_vec.push_back(Executable);
    args_vec.insert(args_vec.end(), Arguments.begin(), Arguments.end());

    if (!ExecutionValidator::CanExecuteCommand(args_vec)) {
        return Errors::MakeError(Errors::ErrorCode::ExecutableNotFound,
                                "Executable not found: " + Executable,
                                "", "Verify the executable exists and is in PATH");
    }

    // Validate working directory if specified
    if (WorkDir && !fs::exists(*WorkDir)) {
        return Errors::MakeError(Errors::ErrorCode::InvalidWorkingDirectory,
                                "Working directory does not exist: " + *WorkDir,
                                "", "Create the directory or specify a valid path");
    }

    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};

    HANDLE stdout_read, stdout_write, stderr_read, stderr_write;
    if (!CreatePipe(&stdout_read, &stdout_write, &sa, 0)) {
        return Errors::MakeSystemError(Errors::ErrorCode::PipeCreationFailed,
                                      "Failed to create stdout pipe");
    }

    if (!CreatePipe(&stderr_read, &stderr_write, &sa, 0)) {
        CloseHandle(stdout_read);
        CloseHandle(stdout_write);
        return Errors::MakeSystemError(Errors::ErrorCode::PipeCreationFailed,
                                      "Failed to create stderr pipe");
    }

    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {sizeof(STARTUPINFOA)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = stdout_write;
    si.hStdError = stderr_write;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi = {};

    // Build command line using ranges and utility function
    std::string cmdline = Utils::QuoteArgumentWindows(Executable);
    const auto quoted_args = Arguments | std::views::transform(Utils::QuoteArgumentWindows);

    for (const auto& quoted_arg : quoted_args) {
        cmdline += ' ';
        cmdline += quoted_arg;
    }

    // Build environment block: merge current environment with overrides (if any)
    std::string env_block;
    if (!EnvVars.empty()) {
        // Gather current environment
        LPCH env_strings = GetEnvironmentStringsA();
        if (env_strings) {
            // Copy all existing vars unless overridden (case-insensitive on Windows)
            std::unordered_map<std::string, std::string> lower_over;
            lower_over.reserve(EnvVars.size());
            for (const auto& [k, v] : EnvVars) {
                std::string lk = k;
                std::transform(lk.begin(), lk.end(), lk.begin(), [](char c) { return std::tolower(c); });
                lower_over.emplace(std::move(lk), v);
            }
            for (LPCSTR p = env_strings; *p; ) {
                std::string entry = p;
                size_t eq = entry.find('=');
                if (eq != std::string::npos) {
                    std::string key = entry.substr(0, eq);
                    std::string lk = key;
                    std::transform(lk.begin(), lk.end(), lk.begin(), [](char c) { return std::tolower(c); });
                    if (lower_over.find(lk) == lower_over.end()) {
                        env_block += entry;
                        env_block.push_back('\0');
                    }
                }
                p += entry.size() + 1;
            }
            FreeEnvironmentStringsA(env_strings);
        }
        // Add/override with provided variables
        for (const auto& [key, value] : EnvVars) {
            env_block += key;
            env_block += '=';
            env_block += value;
            env_block.push_back('\0');
        }
        env_block.push_back('\0');
    }

    BOOL success = CreateProcessA(
        nullptr, const_cast<char*>(cmdline.c_str()),
        nullptr, nullptr, TRUE, 0,
        env_block.empty() ? nullptr : const_cast<char*>(env_block.c_str()),
        WorkDir ? WorkDir->c_str() : nullptr,
        &si, &pi
    );

    CloseHandle(stdout_write);
    CloseHandle(stderr_write);

    if (!success) {
        CloseHandle(stdout_read);
        CloseHandle(stderr_read);

        const DWORD error_code = GetLastError();
        std::string suggestion;
        switch (error_code) {
            case ERROR_FILE_NOT_FOUND: 
                suggestion = "Verify the executable path exists";
                break;
            case ERROR_ACCESS_DENIED:
                suggestion = "Check file permissions and security settings";
                break;
            case ERROR_NOT_ENOUGH_MEMORY:
                suggestion = "Free up system memory";
                break;
            default:
                suggestion = "Check Windows event logs for more details";
                break;
        }

        return Errors::MakeError(Errors::ErrorCode::SpawnFailed,
                                "Failed to create process: " + Executable,
                                "CreateProcessA failed with error " + std::to_string(error_code),
                                suggestion);
    }

    return Child(pi.hProcess, pi.hThread, stdout_read, stderr_read);
}

inline std::pair<std::string, std::string> AsyncPipeReader::ReadPipes(HANDLE stdout_handle, HANDLE stderr_handle) {
    auto read_all = [](HANDLE h) -> std::string {
        std::string acc;
        acc.reserve(Constants::PIPE_BUFFER_SIZE);
        Buffer buf{};
        DWORD n = 0;
        for (;;) {
            if (!ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr)) {
                const DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) break;
                // Transient: small backoff
                Sleep(1);
                continue;
            }
            if (n == 0) break;
            acc.append(buf.data(), n);
        }
        return acc;
    };
    auto f_out = std::async(std::launch::async, read_all, stdout_handle);
    auto f_err = std::async(std::launch::async, read_all, stderr_handle);
    return {f_out.get(), f_err.get()};
}

inline bool AsyncPipeReader::ReadFromPipe(PipeData& pipe_data, Buffer& buffer) noexcept {
    DWORD bytes_read;
    if (ReadFile(pipe_data.Handle, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, nullptr)) {
        if (bytes_read > 0) {
            pipe_data.Buffer.append(buffer.data(), bytes_read);
            return true;
        }
    }
    return false;
}


#else

// Unix implementations
inline Errors::Result<CommandResult> Child::Wait(std::optional<std::chrono::duration<double>> timeout) const {
    const auto start_time = std::chrono::steady_clock::now();

    CommandResult result;
    int status = 0;
    rusage usage{};

    // Start asynchronous pipe reader to avoid deadlocks while child runs
    auto reader_future = std::async(std::launch::async, AsyncPipeReader::ReadPipes, StdoutFd, StderrFd);

    if (timeout) {
        const auto timeout_time = start_time + *timeout;
        while (std::chrono::steady_clock::now() < timeout_time) {
            const int wait_result = waitpid(ProcessId, &status, WNOHANG);
            if (wait_result == ProcessId) {
                // Child finished; collect final status
                waitpid(ProcessId, &status, 0);
                break; // Process finished
            }

            if (wait_result == -1) {
                result.ExitCode = Constants::EXIT_FAIL_EC;
                result.Stderr = "waitpid failed";
                break;
            }

            std::this_thread::sleep_for(Constants::SLEEP_INTERVAL);
        }

        // Check if we timed out
        if (std::chrono::steady_clock::now() >= timeout_time) {
            if (const int wait_result = waitpid(ProcessId, &status, WNOHANG); wait_result == 0) { // Still running
                static_cast<void>(Kill());
                result.TimedOut = true;
                // Collect final status after terminating
                waitpid(ProcessId, &status, 0);
            } else if (wait_result == ProcessId) {
                // Already finished; ensure status is reaped
                waitpid(ProcessId, &status, 0);
            }
        }
    } else {
        // Blocking wait for child process
        waitpid(ProcessId, &status, 0);
    }

    // Collect outputs (reader finishes when pipes close)
    auto [stdout_result, stderr_result] = reader_future.get();
    result.Stdout = std::move(stdout_result);
    result.Stderr = std::move(stderr_result);

    close(StdoutFd);
    close(StderrFd);

    // Populate resource usage after child has terminated
    getrusage(RUSAGE_CHILDREN, &usage);
#ifdef __linux__
    constexpr long MICROSECONDS_PER_SECOND = 1000000;
    result.Usage.UserCpuTime = usage.ru_utime.tv_sec * MICROSECONDS_PER_SECOND + usage.ru_utime.tv_usec;
    result.Usage.SystemCpuTime = usage.ru_stime.tv_sec * MICROSECONDS_PER_SECOND + usage.ru_stime.tv_usec;
    result.Usage.MaxResidentSetSize = usage.ru_maxrss;
    result.Usage.MinorPageFaults = usage.ru_minflt;
    result.Usage.MajorPageFaults = usage.ru_majflt;
    result.Usage.VoluntaryContextSwitches = usage.ru_nvcsw;
    result.Usage.InvoluntaryContextSwitches = usage.ru_nivcsw;
#endif

    // Enhanced process termination analysis
    if (!result.TimedOut) {
        if (WIFEXITED(status)) {
            result.ExitCode = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            result.KilledBySignal = true;
            result.TerminatingSignal = WTERMSIG(status);
            result.ExitCode = 128 + result.TerminatingSignal;
#if defined(WCOREFLAG)
            result.CoreDumped = (status & WCOREFLAG) != 0;
#elif defined(WCOREDUMP)
            result.CoreDumped = WCOREDUMP(status);
#else
            result.CoreDumped = false;
#endif
        } else if (WIFSTOPPED(status)) {
            result.Stopped = true;
            result.StopSignal = WSTOPSIG(status);
        }
    }

    const auto end_time = std::chrono::steady_clock::now();
    result.ExecutionTime = end_time - start_time;

    return Errors::Result(std::move(result));
}

inline Errors::Result<void> Child::Kill(const int signal) const {
    if (kill(ProcessId, signal) == -1) {
        return Errors::Result<void>(
            Errors::MakeSystemError(Errors::ErrorCode::KillFailed,
            "Failed to send signal " + std::to_string(signal) +
            " to process " + std::to_string(ProcessId)));
    }
    return {};
}

inline Errors::Result<Child> Command::Spawn() {
    if (Executable.empty()) {
        return Errors::Result<Child>(Errors::MakeError(Errors::ErrorCode::EmptyCommand,
                                                       "Command executable cannot be empty", "",
                                                       "Provide a valid executable name or path"));
    }
    std::vector<std::string> args_vec;
    args_vec.push_back(Executable);
    args_vec.insert(args_vec.end(), Arguments.begin(), Arguments.end());

    if (!ExecutionValidator::CanExecuteCommand(args_vec)) {
        return Errors::Result<Child>(Errors::MakeError(Errors::ErrorCode::ExecutableNotFound,
                                                       "Executable not found: " + Executable, "",
                                                       "Verify the executable exists and is in PATH"));
    }

    int stdout_pipe[2], stderr_pipe[2];
    if (pipe(stdout_pipe) == -1 || pipe(stderr_pipe) == -1) {
        return Errors::Result<Child>(
                Errors::MakeSystemError(Errors::ErrorCode::PipeCreationFailed, "Failed to create stdout pipe"));
    }

#ifdef __APPLE__
    posix_spawn_file_actions_t file_actions;
    posix_spawnattr_t attr;

    if (posix_spawn_file_actions_init(&file_actions) != 0 ||
        posix_spawnattr_init(&attr) != 0) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        return Errors::MakeSystemError(Errors::ErrorCode::SpawnFailed,
                                      "Failed to initialize posix_spawn attributes/actions");
    }

    posix_spawn_file_actions_adddup2(&file_actions, stdout_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&file_actions, stderr_pipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&file_actions, stdout_pipe[0]);
    posix_spawn_file_actions_addclose(&file_actions, stdout_pipe[1]);
    posix_spawn_file_actions_addclose(&file_actions, stderr_pipe[0]);
    posix_spawn_file_actions_addclose(&file_actions, stderr_pipe[1]);

    if (WorkDir) {
        posix_spawn_file_actions_addchdir_np(&file_actions, WorkDir->c_str());
    }

    std::vector<char*> argv, envp;
    argv.reserve(args_vec.size() + 1);
    for (const auto& s : args_vec) {
        argv.push_back(const_cast<char*>(s.c_str()));
    }
    argv.push_back(nullptr);

    std::vector<std::string> env_strings;
    if (!EnvVars.empty()) {
        for (char** env = environ; *env; ++env) {
            std::string env_str(*env);
            std::string key = env_str.substr(0, env_str.find('='));
            if (EnvVars.find(key) == EnvVars.end()) {
                env_strings.push_back(env_str);
            }
        }
        for (const auto& [key, value] : EnvVars) {
            env_strings.push_back(key + "=" + value);
        }
        for (const auto& s : env_strings) {
            envp.push_back(const_cast<char*>(s.c_str()));
        }
        envp.push_back(nullptr);
    }

    pid_t pid;
    int result = posix_spawnp(&pid, argv[0], &file_actions, &attr,
                            argv.data(), envp.empty() ? environ : envp.data()); // spawnp for PATH search

    posix_spawn_file_actions_destroy(&file_actions);
    posix_spawnattr_destroy(&attr);

    if (result != 0) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        return Errors::MakeError(Errors::ErrorCode::SpawnFailed,
                                 "posix_spawnp failed for: " + Executable,
                                 std::string(strerror(result)),
                                 "Verify the executable, PATH, and permissions");
    }
#else
    const pid_t pid = fork();
    if (pid == -1) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        return Errors::Result<Child>(
                Errors::MakeSystemError(Errors::ErrorCode::ForkFailed, "fork() failed"));
    }

    if (pid == 0) {
        if (WorkDir && chdir(WorkDir->c_str()) != 0) {
            _exit(Constants::EXIT_FAIL_EC);
        }

        for(const auto &[key, value] : EnvVars) {
            setenv(key.c_str(), value.c_str(), 1);
        }

        if (dup2(stdout_pipe[1], STDOUT_FILENO) == -1 ||
            dup2(stderr_pipe[1], STDERR_FILENO) == -1) {
            _exit(Constants::EXIT_FAIL_EC);
        }
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);

        std::vector<char*> argv;
        argv.reserve(args_vec.size() + 1);
        for (const auto& s : args_vec) {
            argv.push_back(const_cast<char*>(s.c_str()));
        }
        argv.push_back(nullptr);

        execvp(argv[0], argv.data());
        _exit(Constants::EXIT_FAIL_EC);
    }
#endif

    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    return Errors::Result(Child(pid, stdout_pipe[0], stderr_pipe[0]));
}

// Implementation of AsyncPipeReader
inline std::pair<std::string, std::string> AsyncPipeReader::ReadPipes(const int stdout_fd, const int stderr_fd) {
    fcntl(stdout_fd, F_SETFL, O_NONBLOCK);
    fcntl(stderr_fd, F_SETFL, O_NONBLOCK);

    PipeData stdout_data{stdout_fd};
    PipeData stderr_data{stderr_fd};

    stdout_data.Buffer.reserve(Constants::PIPE_BUFFER_SIZE);
    stderr_data.Buffer.reserve(Constants::STDERR_BUFFER_SIZE);

    Buffer read_buffer{};

    while (!stdout_data.Finished || !stderr_data.Finished) {
        std::array<pollfd, 2> fds = {{
            {stdout_fd, POLLIN, 0},
            {stderr_fd, POLLIN, 0}
        }};

        if (const int poll_result = poll(fds.data(), 2, Constants::POLL_TIMEOUT_MS); poll_result > 0) {
            if (fds[0].revents & POLLIN) {
                if (!ReadFromPipe(stdout_data, read_buffer)) {
                    stdout_data.Finished = true;
                }
            }
            if (fds[1].revents & POLLIN) {
                if (!ReadFromPipe(stderr_data, read_buffer)) {
                    stderr_data.Finished = true;
                }
            }

            if (fds[0].revents & (POLLHUP | POLLERR)) stdout_data.Finished = true;
            if (fds[1].revents & (POLLHUP | POLLERR)) stderr_data.Finished = true;
        } else if (poll_result == 0) {
            if (!IsPipeOpen(stdout_fd)) stdout_data.Finished = true;
            if (!IsPipeOpen(stderr_fd)) stderr_data.Finished = true;
        }
    }

    return {std::move(stdout_data.Buffer), std::move(stderr_data.Buffer)};
}

inline bool AsyncPipeReader::ReadFromPipe(PipeData& pipe_data, Buffer& buffer) noexcept {
    const ssize_t bytes_read = read(pipe_data.Fd, buffer.data(), buffer.size());
    if (bytes_read > 0) {
        pipe_data.Buffer.append(buffer.data(), static_cast<size_t>(bytes_read));
        return true;
    }
    return bytes_read != 0;
}

inline bool AsyncPipeReader::IsPipeOpen(const int fd) noexcept {
    return fcntl(fd, F_GETFD) != -1;
}

#endif

inline Errors::Result<CommandResult> Command::Execute() {
    auto spawn_result = Spawn();
    if (spawn_result.IsError()) {
        // Convert spawn error to CommandResult with error info
        CommandResult result;
        result.ExitCode = Constants::EXIT_FAIL_EC;
        result.ExecutionError = spawn_result.Error();
        result.Stderr = spawn_result.Error().FullMessage();
        return Errors::Result(std::move(result));
    }

    auto wait_result = spawn_result.Value().Wait(TimeoutDuration);
    if (wait_result.IsError()) {
        return Errors::Result<CommandResult>(wait_result.Error()); // Propagate wait error
    }

    auto result = wait_result.Value();
    if (result.TimedOut) {
        result.ExecutionError = Errors::MakeError(
            Errors::ErrorCode::ExecutionTimeout,
            "Process execution timed out",
            "Process exceeded the specified timeout duration",
            "Consider increasing the timeout or optimizing the command"
        );
    }

    return Errors::Result(std::move(result));
}

class SignalInfo {
public:
    static const char* GetSignalName(const int signal) {
#ifndef _WIN32
        switch (signal) {
            case SIGTERM: return "SIGTERM";
            case SIGKILL: return "SIGKILL";
            case SIGINT: return "SIGINT";
            case SIGQUIT: return "SIGQUIT";
            case SIGABRT: return "SIGABRT";
            case SIGFPE: return "SIGFPE";
            case SIGILL: return "SIGILL";
            case SIGSEGV: return "SIGSEGV";
            case SIGBUS: return "SIGBUS";
            case SIGPIPE: return "SIGPIPE";
            case SIGALRM: return "SIGALRM";
            case SIGUSR1: return "SIGUSR1";
            case SIGUSR2: return "SIGUSR2";
            case SIGCHLD: return "SIGCHLD";
            case SIGCONT: return "SIGCONT";
            case SIGSTOP: return "SIGSTOP";
            case SIGTSTP: return "SIGTSTP";
            default: return "UNKNOWN";
        }
#else
        static_cast<void>(signal);
        return "N/A";
#endif
    }
    
    static std::string GetProcessInfo(const CommandResult& result) {
        std::ostringstream info;
        if (result.KilledBySignal) {
            info << "Killed by signal " << result.TerminatingSignal 
                 << " (" << GetSignalName(result.TerminatingSignal) << ")";
            if (result.CoreDumped) info << " [core dumped]";
        } else if (result.Stopped) {
            info << "Stopped by signal " << result.StopSignal
                 << " (" << GetSignalName(result.StopSignal) << ")";
        } else if (result.TimedOut) {
            info << "Process timed out";
        } else {
            info << "Exited normally with code " << result.ExitCode;
        }
        return info.str();
    }
};

#endif
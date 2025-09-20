// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 assembler-0
// Licensed under GPL-3.0-or-later

/**
 * @brief CatalystCX - A cross-platform single-header C++ library for executing and managing external processes (or commands).
 * @version 0.0.1
 * @author assembler-0
 */

#pragma once
#ifndef CATALYSTCX_HPP
#define CATALYSTCX_HPP

#include <array>
#include <chrono>
#include <filesystem>
#include <future>
#include <optional>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <io.h>
#include <fcntl.h>
using pid_t = DWORD;
#else
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef __APPLE__
#include <spawn.h>
extern char **environ;
#endif
#endif

namespace fs = std::filesystem;

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

    struct ResourceUsage {
#if defined(__linux__)
        long UserCpuTime;
        long SystemCpuTime;
        long MaxResidentSetSize;
        long MinorPageFaults;
        long MajorPageFaults;
        long VoluntaryContextSwitches;
        long InvoluntaryContextSwitches;
#elif defined(_WIN32)
        FILETIME UserTime;
        FILETIME KernelTime;
        SIZE_T PeakWorkingSetSize;
        SIZE_T PageFaultCount;
#endif
    } Usage{};
};

class Child {
public:
#ifdef _WIN32
    Child(HANDLE process, HANDLE thread, HANDLE stdout_handle, HANDLE stderr_handle)
        : ProcessHandle(process), ThreadHandle(thread), StdoutHandle(stdout_handle), StderrHandle(stderr_handle) {
        ProcessId = GetProcessId(process);
    }
    
    ~Child() {
        if (ProcessHandle != INVALID_HANDLE_VALUE) CloseHandle(ProcessHandle);
        if (ThreadHandle != INVALID_HANDLE_VALUE) CloseHandle(ThreadHandle);
    }
#else
    Child(const pid_t pid, const int stdout_fd, const int stderr_fd)
        : ProcessId(pid), StdoutFd(stdout_fd), StderrFd(stderr_fd) {}
#endif

    [[nodiscard]] CommandResult Wait(std::optional<std::chrono::duration<double>> timeout = std::nullopt) const;
    [[nodiscard]] pid_t GetPid() const { return ProcessId; }

#ifdef _WIN32
    void Kill(int signal = 0) const;
#else
    void Kill(int signal = SIGTERM) const;
#endif

private:
    pid_t ProcessId;
#ifdef _WIN32
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    HANDLE StdoutHandle;
    HANDLE StderrHandle;
#else
    int StdoutFd;
    int StderrFd;
#endif
};

class Command {
public:
    explicit Command(std::string executable) : Executable(std::move(executable)) {}

    Command& Arg(std::string argument) {
        Arguments.push_back(std::move(argument));
        return *this;
    }

    Command& Args(const std::vector<std::string>& arguments) {
        Arguments.insert(Arguments.end(), arguments.begin(), arguments.end());
        return *this;
    }

    Command& WorkingDirectory(std::string path) {
        WorkDir = std::move(path);
        return *this;
    }

    Command& Environment(const std::string& key, const std::string& value) {
        EnvVars[key] = value;
        return *this;
    }

    Command& Timeout(std::chrono::duration<double> duration) {
        TimeoutDuration = duration;
        return *this;
    }

    [[nodiscard]] CommandResult Status();
    [[nodiscard]] std::optional<Child> Spawn();

private:
    std::string Executable;
    std::vector<std::string> Arguments;
    std::optional<std::string> WorkDir;
    std::unordered_map<std::string, std::string> EnvVars;
    std::optional<std::chrono::duration<double>> TimeoutDuration;
};

class AsyncPipeReader {
public:
#ifdef _WIN32
    static std::pair<std::string, std::string> ReadPipes(HANDLE stdout_handle, HANDLE stderr_handle);
private:
    static bool ReadFromPipe(PipeData& pipe_data, std::array<char, 8192>& buffer);
#else
    static std::pair<std::string, std::string> ReadPipes(int stdout_fd, int stderr_fd);
private:

    struct PipeData {
#ifdef _WIN32
        HANDLE Handle;
#else
        int Fd;
#endif
        std::string Buffer;
        bool Finished = false;
    };

    static bool ReadFromPipe(PipeData& pipe_data, std::array<char, 8192>& buffer);
    static bool IsPipeOpen(int fd);
#endif
};

class ExecutionValidator {
public:
    static bool IsFileExecutable(const std::string& path);
    static bool IsCommandExecutable(const std::string& command);
    static bool CanExecuteCommand(const std::vector<std::string>& args);
};

// Windows implementations
#ifdef _WIN32
inline CommandResult Child::Wait(std::optional<std::chrono::duration<double>> timeout) const {
    auto start_time = std::chrono::steady_clock::now();
    CommandResult result;
    
    DWORD wait_time = timeout ? static_cast<DWORD>(timeout->count() * 1000) : INFINITE;
    DWORD wait_result = WaitForSingleObject(ProcessHandle, wait_time);
    
    auto end_time = std::chrono::steady_clock::now();
    result.ExecutionTime = end_time - start_time;
    
    if (wait_result == WAIT_TIMEOUT) {
        result.TimedOut = true;
        TerminateProcess(ProcessHandle, 1);
        WaitForSingleObject(ProcessHandle, INFINITE);
    }
    
    DWORD exit_code;
    GetExitCodeProcess(ProcessHandle, &exit_code);
    result.ExitCode = static_cast<int>(exit_code);
    
    FILETIME creation_time, exit_time;
    GetProcessTimes(ProcessHandle, &creation_time, &exit_time, 
                   &result.Usage.KernelTime, &result.Usage.UserTime);
    
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(ProcessHandle, &pmc, sizeof(pmc))) {
        result.Usage.PeakWorkingSetSize = pmc.PeakWorkingSetSize;
        result.Usage.PageFaultCount = pmc.PageFaultCount;
    }
    
    auto [stdout_result, stderr_result] = AsyncPipeReader::ReadPipes(StdoutHandle, StderrHandle);
    result.Stdout = std::move(stdout_result);
    result.Stderr = std::move(stderr_result);
    
    CloseHandle(StdoutHandle);
    CloseHandle(StderrHandle);
    
    return result;
}

inline void Child::Kill(int) const {
    TerminateProcess(ProcessHandle, 1);
}

inline std::optional<Child> Command::Spawn() {
    std::vector<std::string> args_vec;
    args_vec.push_back(Executable);
    args_vec.insert(args_vec.end(), Arguments.begin(), Arguments.end());

    if (!ExecutionValidator::CanExecuteCommand(args_vec)) {
        return std::nullopt;
    }

    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    
    HANDLE stdout_read, stdout_write, stderr_read, stderr_write;
    if (!CreatePipe(&stdout_read, &stdout_write, &sa, 0) ||
        !CreatePipe(&stderr_read, &stderr_write, &sa, 0)) {
        return std::nullopt;
    }
    
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);
    
    STARTUPINFOA si = {sizeof(STARTUPINFOA)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = stdout_write;
    si.hStdError = stderr_write;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    
    PROCESS_INFORMATION pi = {};
    
    auto QuoteArgWin = [](const std::string& s) -> std::string {
        bool need_quotes = s.find_first_of(" \t\"") != std::string::npos;
        if (!need_quotes) return s;
        std::string out;
        out.push_back('"');
        size_t bs = 0;
        for (char c : s) {
            if (c == '\\') { ++bs; continue; }
            if (c == '"') { out.append(bs * 2 + 1, '\\'); out.push_back('"'); bs = 0; continue; }
            if (bs) { out.append(bs, '\\'); bs = 0; }
            out.push_back(c);
        }
        if (bs) out.append(bs * 2, '\\');
        out.push_back('"');
        return out;
    };
    std::string cmdline = QuoteArgWin(Executable);
    for (const auto& arg : Arguments) {
        cmdline += ' ';
        cmdline += QuoteArgWin(arg);
    }
    
    std::string env_block;
    if (!EnvVars.empty()) {
        for (const auto& [key, value] : EnvVars) {
            env_block += key + "=" + value + "\0";
        }
        env_block += "\0";
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
        return std::nullopt;
    }
    
    return Child(pi.hProcess, pi.hThread, stdout_read, stderr_read);
}

inline std::pair<std::string, std::string> AsyncPipeReader::ReadPipes(HANDLE stdout_handle, HANDLE stderr_handle) {
    PipeData stdout_data{stdout_handle, {}};
    PipeData stderr_data{stderr_handle, {}};
    
    std::array<char, 8192> buffer;
    
    while (!stdout_data.Finished || !stderr_data.Finished) {
        if (!stdout_data.Finished && !ReadFromPipe(stdout_data, buffer)) {
            stdout_data.Finished = true;
        }
        if (!stderr_data.Finished && !ReadFromPipe(stderr_data, buffer)) {
            stderr_data.Finished = true;
        }
        if (!stdout_data.Finished || !stderr_data.Finished) {
            Sleep(10);
        }
    }
    
    return {std::move(stdout_data.Buffer), std::move(stderr_data.Buffer)};
}

inline bool AsyncPipeReader::ReadFromPipe(PipeData& pipe_data, std::array<char, 8192>& buffer) {
    DWORD bytes_read;
    if (ReadFile(pipe_data.Handle, buffer.data(), buffer.size(), &bytes_read, nullptr)) {
        if (bytes_read > 0) {
            pipe_data.Buffer.append(buffer.data(), bytes_read);
            return true;
        }
    }
    return false;
}

inline bool ExecutionValidator::IsFileExecutable(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

inline bool ExecutionValidator::IsCommandExecutable(const std::string& command) {
    if (command.find('\\') != std::string::npos || command.find('/') != std::string::npos) {
        return IsFileExecutable(command) || IsFileExecutable(command + ".exe");
    }
    
    const char* path_env = getenv("PATH");
    if (!path_env) return false;
    
    std::string path_str(path_env);
    size_t start = 0;
    size_t end = path_str.find(';');
    
    while (start < path_str.length()) {
        std::string dir = path_str.substr(start, end - start);
        std::string full_path = dir + "\\" + command;
        
        if (IsFileExecutable(full_path) || IsFileExecutable(full_path + ".exe")) {
            return true;
        }
        
        if (end == std::string::npos) break;
        start = end + 1;
        end = path_str.find(';', start);
    }
    
    return false;
}

#else
// Unix implementations
inline CommandResult Child::Wait(std::optional<std::chrono::duration<double>> timeout) const {
    auto start_time = std::chrono::steady_clock::now();

    CommandResult result;
    int status = 0;
    rusage usage{};

    if (timeout) {
        while (true) {
            const int wait_result = waitpid(ProcessId, &status, WNOHANG);
            if (wait_result == ProcessId) {
                break; // Process finished
            }

            if (wait_result == -1) {
                result.ExitCode = 127;
                result.Stderr = "waitpid failed";
                break;
            }

            if (auto current_time = std::chrono::steady_clock::now(); current_time - start_time > *timeout) {
                Kill();
                result.TimedOut = true;
                wait4(ProcessId, &status, 0, &usage); // Clean up the zombie process and get usage
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    } else {
        wait4(ProcessId, &status, 0, &usage);
    }

    auto end_time = std::chrono::steady_clock::now();
    result.ExecutionTime = end_time - start_time;

    auto [stdout_result, stderr_result] = AsyncPipeReader::ReadPipes(StdoutFd, StderrFd);
    result.Stdout = std::move(stdout_result);
    result.Stderr += stderr_result;

    close(StdoutFd);
    close(StderrFd);

#ifdef __linux__
    result.Usage.UserCpuTime = usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec;
    result.Usage.SystemCpuTime = usage.ru_stime.tv_sec * 1000000 + usage.ru_stime.tv_usec;
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
#ifdef WCOREDUMP
            result.CoreDumped = WCOREDUMP(status);
#endif
        } else if (WIFSTOPPED(status)) {
            result.Stopped = true;
            result.StopSignal = WSTOPSIG(status);
        }
    }

    return result;
}

inline void Child::Kill(const int signal) const {
    kill(ProcessId, signal);
}

inline std::optional<Child> Command::Spawn() {
    std::vector<std::string> args_vec;
    args_vec.push_back(Executable);
    args_vec.insert(args_vec.end(), Arguments.begin(), Arguments.end());

    if (!ExecutionValidator::CanExecuteCommand(args_vec)) {
        return std::nullopt;
    }

    int stdout_pipe[2], stderr_pipe[2];
    if (pipe(stdout_pipe) == -1 || pipe(stderr_pipe) == -1) {
        return std::nullopt;
    }

#ifdef __APPLE__
    posix_spawn_file_actions_t file_actions;
    posix_spawnattr_t attr;

    if (posix_spawn_file_actions_init(&file_actions) != 0 ||
        posix_spawnattr_init(&attr) != 0) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        return std::nullopt;
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
        return std::nullopt;
    }
#else
    const pid_t pid = fork();
    if (pid == -1) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        return std::nullopt;
    }

    if (pid == 0) {
        if (WorkDir && chdir(WorkDir->c_str()) != 0) {
            _exit(127);
        }

        for(const auto &[key, value] : EnvVars) {
            setenv(key.c_str(), value.c_str(), 1);
        }

        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);

        std::vector<char*> argv;
        argv.reserve(args_vec.size() + 1);
        for (const auto& s : args_vec) {
            argv.push_back(const_cast<char*>(s.c_str()));
        }
        argv.push_back(nullptr);

        execvp(argv[0], argv.data());
        _exit(127);
    }
#endif

    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    return Child(pid, stdout_pipe[0], stderr_pipe[0]);
}


// Implementation of AsyncPipeReader
inline std::pair<std::string, std::string> AsyncPipeReader::ReadPipes(const int stdout_fd, const int stderr_fd) {
    fcntl(stdout_fd, F_SETFL, O_NONBLOCK);
    fcntl(stderr_fd, F_SETFL, O_NONBLOCK);

    PipeData stdout_data{stdout_fd, {}};
    PipeData stderr_data{stderr_fd, {}};

    stdout_data.Buffer.reserve(8192);
    stderr_data.Buffer.reserve(4096);

    std::array<char, 8192> read_buffer{};

    while (!stdout_data.Finished || !stderr_data.Finished) {
        std::array<pollfd, 2> fds = {
            {{stdout_fd, POLLIN, 0},
             {stderr_fd, POLLIN, 0}}
        };

        if (const int poll_result = poll(fds.data(), 2, 100); poll_result > 0) {
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

inline bool AsyncPipeReader::ReadFromPipe(PipeData& pipe_data, std::array<char, 8192>& buffer) {
    const ssize_t bytes_read = read(pipe_data.Fd, buffer.data(), buffer.size());
    if (bytes_read > 0) {
        pipe_data.Buffer.append(buffer.data(), bytes_read);
        return true;
    }
    return bytes_read != 0;
}

inline bool AsyncPipeReader::IsPipeOpen(const int fd) {
    return fcntl(fd, F_GETFD) != -1;
}

inline bool ExecutionValidator::IsCommandExecutable(const std::string& command) {
    if (command.find('/') != std::string::npos) {
        return IsFileExecutable(command);
    }

    const char* path_env = getenv("PATH");
    if (!path_env) return false;

    std::string path_str(path_env);
    size_t start = 0;
    size_t end = path_str.find(':');

    while (start < path_str.length()) {
        std::string dir = path_str.substr(start, end - start);
        std::string full_path = dir + "/" + command;

        if (IsFileExecutable(full_path)) {
            return true;
        }

        if (end == std::string::npos) break;
        start = end + 1;
        end = path_str.find(':', start);
    }

    return false;
}

inline bool ExecutionValidator::IsFileExecutable(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && st.st_mode & S_IXUSR;
}

#endif

inline CommandResult Command::Status() {
    if (const auto child = Spawn()) {
        return child->Wait(TimeoutDuration);
    }
    CommandResult result;
    result.ExitCode = 127;
    result.Stderr = "Failed to spawn process";
    return result;
}

inline bool ExecutionValidator::CanExecuteCommand(const std::vector<std::string>& args) {
    return !args.empty() && IsCommandExecutable(args[0]);
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
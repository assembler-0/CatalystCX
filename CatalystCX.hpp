// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 assembler-0
// Licensed under GPL-3.0-or-later
#pragma once
#ifndef CATALYSTCX_HPP
#define CATALYSTCX_HPP

#include <array>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <filesystem>
#include <future>
#include <optional>
#include <poll.h>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#ifdef __APPLE__
#include <spawn.h>
extern char **environ;
#endif

namespace fs = std::filesystem;

// A struct to hold the result of a command execution
struct CommandResult {
    int ExitCode{};
    std::string Stdout;
    std::string Stderr;
    std::chrono::duration<double> ExecutionTime{};
    bool TimedOut = false;
    
    // Process termination info
    bool KilledBySignal = false;
    int TerminatingSignal = 0;
    bool CoreDumped = false;
    bool Stopped = false;
    int StopSignal = 0;

#ifdef __linux__
    struct ResourceUsage {
        long UserCpuTime; // in microseconds
        long SystemCpuTime; // in microseconds
        long MaxResidentSetSize; // in kilobytes
        long MinorPageFaults;
        long MajorPageFaults;
        long VoluntaryContextSwitches;
        long InvoluntaryContextSwitches;
    } Usage{};
#endif
};

class Child {
public:
    Child(const pid_t pid, const int stdout_fd, const int stderr_fd)
        : ProcessId(pid), StdoutFd(stdout_fd), StderrFd(stderr_fd) {}

    // Wait for the child process to exit and return the result
    [[nodiscard]] CommandResult Wait(std::optional<std::chrono::duration<double>> timeout = std::nullopt) const;

    // Get the process ID
    [[nodiscard]] pid_t GetPid() const { return ProcessId; }

    // Send a signal to the process
    void Kill(int signal = SIGTERM) const;

private:
    pid_t ProcessId;
    int StdoutFd;
    int StderrFd;
};

class Command {
public:
    explicit Command(std::string executable) : Executable(std::move(executable)) {}

    // Add a single argument
    Command& Arg(std::string argument) {
        Arguments.push_back(std::move(argument));
        return *this;
    }

    // Add multiple arguments
    Command& Args(const std::vector<std::string>& arguments) {
        Arguments.insert(Arguments.end(), arguments.begin(), arguments.end());
        return *this;
    }

    // Set the working directory
    Command& WorkingDirectory(std::string path) {
        WorkDir = std::move(path);
        return *this;
    }

    // Set an environment variable
    Command& Environment(const std::string& key, const std::string& value) {
        EnvVars[key] = value;
        return *this;
    }

    // Set a timeout for the command
    Command& Timeout(std::chrono::duration<double> duration) {
        TimeoutDuration = duration;
        return *this;
    }

    // Execute the command and wait for it to complete
    [[nodiscard]] CommandResult Status();

    // Spawn the command and return a Child object
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
    static std::pair<std::string, std::string> ReadPipes(int stdout_fd, int stderr_fd);

private:
    struct PipeData {
        int Fd;
        std::string Buffer;
        bool Finished = false;
    };

    static bool ReadFromPipe(PipeData& pipe_data, std::array<char, 8192>& buffer);
    static bool IsPipeOpen(int fd);
};

class ExecutionValidator {
public:
    static bool IsFileExecutable(const std::string& path);
    static bool IsCommandExecutable(const std::string& command);
    static bool CanExecuteCommand(const std::vector<std::string>& args);
};

// Implementation of Child methods
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

// Implementation of Command methods
inline CommandResult Command::Status() {
    if (const auto child = Spawn()) {
        return child->Wait(TimeoutDuration);
    }
    CommandResult result;
    result.ExitCode = 127;
    result.Stderr = "Failed to spawn process";
    return result;
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
    int result = posix_spawn(&pid, argv[0], &file_actions, &attr, 
                            argv.data(), envp.empty() ? environ : envp.data());
    
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

inline bool ExecutionValidator::IsFileExecutable(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && st.st_mode & S_IXUSR;
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

inline bool ExecutionValidator::CanExecuteCommand(const std::vector<std::string>& args) {
    return !args.empty() && IsCommandExecutable(args[0]);
}

// Signal name lookup utility
class SignalInfo {
public:
    static const char* GetSignalName(const int signal) {
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
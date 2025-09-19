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

namespace fs = std::filesystem;

// A struct to hold the result of a command execution
struct CommandResult {
    int ExitCode{};
    std::string Stdout;
    std::string Stderr;
    std::chrono::duration<double> ExecutionTime{};
    bool TimedOut = false;

#ifdef __linux__
    struct ResourceUsage {
        long UserCpuTime; // in microseconds
        long SystemCpuTime; // in microseconds
        long MaxResidentSetSize; // in kilobytes
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
#endif

    if (!result.TimedOut) {
        result.ExitCode = WEXITSTATUS(status);
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

    const pid_t pid = fork();
    if (pid == -1) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        return std::nullopt;
    }

    if (pid == 0) { // Child process
        if (WorkDir) {
            if (chdir(WorkDir->c_str()) != 0) {
                _exit(127);
            }
        }

        for(const auto &[fst, snd] : EnvVars) {
            setenv(fst.c_str(), snd.c_str(), 1);
        }

        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);

        std::vector<char*> argv;
        argv.reserve(args_vec.size() + 1);
        for (const auto& s : args_vec) {
            argv.push_back(const_cast<char*>(s.c_str()));
        }
        argv.push_back(nullptr);

        execvp(argv[0], argv.data());
        _exit(127); // exec failed
    }

    // Parent process
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
    return bytes_read == 0; // EOF
}

inline bool AsyncPipeReader::IsPipeOpen(const int fd) {
    return fcntl(fd, F_GETFD) != -1;
}


// Implementation of ExecutionValidator
inline bool ExecutionValidator::IsFileExecutable(const std::string& path) {
    char resolved_path[PATH_MAX];
    if (realpath(path.c_str(), resolved_path) == nullptr) {
        return false;
    }

    struct stat sb{};
    if (stat(resolved_path, &sb) != 0) {
        return false;
    }

    if (!S_ISREG(sb.st_mode)) {
        return false;
    }

    return access(resolved_path, X_OK) == 0;
}

inline bool ExecutionValidator::IsCommandExecutable(const std::string& command) {
    if (command.empty() || command.find('\0') != std::string::npos) {
        return false;
    }

    if (command.find("../") != std::string::npos) {
        return false;
    }

    if (command.find('/') != std::string::npos) {
        return IsFileExecutable(command);
    }

    const char* path_env = std::getenv("PATH");
    if (!path_env) {
        return false;
    }

    const std::string path_str(path_env);
    std::stringstream ss(path_str);
    std::string dir;

    while (std::getline(ss, dir, ':')) {
        if (dir.empty() || dir.find("..") != std::string::npos) {
            continue;
        }

        std::string full_path = dir + "/" + command;

        if (full_path.length() >= PATH_MAX) {
            continue;
        }

        if (IsFileExecutable(full_path)) {
            return true;
        }
    }

    return false;
}

inline bool ExecutionValidator::CanExecuteCommand(const std::vector<std::string>& args) {
    if (args.empty()) return false;
    return IsCommandExecutable(args[0]);
}


#endif // CATALYSTCX_HPP
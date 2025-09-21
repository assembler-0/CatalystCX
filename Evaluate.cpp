// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 assembler-0
// Licensed under GPL-3.0-or-later
#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "CatalystCX.hpp"

class TestRunner {
    int passed = 0;
    int failed = 0;
    
public:
    void Assert(const bool condition, const std::string& test_name) {
        if (condition) {
            std::cout << "[PASS] " << test_name << std::endl;
            passed++;
        } else {
            std::cout << "[FAIL] " << test_name << std::endl;
            failed++;
        }
    }
    
    void PrintSummary() const {
        std::cout << "\n=== Test Summary ===" << std::endl;
        std::cout << "Passed: " << passed << std::endl;
        std::cout << "Failed: " << failed << std::endl;
        std::cout << "Total: " << (passed + failed) << std::endl;
    }
    
    [[nodiscard]] int GetFailedCount() const { return failed; }
};

void TestBasicExecution(TestRunner& runner) {
    std::cout << "\n=== Basic Execution Tests ===" << std::endl;
    
    // Test simple command
    auto execute_result = Command("echo").Arg("hello").Execute();
    runner.Assert(execute_result.IsOk(), "Echo command executed successfully");

    if (execute_result.IsOk()) {
        const auto& result = execute_result.Value();
        runner.Assert(result.ExitCode == 0, "Echo command success");
        runner.Assert(result.Stdout.find("hello") != std::string::npos, "Echo output correct");
    }

    // Test command with multiple args
    execute_result = Command("echo").Args(Utils::Expand({"hello", "world"})).Execute();
    runner.Assert(execute_result.IsOk(), "Multiple args command executed");

    if (execute_result.IsOk()) {
        const auto& result = execute_result.Value();
        runner.Assert(result.ExitCode == 0, "Multiple args success");
        runner.Assert(result.Stdout.find("hello world") != std::string::npos, "Multiple args output");
    }

    // Test command failure
    execute_result = Command("false").Execute();
    runner.Assert(execute_result.IsOk(), "False command spawned (even though it fails)");

    if (execute_result.IsOk()) {
        const auto& result = execute_result.Value();
        runner.Assert(result.ExitCode == 1, "False command exit code");
    }
}

void TestAsyncExecution(TestRunner& runner) {
    std::cout << "\n=== Async Execution Tests ===" << std::endl;
    
    // Test spawn and wait
    const auto spawn_result = Command("sleep").Arg("1").Spawn();
    runner.Assert(spawn_result.IsOk(), "Sleep spawn success");

    if (spawn_result.IsOk()) {
        const auto& child = spawn_result.Value();
        const pid_t pid = child.GetPid();
        runner.Assert(pid > 0, "Valid PID returned");

        const auto result = child.Wait();
        runner.Assert(result.Value().ExitCode == 0, "Sleep completed successfully");
        runner.Assert(result.Value().ExecutionTime.count() >= 1.0, "Sleep duration correct");
    }
}

void TestTimeout(TestRunner& runner) {
    std::cout << "\n=== Timeout Tests ===" << std::endl;
    
    // Test timeout functionality
    const auto start = std::chrono::steady_clock::now();
    const auto execute_result = Command("sleep").Arg("5").Timeout(std::chrono::seconds(1)).Execute();
    const auto duration = std::chrono::steady_clock::now() - start;

    runner.Assert(execute_result.IsOk(), "Timeout command executed");

    if (execute_result.IsOk()) {
        const auto& result = execute_result.Value();
        runner.Assert(result.TimedOut, "Command timed out");
        runner.Assert(duration < std::chrono::seconds(2), "Timeout enforced quickly");
    }
}

void TestSignalHandling(TestRunner& runner) {
    std::cout << "\n=== Signal Handling Tests ===" << std::endl;
    
    // Test SIGTERM handling
    if (const auto spawn_result = Command("sleep").Arg("10").Spawn(); spawn_result.IsOk()) {
        const auto& child = spawn_result.Value();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        static_cast<void>(child.Kill(SIGTERM));
        const auto result = child.Wait();

        runner.Assert(result.Value().KilledBySignal, "Process killed by signal");
        runner.Assert(result.Value().TerminatingSignal == SIGTERM, "Correct terminating signal");
        runner.Assert(result.Value().ExitCode == 128 + SIGTERM, "Correct exit code for signal");
    } else {
        runner.Assert(false, "Failed to spawn sleep for signal test");
    }
    
    // Test signal name lookup
    runner.Assert(std::string(SignalInfo::GetSignalName(SIGTERM)) == "SIGTERM", "Signal name lookup");
    runner.Assert(std::string(SignalInfo::GetSignalName(SIGKILL)) == "SIGKILL", "SIGKILL name");
}

void TestEnvironmentVariables(TestRunner& runner) {
    std::cout << "\n=== Environment Variable Tests ===" << std::endl;

    const auto execute_result = Command("printenv").Arg("TEST_VAR")
                    .Environment("TEST_VAR", "test_value")
                    .Execute();

    runner.Assert(execute_result.IsOk(), "Environment variable command executed");

    if (execute_result.IsOk()) {
        const auto& result = execute_result.Value();
        runner.Assert(result.ExitCode == 0, "Environment variable set");
        runner.Assert(result.Stdout.find("test_value") != std::string::npos, "Environment variable value");
    }
}

void TestWorkingDirectory(TestRunner& runner) {
    std::cout << "\n=== Working Directory Tests ===" << std::endl;

    const auto execute_result = Command("pwd").WorkingDirectory("/tmp").Execute();
    runner.Assert(execute_result.IsOk(), "Working directory command executed");

    if (execute_result.IsOk()) {
        const auto& result = execute_result.Value();
        runner.Assert(result.ExitCode == 0, "Working directory command success");
        runner.Assert(result.Stdout.find("/tmp") != std::string::npos, "Working directory set correctly");
    }
}

void TestErrorHandling(TestRunner& runner) {
    std::cout << "\n=== Error Handling Tests ===" << std::endl;

    // Test non-existent command
    const auto spawn_result = Command("nonexistentcommand12345").Spawn();
    runner.Assert(spawn_result.IsError(), "Non-existent command fails to spawn");

    if (spawn_result.IsError()) {
        std::cout << "Expected error: " << spawn_result.Error().FullMessage() << std::endl;
    }

    // Test command that writes to stderr
    const auto execute_result = Command("sh").Args(Utils::Expand({"-c", "echo error >&2; exit 42"})).Execute();
    runner.Assert(execute_result.IsOk(), "Stderr command executed");

    if (execute_result.IsOk()) {
        const auto& result = execute_result.Value();
        runner.Assert(result.ExitCode == 42, "Custom exit code preserved");
        runner.Assert(result.Stderr.find("error") != std::string::npos, "Stderr captured");
    }
}

void TestResourceUsage(TestRunner& runner) {
    std::cout << "\n=== Resource Usage Tests ===" << std::endl;
    
#ifdef __linux__
    if (const auto result = Command("dd").Args(Utils::Expand({"if=/dev/zero", "of=/dev/null", "bs=1M", "count=10"})).Execute(); result.IsOk()) {
        const auto& r = result.Value();
        runner.Assert(r.ExitCode == 0, "DD command success");
        runner.Assert(r.Usage.UserCpuTime >= 0, "User CPU time recorded");
        runner.Assert(r.Usage.SystemCpuTime >= 0, "System CPU time recorded");
        runner.Assert(r.Usage.MaxResidentSetSize > 0, "Memory usage recorded");
    }
#else
    std::cout << "[SKIP] Resource usage tests (Linux only)" << std::endl;
#endif
}

void TestPipeHandling(TestRunner& runner) {
    std::cout << "\n=== Pipe Handling Tests ===" << std::endl;
    auto result = Command("seq").Args(Utils::Expand({"1", "1000"})).Execute();
    // Test large output
    if (result.IsOk()) {
        const auto& r = result.Value();
        runner.Assert(r.ExitCode == 0, "Seq command success");
        runner.Assert(r.Stdout.find("1000") != std::string::npos, "Large output captured");
    }

    // Test mixed stdout/stderr
    result = Command("sh").Args(Utils::Expand({"-c", "echo stdout; echo stderr >&2"})).Execute();
    if (result.IsOk()) {
        const auto& r = result.Value();
        runner.Assert(r.Stdout.find("stdout") != std::string::npos, "Stdout captured");
        runner.Assert(r.Stderr.find("stderr") != std::string::npos, "Stderr captured");
    }

}

void TestExecutionValidator(TestRunner& runner) {
    std::cout << "\n=== Execution Validator Tests ===" << std::endl;
    
    runner.Assert(ExecutionValidator::IsCommandExecutable("ls"), "ls is executable");
    runner.Assert(ExecutionValidator::IsCommandExecutable("echo"), "echo is executable");
    runner.Assert(!ExecutionValidator::IsCommandExecutable("nonexistentcmd123"), "Non-existent not executable");

    const std::vector<std::string> valid_args = {"ls", "-l"};
    const std::vector<std::string> invalid_args = {"nonexistentcmd123"};
    
    runner.Assert(ExecutionValidator::CanExecuteCommand(valid_args), "Valid command can execute");
    runner.Assert(!ExecutionValidator::CanExecuteCommand(invalid_args), "Invalid command cannot execute");
}

void TestProcessInfo(TestRunner& runner) {
    std::cout << "\n=== Process Info Tests ===" << std::endl;
    
    // Test normal exit
    auto result = Command("true").Execute();
    std::string info = SignalInfo::GetProcessInfo(result.Value());
    runner.Assert(info.find("Exited normally") != std::string::npos, "Normal exit info");
    
    // Test timeout info
    result = Command("sleep").Arg("5").Timeout(std::chrono::milliseconds(100)).Execute();
    info = SignalInfo::GetProcessInfo(result.Value());
    runner.Assert(info.find("timed out") != std::string::npos, "Timeout info");
}

void TestEdgeCases(TestRunner& runner) {
    std::cout << "\n=== Edge Case Tests ===" << std::endl;
    
    // Empty command
    constexpr std::vector<std::string> empty_args;
    runner.Assert(!ExecutionValidator::CanExecuteCommand(empty_args), "Empty args rejected");
    
    // Command with spaces in args
    auto result = Command("echo").Arg("hello world").Execute();
    runner.Assert(result.Value().Stdout.find("hello world") != std::string::npos, "Spaces in args handled");
    
    // Very short timeout
    result = Command("sleep").Arg("1").Timeout(std::chrono::milliseconds(1)).Execute();
    runner.Assert(result.Value().TimedOut, "Very short timeout works");
}

#ifndef _WIN32
void TestLargeStdoutStderr(TestRunner& runner);
void TestExecutionValidatorFilePermissions(TestRunner& runner);
void TestEnvMergingAndOverride(TestRunner& runner);
#endif
int main() {
    TestRunner runner;
    
    std::cout << "CatalystCX Test Suite" << std::endl;
    std::cout << "=====================" << std::endl;
    
    TestBasicExecution(runner);
    TestAsyncExecution(runner);
    TestTimeout(runner);
    TestSignalHandling(runner);
    TestEnvironmentVariables(runner);
    TestWorkingDirectory(runner);
    TestErrorHandling(runner);
    TestResourceUsage(runner);
    TestPipeHandling(runner);
    TestExecutionValidator(runner);
    TestProcessInfo(runner);
    TestEdgeCases(runner);
#ifndef _WIN32
    TestLargeStdoutStderr(runner);
    TestExecutionValidatorFilePermissions(runner);
    TestEnvMergingAndOverride(runner);
#endif
    
    runner.PrintSummary();
    
    return runner.GetFailedCount();
}

// ===== Additional Linux-focused tests and helpers =====
#ifndef _WIN32
static std::string JoinPath(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (a.back() == '/') return a + b;
    return a + "/" + b;
}

static std::string MakeTempDir() {
    std::string tmpl = "/tmp/catalystcxXXXXXX";
    std::vector buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    char* p = mkdtemp(buf.data());
    if (!p) return {};
    return {p};
}

static bool WriteTextFile(const std::string& path, const std::string& content) {
    std::ofstream ofs(path, std::ios::out | std::ios::trunc);
    if (!ofs) return false;
    ofs << content;
    return ofs.good();
}

static void CleanupTemp(const std::string& dir, const std::vector<std::string>& files) {
    for (const auto& f : files) {
        unlink(JoinPath(dir, f).c_str());
    }
    rmdir(dir.c_str());
}

void TestLargeStdoutStderr(TestRunner& runner) {
    std::cout << "\n=== Large Stdout/Stderr Tests ===" << std::endl;

    // Large stdout (~5MB)
    auto execute_result = Command("sh").Args(Utils::Expand({"-c", "dd if=/dev/zero bs=1M count=5 2>/dev/null"})).Execute();
    runner.Assert(execute_result.IsOk(), "Large stdout command executed");

    if (execute_result.IsOk()) {
        const auto& res = execute_result.Value();
        runner.Assert(res.ExitCode == 0, "Large stdout command success");
        runner.Assert(res.Stdout.size() >= 5 * 1024 * 1024, "Large stdout captured without deadlock");
    }

    // Large stderr (~5MB zeros)
    execute_result = Command("sh").Args(Utils::Expand({"-c", "dd if=/dev/zero of=/dev/stderr bs=1M count=5 1>/dev/null"})).Execute();
    runner.Assert(execute_result.IsOk(), "Large stderr command executed");

    if (execute_result.IsOk()) {
        const auto& res = execute_result.Value();
        runner.Assert(res.ExitCode == 0, "Large stderr command success");
        runner.Assert(res.Stderr.size() >= 5 * 1024 * 1024, "Large stderr captured without deadlock");
    }

    // Interleaved stdout and stderr
    execute_result = Command("sh").Args(Utils::Expand({"-c", "for i in $(seq 1 2000); do echo outline; echo errline >&2; done"})).Execute();
    runner.Assert(execute_result.IsOk(), "Interleaved command executed");

    if (execute_result.IsOk()) {
        const auto& res = execute_result.Value();
        runner.Assert(res.ExitCode == 0, "Interleaved out/err success");
        runner.Assert(res.Stdout.find("outline") != std::string::npos, "Interleaved stdout captured");
        runner.Assert(res.Stderr.find("errline") != std::string::npos, "Interleaved stderr captured");
    }
}

void TestExecutionValidatorFilePermissions(TestRunner& runner) {
    std::cout << "\n=== Execution Validator File Permission Tests ===" << std::endl;
    const std::string dir = MakeTempDir();
    if (dir.empty()) {
        std::cout << "[SKIP] Unable to create temp dir" << std::endl;
        return;
    }
    std::string fname = "permtest.sh";
    const std::string path = JoinPath(dir, fname);

    WriteTextFile(path, "#!/bin/sh\necho ok\n");
    chmod(path.c_str(), 0644); // no exec

    runner.Assert(!ExecutionValidator::IsFileExecutable(path), "Non-executable file rejected");
    runner.Assert(!ExecutionValidator::IsCommandExecutable("./" + fname), "IsCommandExecutable false for non-exec");

    chmod(path.c_str(), 0755);

    runner.Assert(ExecutionValidator::IsFileExecutable(path), "Executable bit recognized");
    runner.Assert(ExecutionValidator::IsCommandExecutable(path) == true, "IsCommandExecutable true for exec");

    CleanupTemp(dir, {fname});
}

void TestEnvMergingAndOverride(TestRunner& runner) {
    std::cout << "\n=== Environment Merge/Override Tests ===" << std::endl;

    // New variable should be visible
    auto execute_result = Command("sh").Args(Utils::Expand({"-c", "printf '%s' \"$NEW_VAR\""}))
                    .Environment("NEW_VAR", "new_value").Execute();
    runner.Assert(execute_result.IsOk(), "New env var command executed");

    if (execute_result.IsOk()) {
        const auto& res = execute_result.Value();
        runner.Assert(res.ExitCode == 0, "New env var set");
        runner.Assert(res.Stdout == "new_value", "New env var value visible");
    }

    // Override an env var for the child only
    // Use HOME which should exist; don't leak to parent
    execute_result = Command("sh").Args(Utils::Expand({"-c", "printf '%s' \"$HOME\""}))
            .Environment("HOME", "/tmp/testhome").Execute();
    runner.Assert(execute_result.IsOk(), "Override env var command executed");

    if (execute_result.IsOk()) {
        const auto& res = execute_result.Value();
        runner.Assert(res.ExitCode == 0, "Override env var success");
        runner.Assert(res.Stdout == "/tmp/testhome", "Override value applied in child");
    }
}
#endif // _WIN32

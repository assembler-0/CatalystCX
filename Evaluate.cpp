// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 assembler-0
// Licensed under GPL-3.0-or-later
#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>
#include "CatalystCX.hpp"

class TestRunner {
    int passed = 0;
    int failed = 0;
    
public:
    void Assert(bool condition, const std::string& test_name) {
        if (condition) {
            std::cout << "[PASS] " << test_name << std::endl;
            passed++;
        } else {
            std::cout << "[FAIL] " << test_name << std::endl;
            failed++;
        }
    }
    
    void PrintSummary() {
        std::cout << "\n=== Test Summary ===" << std::endl;
        std::cout << "Passed: " << passed << std::endl;
        std::cout << "Failed: " << failed << std::endl;
        std::cout << "Total: " << (passed + failed) << std::endl;
    }
    
    int GetFailedCount() const { return failed; }
};

void TestBasicExecution(TestRunner& runner) {
    std::cout << "\n=== Basic Execution Tests ===" << std::endl;
    
    // Test simple command
    auto result = Command("echo").Arg("hello").Status();
    runner.Assert(result.ExitCode == 0, "Echo command success");
    runner.Assert(result.Stdout.find("hello") != std::string::npos, "Echo output correct");
    
    // Test command with multiple args
    result = Command("echo").Args({"hello", "world"}).Status();
    runner.Assert(result.ExitCode == 0, "Multiple args success");
    runner.Assert(result.Stdout.find("hello world") != std::string::npos, "Multiple args output");
    
    // Test command failure
    result = Command("false").Status();
    runner.Assert(result.ExitCode == 1, "False command exit code");
}

void TestAsyncExecution(TestRunner& runner) {
    std::cout << "\n=== Async Execution Tests ===" << std::endl;
    
    // Test spawn and wait
    auto child = Command("sleep").Arg("1").Spawn();
    runner.Assert(child.has_value(), "Sleep spawn success");
    
    if (child) {
        pid_t pid = child->GetPid();
        runner.Assert(pid > 0, "Valid PID returned");
        
        auto result = child->Wait();
        runner.Assert(result.ExitCode == 0, "Sleep completed successfully");
        runner.Assert(result.ExecutionTime.count() >= 1.0, "Sleep duration correct");
    }
}

void TestTimeout(TestRunner& runner) {
    std::cout << "\n=== Timeout Tests ===" << std::endl;
    
    // Test timeout functionality
    auto start = std::chrono::steady_clock::now();
    auto result = Command("sleep").Arg("5").Timeout(std::chrono::seconds(1)).Status();
    auto duration = std::chrono::steady_clock::now() - start;
    
    runner.Assert(result.TimedOut, "Command timed out");
    runner.Assert(duration < std::chrono::seconds(2), "Timeout enforced quickly");
}

void TestSignalHandling(TestRunner& runner) {
    std::cout << "\n=== Signal Handling Tests ===" << std::endl;
    
    // Test SIGTERM handling
    auto child = Command("sleep").Arg("10").Spawn();
    if (child) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        child->Kill(SIGTERM);
        auto result = child->Wait();
        
        runner.Assert(result.KilledBySignal, "Process killed by signal");
        runner.Assert(result.TerminatingSignal == SIGTERM, "Correct terminating signal");
        runner.Assert(result.ExitCode == 128 + SIGTERM, "Correct exit code for signal");
    }
    
    // Test signal name lookup
    runner.Assert(std::string(SignalInfo::GetSignalName(SIGTERM)) == "SIGTERM", "Signal name lookup");
    runner.Assert(std::string(SignalInfo::GetSignalName(SIGKILL)) == "SIGKILL", "SIGKILL name");
}

void TestEnvironmentVariables(TestRunner& runner) {
    std::cout << "\n=== Environment Variable Tests ===" << std::endl;
    
    auto result = Command("printenv").Arg("TEST_VAR")
                    .Environment("TEST_VAR", "test_value")
                    .Status();
    
    runner.Assert(result.ExitCode == 0, "Environment variable set");
    runner.Assert(result.Stdout.find("test_value") != std::string::npos, "Environment variable value");
}

void TestWorkingDirectory(TestRunner& runner) {
    std::cout << "\n=== Working Directory Tests ===" << std::endl;
    
    auto result = Command("pwd").WorkingDirectory("/tmp").Status();
    runner.Assert(result.ExitCode == 0, "Working directory command success");
    runner.Assert(result.Stdout.find("/tmp") != std::string::npos, "Working directory set correctly");
}

void TestErrorHandling(TestRunner& runner) {
    std::cout << "\n=== Error Handling Tests ===" << std::endl;
    
    // Test non-existent command
    auto child = Command("nonexistentcommand12345").Spawn();
    runner.Assert(!child.has_value(), "Non-existent command fails to spawn");
    
    // Test command that writes to stderr
    auto result = Command("sh").Args({"-c", "echo error >&2; exit 42"}).Status();
    runner.Assert(result.ExitCode == 42, "Custom exit code preserved");
    runner.Assert(result.Stderr.find("error") != std::string::npos, "Stderr captured");
}

void TestResourceUsage(TestRunner& runner) {
    std::cout << "\n=== Resource Usage Tests ===" << std::endl;
    
#ifdef __linux__
    auto result = Command("dd").Args({"if=/dev/zero", "of=/dev/null", "bs=1M", "count=10"}).Status();
    runner.Assert(result.ExitCode == 0, "DD command success");
    runner.Assert(result.Usage.UserCpuTime >= 0, "User CPU time recorded");
    runner.Assert(result.Usage.SystemCpuTime >= 0, "System CPU time recorded");
    runner.Assert(result.Usage.MaxResidentSetSize > 0, "Memory usage recorded");
#else
    std::cout << "[SKIP] Resource usage tests (Linux only)" << std::endl;
#endif
}

void TestPipeHandling(TestRunner& runner) {
    std::cout << "\n=== Pipe Handling Tests ===" << std::endl;
    
    // Test large output
    auto result = Command("seq").Args({"1", "1000"}).Status();
    runner.Assert(result.ExitCode == 0, "Large output command success");
    runner.Assert(result.Stdout.find("1000") != std::string::npos, "Large output captured");
    
    // Test mixed stdout/stderr
    result = Command("sh").Args({"-c", "echo stdout; echo stderr >&2"}).Status();
    runner.Assert(result.Stdout.find("stdout") != std::string::npos, "Stdout separated");
    runner.Assert(result.Stderr.find("stderr") != std::string::npos, "Stderr separated");
}

void TestExecutionValidator(TestRunner& runner) {
    std::cout << "\n=== Execution Validator Tests ===" << std::endl;
    
    runner.Assert(ExecutionValidator::IsCommandExecutable("ls"), "ls is executable");
    runner.Assert(ExecutionValidator::IsCommandExecutable("echo"), "echo is executable");
    runner.Assert(!ExecutionValidator::IsCommandExecutable("nonexistentcmd123"), "Non-existent not executable");
    
    std::vector<std::string> valid_args = {"ls", "-l"};
    std::vector<std::string> invalid_args = {"nonexistentcmd123"};
    
    runner.Assert(ExecutionValidator::CanExecuteCommand(valid_args), "Valid command can execute");
    runner.Assert(!ExecutionValidator::CanExecuteCommand(invalid_args), "Invalid command cannot execute");
}

void TestProcessInfo(TestRunner& runner) {
    std::cout << "\n=== Process Info Tests ===" << std::endl;
    
    // Test normal exit
    auto result = Command("true").Status();
    std::string info = SignalInfo::GetProcessInfo(result);
    runner.Assert(info.find("Exited normally") != std::string::npos, "Normal exit info");
    
    // Test timeout info
    result = Command("sleep").Arg("5").Timeout(std::chrono::milliseconds(100)).Status();
    info = SignalInfo::GetProcessInfo(result);
    runner.Assert(info.find("timed out") != std::string::npos, "Timeout info");
}

void TestEdgeCases(TestRunner& runner) {
    std::cout << "\n=== Edge Case Tests ===" << std::endl;
    
    // Empty command
    std::vector<std::string> empty_args;
    runner.Assert(!ExecutionValidator::CanExecuteCommand(empty_args), "Empty args rejected");
    
    // Command with spaces in args
    auto result = Command("echo").Arg("hello world").Status();
    runner.Assert(result.Stdout.find("hello world") != std::string::npos, "Spaces in args handled");
    
    // Very short timeout
    result = Command("sleep").Arg("1").Timeout(std::chrono::milliseconds(1)).Status();
    runner.Assert(result.TimedOut, "Very short timeout works");
}

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
    
    runner.PrintSummary();
    
    return runner.GetFailedCount();
}
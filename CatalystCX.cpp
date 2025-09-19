// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 assembler-0
// Licensed under GPL-3.0-or-later
#include "CatalystCX.hpp"
#include <iostream>

void PrintResult(const CommandResult& result) {
    std::cout << "Exit Code: " << result.ExitCode << std::endl;
    std::cout << "Timed Out: " << (result.TimedOut ? "Yes" : "No") << std::endl;
    std::cout << "Execution Time: " << result.ExecutionTime.count() << "s" << std::endl;

#ifdef __linux__
    std::cout << "User CPU Time: " << result.Usage.UserCpuTime << "us" << std::endl;
    std::cout << "System CPU Time: " << result.Usage.SystemCpuTime << "us" << std::endl;
    std::cout << "Max Resident Set Size: " << result.Usage.MaxResidentSetSize << "KB" << std::endl;
#endif

    std::cout << "\nStdout:\n" << result.Stdout << std::endl;
    std::cout << "\nStderr:\n" << result.Stderr << std::endl;
}

int main() {
    std::cout << "--- Running ls -l ---" << std::endl;
    auto result = Command("ls").Arg("-l").Status();
    PrintResult(result);

    std::cout << "\n--- Running ping with a 2-second timeout ---" << std::endl;
    auto ping_result = Command("ping").Arg("8.8.8.8").Timeout(std::chrono::seconds(2)).Status();
    PrintResult(ping_result);

    std::cout << "\n--- Spawning a long-running process and waiting for it ---" << std::endl;
    if (auto child = Command("sleep").Arg("3").Spawn()) {
        std::cout << "Process spawned with PID: " << child->GetPid() << std::endl;
        auto sleep_result = child->Wait();
        PrintResult(sleep_result);
    } else {
        std::cerr << "Failed to spawn sleep process." << std::endl;
    }

    std::cout << "\n--- Attempting to spawn a non-existent command ---" << std::endl;
    if (auto child = Command("nonexistentcommand").Spawn()) {
        child->Wait();
    } else {
        std::cerr << "Failed to spawn non-existent command, as expected." << std::endl;
    }

    return 0;
}
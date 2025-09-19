#include "CatalystCX.hpp"
#include <iostream>

int main() {
    std::cout << "--- Running ls -l ---" << std::endl;
    const auto result = Command("ls").Arg("-l").Status();

    std::cout << "Exit Code: " << result.ExitCode << std::endl;
    std::cout << "Execution Time: " << result.ExecutionTime.count() << "s" << std::endl;

#ifdef __linux__
    std::cout << "User CPU Time: " << result.Usage.UserCpuTime << "us" << std::endl;
    std::cout << "System CPU Time: " << result.Usage.SystemCpuTime << "us" << std::endl;
    std::cout << "Max Resident Set Size: " << result.Usage.MaxResidentSetSize << "KB" << std::endl;
#endif

    std::cout << "\nStdout:\n" << result.Stdout << std::endl;
    std::cout << "\nStderr:\n" << result.Stderr << std::endl;

    std::cout << "\n--- Running ping with a 2-second timeout ---" << std::endl;
    auto ping_result = Command("ping").Arg("8.8.8.8").Timeout(std::chrono::seconds(2)).Status();

    std::cout << "Exit Code: " << ping_result.ExitCode << std::endl;
    std::cout << "Timed Out: " << (ping_result.TimedOut ? "Yes" : "No") << std::endl;
    std::cout << "Execution Time: " << ping_result.ExecutionTime.count() << "s" << std::endl;

#ifdef __linux__
    std::cout << "User CPU Time: " << ping_result.Usage.UserCpuTime << "us" << std::endl;
    std::cout << "System CPU Time: " << ping_result.Usage.SystemCpuTime << "us" << std::endl;
    std::cout << "Max Resident Set Size: " << ping_result.Usage.MaxResidentSetSize << "KB" << std::endl;
#endif

    std::cout << "\nStdout:\n" << ping_result.Stdout << std::endl;
    std::cout << "\nStderr:\n" << ping_result.Stderr << std::endl;

    return 0;
}

#include <windows.h>

#include <cstdio>
#include <filesystem>
#include <string>

namespace {

constexpr wchar_t kManagerFileName[] = L"PassManager.exe";

void reportWinApiError(const char* text) {
    std::printf("***%s FAILED, GetLastError() = 0x%lX\n", text, GetLastError());
}

}

int wmain() {

    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const std::filesystem::path selfDirectory = [] {
        wchar_t buffer[32768] = {};
        const DWORD length = GetModuleFileNameW(nullptr, buffer, 32768);
        return std::filesystem::path(std::wstring(buffer, length)).parent_path();
    }();
    const std::filesystem::path managerPath = selfDirectory / kManagerFileName;
    std::wstring commandLine = L"\"" + managerPath.wstring() + L"\"";

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(managerPath.c_str(), commandLine.data(), nullptr, nullptr,
                                        FALSE, CREATE_SUSPENDED, nullptr,
                                        selfDirectory.c_str(), &startup, &process);
    if (!created) {
        reportWinApiError("CreateProcessW()");
        return 1;
    }
    std::printf("***CreateProcessW() success, pid = %lu\n", process.dwProcessId);

    if (!DebugActiveProcess(process.dwProcessId)) {
        reportWinApiError("DebugActiveProcess()");
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 1;
    }
    std::printf("***DebugActiveProcess() success\n");

    ResumeThread(process.hThread);
    DEBUG_EVENT debugEvent{};
    bool managerRunning = true;
    while (managerRunning) {
        if (!WaitForDebugEvent(&debugEvent, INFINITE)) {
            reportWinApiError("WaitForDebugEvent()");
            break;
        }
        DWORD continueStatus = DBG_CONTINUE;
        switch (debugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:

            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            if (debugEvent.dwProcessId == process.dwProcessId) {
                std::printf("***PassManager exited, exit code = %lu\n", debugEvent.u.ExitProcess.dwExitCode);
                managerRunning = false;
            }
            break;
        default:
            break;
        }
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
    }

    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 0;
}

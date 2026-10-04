// protector.cpp
// Приложение-протектор (ЛР1, защита от отладки методом "самоотладки").
// Протектор запускает PassManager.exe в приостановленном состоянии, подключается к нему
// как отладчик функцией DebugActiveProcess() и только после этого возобновляет процесс.
// Пока протектор подключён, сторонний отладчик (например, x64dbg) не может подключиться:
// у процесса может быть только один отладчик. Протектор обрабатывает отладочные события
// WaitForDebugEvent() / ContinueDebugEvent() до завершения менеджера паролей.
#include <windows.h>

#include <cstdio>
#include <filesystem>
#include <string>

namespace {

constexpr wchar_t kManagerFileName[] = L"PassManager.exe";

// Выводит сообщение об ошибке WinAPI вместе с кодом GetLastError().
// text - описание действия, которое не удалось выполнить.
void reportWinApiError(const char* text) {
    std::printf("***%s FAILED, GetLastError() = 0x%lX\n", text, GetLastError());
}

}  // namespace

// Точка входа протектора.
// Возвращает 0, если менеджер паролей запущен и отработал под защитой; 1 - при ошибке запуска.
int wmain() {
    // Журнал событий пишется сразу, даже если вывод перенаправлен в файл.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const std::filesystem::path selfDirectory = [] {
        wchar_t buffer[32768] = {};
        const DWORD length = GetModuleFileNameW(nullptr, buffer, 32768);
        return std::filesystem::path(std::wstring(buffer, length)).parent_path();
    }();
    const std::filesystem::path managerPath = selfDirectory / kManagerFileName;
    std::wstring commandLine = L"\"" + managerPath.wstring() + L"\"";

    // 1. Создать процесс менеджера паролей в приостановленном состоянии, чтобы подключить отладчик до старта.
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

    // 2. Подключиться к процессу как отладчик.
    if (!DebugActiveProcess(process.dwProcessId)) {
        reportWinApiError("DebugActiveProcess()");
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 1;
    }
    std::printf("***DebugActiveProcess() success\n");

    // Главный цикл отладки: возобновляем процесс и пропускаем все отладочные события.
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
            // Исключения самого менеджера передаются его собственным обработчикам.
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

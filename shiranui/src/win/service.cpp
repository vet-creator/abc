// SPDX-License-Identifier: MIT
// Windows service hosting.
#ifdef _WIN32

#include "shiranui/win/winutil.hpp"

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>

namespace shiranui::platform::service {

namespace {

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS        g_status{};
std::atomic<bool>     g_stopRequested{false};
std::mutex            g_statusMutex;

/// Body supplied by the CLI; captured in a namespace-scope slot because the
/// service entry point is a C callback with no user context parameter.
std::function<void(const std::function<bool()>&)> g_body;
Status                                            g_bodyResult = Status::success();

void report(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHintMs = 0) {
    std::lock_guard<std::mutex> lock(g_statusMutex);
    static DWORD checkPoint = 1;

    g_status.dwCurrentState  = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint      = waitHintMs;
    g_status.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    g_status.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;

    if (g_statusHandle) ::SetServiceStatus(g_statusHandle, &g_status);
}

DWORD WINAPI controlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            report(SERVICE_STOP_PENDING, NO_ERROR, 15000);
            g_stopRequested.store(true);
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
    std::wstring name = utf8ToWide(kServiceName);
    g_statusHandle    = ::RegisterServiceCtrlHandlerExW(name.c_str(), controlHandler, nullptr);
    if (!g_statusHandle) return;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    report(SERVICE_START_PENDING, NO_ERROR, 10000);
    report(SERVICE_RUNNING);

    if (g_body) {
        try {
            g_body([] { return g_stopRequested.load(); });
        } catch (const std::exception& e) {
            g_bodyResult = Status::fail(std::string("service body threw: ") + e.what());
            report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
            return;
        }
    }
    report(SERVICE_STOPPED);
}

}  // namespace

Status install(const fs::path& exePath, const std::string& arguments) {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm)
        return Status::fail("OpenSCManager: " + win32ErrorMessage(::GetLastError()) +
                            " (installation requires an elevated prompt)");
    auto scmGuard = makeGuard([&] { ::CloseServiceHandle(scm); });

    // The binary path is quoted so a directory containing a space cannot be
    // parsed as "C:\Program.exe" — the classic unquoted-service-path hijack.
    std::wstring binPath = L"\"" + exePath.wstring() + L"\"";
    if (!arguments.empty()) binPath += L" " + utf8ToWide(arguments);

    SC_HANDLE svc = ::CreateServiceW(
        scm, utf8ToWide(kServiceName).c_str(), utf8ToWide(kServiceDisplayName).c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        binPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        DWORD err = ::GetLastError();
        if (err == ERROR_SERVICE_EXISTS) return Status::fail("the service is already installed");
        return Status::fail("CreateService: " + win32ErrorMessage(err));
    }
    auto svcGuard = makeGuard([&] { ::CloseServiceHandle(svc); });

    std::wstring        description = L"Real-time file and process monitoring (SHIRANUI).";
    SERVICE_DESCRIPTIONW desc{};
    desc.lpDescription = description.data();
    ::ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    // Restart on failure: a monitoring agent that stays down after one crash is
    // indistinguishable from one an attacker successfully killed.
    SC_ACTION actions[3];
    actions[0] = {SC_ACTION_RESTART, 5000};
    actions[1] = {SC_ACTION_RESTART, 30000};
    actions[2] = {SC_ACTION_RESTART, 60000};
    SERVICE_FAILURE_ACTIONSW failure{};
    failure.dwResetPeriod = 86400;
    failure.cActions      = 3;
    failure.lpsaActions   = actions;
    ::ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &failure);

    return Status::success();
}

Status uninstall() {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return Status::fail("OpenSCManager: " + win32ErrorMessage(::GetLastError()));
    auto scmGuard = makeGuard([&] { ::CloseServiceHandle(scm); });

    SC_HANDLE svc = ::OpenServiceW(scm, utf8ToWide(kServiceName).c_str(),
                                   SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) return Status::fail("the service is not installed");
    auto svcGuard = makeGuard([&] { ::CloseServiceHandle(svc); });

    SERVICE_STATUS status{};
    ::ControlService(svc, SERVICE_CONTROL_STOP, &status);
    for (int i = 0; i < 30 && status.dwCurrentState != SERVICE_STOPPED; ++i) {
        ::Sleep(500);
        if (!::QueryServiceStatus(svc, &status)) break;
    }
    if (!::DeleteService(svc))
        return Status::fail("DeleteService: " + win32ErrorMessage(::GetLastError()));
    return Status::success();
}

Status queryState(std::string& stateOut) {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return Status::fail("OpenSCManager: " + win32ErrorMessage(::GetLastError()));
    auto scmGuard = makeGuard([&] { ::CloseServiceHandle(scm); });

    SC_HANDLE svc = ::OpenServiceW(scm, utf8ToWide(kServiceName).c_str(), SERVICE_QUERY_STATUS);
    if (!svc) {
        stateOut = "not installed";
        return Status::success();
    }
    auto svcGuard = makeGuard([&] { ::CloseServiceHandle(svc); });

    SERVICE_STATUS_PROCESS info{};
    DWORD                  needed = 0;
    if (!::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&info),
                                sizeof info, &needed))
        return Status::fail("QueryServiceStatusEx: " + win32ErrorMessage(::GetLastError()));

    switch (info.dwCurrentState) {
        case SERVICE_STOPPED:          stateOut = "stopped"; break;
        case SERVICE_START_PENDING:    stateOut = "starting"; break;
        case SERVICE_STOP_PENDING:     stateOut = "stopping"; break;
        case SERVICE_RUNNING:          stateOut = "running (pid " + fmtU64(info.dwProcessId) + ")"; break;
        case SERVICE_CONTINUE_PENDING: stateOut = "resuming"; break;
        case SERVICE_PAUSE_PENDING:    stateOut = "pausing"; break;
        case SERVICE_PAUSED:           stateOut = "paused"; break;
        default:                       stateOut = "unknown"; break;
    }
    return Status::success();
}

Status runDispatcher(const std::function<void(const std::function<bool()>&)>& body) {
    g_body          = body;
    g_stopRequested = false;

    std::wstring name = utf8ToWide(kServiceName);
    SERVICE_TABLE_ENTRYW table[] = {{name.data(), serviceMain}, {nullptr, nullptr}};

    if (!::StartServiceCtrlDispatcherW(table)) {
        DWORD err = ::GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            return Status::fail(
                "not started by the service control manager (run `shiranui service install` "
                "first, or use `shiranui monitor` to run in the foreground)");
        return Status::fail("StartServiceCtrlDispatcher: " + win32ErrorMessage(err));
    }
    return g_bodyResult;
}

}  // namespace shiranui::platform::service

#endif  // _WIN32

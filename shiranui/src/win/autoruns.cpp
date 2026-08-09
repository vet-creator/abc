// SPDX-License-Identifier: MIT
// Enumeration of persistence points and running processes.
#ifdef _WIN32

#include "shiranui/win/winutil.hpp"

#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <iterator>

namespace shiranui::platform {

namespace {

void addEntry(std::vector<AutorunEntry>& out, std::string category, std::string location,
              std::string name, std::string command) {
    if (command.empty() && name.empty()) return;
    AutorunEntry e;
    e.category  = std::move(category);
    e.location  = std::move(location);
    e.name      = std::move(name);
    e.command   = reg::expandEnvironment(command);
    e.imagePath = extractImagePath(e.command);
    out.push_back(std::move(e));
}

void collectRunKeys(std::vector<AutorunEntry>& out) {
    struct Spot { HKEY root; const wchar_t* path; const char* label; DWORD view; };
    const Spot kSpots[] = {
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "HKLM\\...\\Run", KEY_WOW64_64KEY},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "HKLM\\...\\Run (WOW64)", KEY_WOW64_32KEY},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
         "HKLM\\...\\RunOnce", KEY_WOW64_64KEY},
        {HKEY_LOCAL_MACHINE,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
         "HKLM\\...\\Policies\\Explorer\\Run", KEY_WOW64_64KEY},
        {HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "HKCU\\...\\Run", KEY_WOW64_64KEY},
        {HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
         "HKCU\\...\\RunOnce", KEY_WOW64_64KEY},
        {HKEY_CURRENT_USER,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
         "HKCU\\...\\Policies\\Explorer\\Run", KEY_WOW64_64KEY},
    };
    for (const Spot& s : kSpots)
        for (auto& [name, value] : reg::enumStringValues(s.root, s.path, s.view))
            addEntry(out, "run-key", s.label, name, value);
}

void collectWinlogon(std::vector<AutorunEntry>& out) {
    const wchar_t* kWinlogon = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    const wchar_t* kValues[] = {L"Shell", L"Userinit", L"Taskman", L"AppSetup", L"GinaDLL"};
    for (const wchar_t* v : kValues) {
        std::string value;
        if (reg::readString(HKEY_LOCAL_MACHINE, kWinlogon, v, value) && !value.empty())
            addEntry(out, "winlogon", "HKLM\\...\\Winlogon", wideToUtf8(v), value);
    }
    // Notification packages and LSA authentication packages load into lsass.
    for (auto& [name, value] :
         reg::enumStringValues(HKEY_LOCAL_MACHINE,
                               L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"))
        addEntry(out, "winlogon-notify", "HKLM\\...\\Winlogon\\Notify", name, value);
}

void collectAppInit(std::vector<AutorunEntry>& out) {
    std::string value;
    if (reg::readString(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                        L"AppInit_DLLs", value) &&
        !trim(value).empty())
        addEntry(out, "appinit-dll", "HKLM\\...\\Windows\\AppInit_DLLs", "AppInit_DLLs", value);
}

void collectIfeo(std::vector<AutorunEntry>& out) {
    // An IFEO "Debugger" value silently substitutes one program for another —
    // a classic way to hijack an application the user already trusts.
    const wchar_t* kIfeo =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    for (const std::string& sub : reg::enumSubKeys(HKEY_LOCAL_MACHINE, kIfeo)) {
        std::wstring full = std::wstring(kIfeo) + L"\\" + utf8ToWide(sub);
        std::string  dbg;
        if (reg::readString(HKEY_LOCAL_MACHINE, full.c_str(), L"Debugger", dbg) && !dbg.empty())
            addEntry(out, "ifeo-debugger", "HKLM\\...\\Image File Execution Options\\" + sub,
                     sub, dbg);
        std::string monitor;
        if (reg::readString(HKEY_LOCAL_MACHINE, full.c_str(), L"GlobalFlag", monitor) &&
            !monitor.empty()) {
            std::wstring silent =
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" +
                utf8ToWide(sub);
            std::string mon;
            if (reg::readString(HKEY_LOCAL_MACHINE, silent.c_str(), L"MonitorProcess", mon) &&
                !mon.empty())
                addEntry(out, "silent-process-exit", "HKLM\\...\\SilentProcessExit\\" + sub, sub, mon);
        }
    }
}

void collectServices(std::vector<AutorunEntry>& out) {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;
    auto guard = makeGuard([&] { ::CloseServiceHandle(scm); });

    DWORD needed = 0, returned = 0, resume = 0;
    ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
                            SERVICE_STATE_ALL, nullptr, 0, &needed, &returned, &resume, nullptr);
    if (needed == 0) return;

    std::vector<BYTE> buffer(needed);
    if (!::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
                                 SERVICE_STATE_ALL, buffer.data(), needed, &needed, &returned,
                                 &resume, nullptr))
        return;

    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    for (DWORD i = 0; i < returned; ++i) {
        std::wstring key = L"SYSTEM\\CurrentControlSet\\Services\\" +
                           std::wstring(services[i].lpServiceName);
        std::string imagePath;
        reg::readString(HKEY_LOCAL_MACHINE, key.c_str(), L"ImagePath", imagePath);
        DWORD startType = 0xFFFFFFFF;
        reg::readDword(HKEY_LOCAL_MACHINE, key.c_str(), L"Start", startType);
        // 0 = boot, 1 = system, 2 = automatic. Manual/disabled services are not
        // persistence on their own, so they are omitted to keep the list useful.
        if (startType > 2) continue;
        bool isDriver = (services[i].ServiceStatusProcess.dwServiceType &
                         (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)) != 0;
        addEntry(out, isDriver ? "driver" : "service",
                 "HKLM\\SYSTEM\\CurrentControlSet\\Services\\" +
                     wideToUtf8(services[i].lpServiceName),
                 wideToUtf8(services[i].lpDisplayName ? services[i].lpDisplayName
                                                      : services[i].lpServiceName),
                 imagePath);
    }
}

void collectStartupFolders(std::vector<AutorunEntry>& out) {
    const char* kEnvRoots[] = {"APPDATA", "ProgramData"};
    const char* kSuffix[]   = {"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                               "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"};
    for (int i = 0; i < 2; ++i) {
        const char* base = std::getenv(kEnvRoots[i]);
        if (!base) continue;
        fs::path dir = utf8ToPath(std::string(base) + kSuffix[i]);
        std::error_code ec;
        if (!fs::is_directory(dir, ec)) continue;
        for (const auto& e : fs::directory_iterator(dir, ec)) {
            if (!e.is_regular_file(ec)) continue;
            addEntry(out, "startup-folder", pathToUtf8(dir),
                     pathToUtf8(e.path().filename()), pathToUtf8(e.path()));
        }
    }
}

void collectScheduledTasks(std::vector<AutorunEntry>& out) {
    // The Task Scheduler COM API needs COM initialisation on the caller's
    // thread; reading the on-disk definitions avoids that and works even when a
    // task has been hidden from the scheduler UI by clearing its registry index.
    const char* winDir = std::getenv("SystemRoot");
    fs::path    tasks  = utf8ToPath(std::string(winDir ? winDir : "C:\\Windows")) /
                     "System32" / "Tasks";
    std::error_code ec;
    if (!fs::is_directory(tasks, ec)) return;

    std::size_t budget = 4096;
    for (auto it = fs::recursive_directory_iterator(
             tasks, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator() && budget; it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        --budget;
        auto mapped = MappedFile::open(it->path(), 512 * 1024);
        if (!mapped) continue;
        std::string xml(reinterpret_cast<const char*>(mapped->data()), mapped->size());
        // Tasks are UTF-16 XML; take a cheap ASCII projection for the tag scan.
        if (xml.size() > 1 && xml[1] == '\0') {
            std::string narrow;
            narrow.reserve(xml.size() / 2);
            for (std::size_t i = 0; i + 1 < xml.size(); i += 2)
                if (xml[i + 1] == '\0') narrow.push_back(xml[i]);
            xml.swap(narrow);
        }
        auto between = [&xml](const char* open, const char* close) -> std::string {
            std::size_t a = xml.find(open);
            if (a == std::string::npos) return {};
            a += std::strlen(open);
            std::size_t b = xml.find(close, a);
            if (b == std::string::npos) return {};
            return std::string(trim(xml.substr(a, b - a)));
        };
        std::string command = between("<Command>", "</Command>");
        if (command.empty()) continue;
        std::string args = between("<Arguments>", "</Arguments>");
        addEntry(out, "scheduled-task", pathToUtf8(it->path().parent_path()),
                 pathToUtf8(it->path().filename()),
                 args.empty() ? command : command + " " + args);
    }
}

}  // namespace

std::vector<AutorunEntry> enumerateAutoruns() {
    std::vector<AutorunEntry> out;
    collectRunKeys(out);
    collectWinlogon(out);
    collectAppInit(out);
    collectIfeo(out);
    collectServices(out);
    collectStartupFolders(out);
    collectScheduledTasks(out);
    return out;
}

// ---------------------------------------------------------------------------
// Process enumeration
// ---------------------------------------------------------------------------
namespace {

using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

/// Reads a process command line out of its PEB. Returns empty on any failure —
/// a missing command line is never worth risking a fault in the scanner.
std::string readCommandLine(HANDLE process) {
    static NtQueryInformationProcessFn query = [] {
        HMODULE nt = ::GetModuleHandleW(L"ntdll.dll");
        return nt ? reinterpret_cast<NtQueryInformationProcessFn>(
                        reinterpret_cast<void*>(::GetProcAddress(nt, "NtQueryInformationProcess")))
                  : nullptr;
    }();
    if (!query) return {};

    // Mixed-bitness inspection needs the WOW64 PEB layout; rather than guess at
    // struct offsets we simply decline, and the caller falls back to the image
    // name. Guessing here would produce silent garbage in reports.
#ifdef _WIN64
    BOOL targetIsWow64 = FALSE;
    if (::IsWow64Process(process, &targetIsWow64) && targetIsWow64) return {};
#endif

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG                     returned = 0;
    if (query(process, ProcessBasicInformation, &pbi, sizeof pbi, &returned) < 0) return {};
    if (!pbi.PebBaseAddress) return {};

    PEB peb{};
    SIZE_T read = 0;
    if (!::ReadProcessMemory(process, pbi.PebBaseAddress, &peb, sizeof peb, &read) ||
        read != sizeof peb)
        return {};
    if (!peb.ProcessParameters) return {};

    RTL_USER_PROCESS_PARAMETERS params{};
    if (!::ReadProcessMemory(process, peb.ProcessParameters, &params, sizeof params, &read) ||
        read != sizeof params)
        return {};

    USHORT len = params.CommandLine.Length;
    if (len == 0 || len > 32768) return {};
    std::wstring buffer(len / sizeof(wchar_t), L'\0');
    if (!::ReadProcessMemory(process, params.CommandLine.Buffer, buffer.data(), len, &read) ||
        read != len)
        return {};
    return wideToUtf8(buffer);
}

std::string tokenUserName(HANDLE process) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(process, TOKEN_QUERY, &token)) return {};
    auto guard = makeGuard([&] { ::CloseHandle(token); });

    DWORD size = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0) return {};
    std::vector<BYTE> buffer(size);
    if (!::GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) return {};

    auto*   user = reinterpret_cast<TOKEN_USER*>(buffer.data());
    wchar_t name[256], domain[256];
    DWORD   nameLen = static_cast<DWORD>(std::size(name));
    DWORD   domLen  = static_cast<DWORD>(std::size(domain));
    SID_NAME_USE use{};
    if (!::LookupAccountSidW(nullptr, user->User.Sid, name, &nameLen, domain, &domLen, &use))
        return {};
    return wideToUtf8(std::wstring(domain, domLen) + L"\\" + std::wstring(name, nameLen));
}

u64 fileTimeToMillis(const FILETIME& ft) {
    ULARGE_INTEGER v;
    v.LowPart  = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    if (v.QuadPart == 0) return 0;
    // 100ns ticks since 1601 -> milliseconds since 1970.
    constexpr u64 kEpochDelta = 116444736000000000ULL;
    if (v.QuadPart < kEpochDelta) return 0;
    return (v.QuadPart - kEpochDelta) / 10000ULL;
}

}  // namespace

std::vector<ProcessInfo> enumerateProcesses() {
    std::vector<ProcessInfo> out;
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return out;
    auto guard = makeGuard([&] { ::CloseHandle(snapshot); });

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof entry;
    if (!::Process32FirstW(snapshot, &entry)) return out;

    do {
        ProcessInfo info;
        info.pid       = entry.th32ProcessID;
        info.parentPid = entry.th32ParentProcessID;
        info.name      = wideToUtf8(entry.szExeFile);

        HANDLE process = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
        if (!process)
            process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
        if (process) {
            auto pguard = makeGuard([&] { ::CloseHandle(process); });
            wchar_t path[MAX_PATH * 2];
            DWORD   len = static_cast<DWORD>(std::size(path));
            if (::QueryFullProcessImageNameW(process, 0, path, &len))
                info.imagePath = fs::path(std::wstring(path, len));

            FILETIME create{}, exit{}, kernel{}, user{};
            if (::GetProcessTimes(process, &create, &exit, &kernel, &user))
                info.createTimeMs = fileTimeToMillis(create);

            info.commandLine = readCommandLine(process);
            info.user        = tokenUserName(process);
        }
        out.push_back(std::move(info));
    } while (::Process32NextW(snapshot, &entry));

    std::sort(out.begin(), out.end(),
              [](const ProcessInfo& a, const ProcessInfo& b) { return a.pid < b.pid; });
    return out;
}

}  // namespace shiranui::platform

#endif  // _WIN32

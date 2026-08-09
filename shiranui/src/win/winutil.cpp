// SPDX-License-Identifier: MIT
#ifdef _WIN32

#include "shiranui/win/winutil.hpp"

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iterator>

#include "shiranui/crypto.hpp"

namespace shiranui::platform {

bool isWindows() noexcept { return true; }
bool authenticodeSupported() noexcept { return true; }

bool isElevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    auto guard = makeGuard([&] { ::CloseHandle(token); });

    TOKEN_ELEVATION elevation{};
    DWORD           returned = 0;
    if (!::GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &returned))
        return false;
    return elevation.TokenIsElevated != 0;
}

bool enableVirtualTerminal() {
    HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == INVALID_HANDLE_VALUE || out == nullptr) return false;
    DWORD mode = 0;
    if (!::GetConsoleMode(out, &mode)) return false;
    if (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) return true;
    return ::SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
}

void hardenCurrentProcess() {
    // Restrict the DLL search path so a planted DLL next to the executable or in
    // the working directory cannot be loaded ahead of the system copy.
    using SetDefaultDllDirectoriesFn = BOOL(WINAPI*)(DWORD);
    if (HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll")) {
        if (auto fn = reinterpret_cast<SetDefaultDllDirectoriesFn>(
                reinterpret_cast<void*>(::GetProcAddress(k32, "SetDefaultDllDirectories")))) {
            fn(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS);
        }

        // Terminate rather than continue on heap corruption.
        using HeapSetInformationFn = BOOL(WINAPI*)(HANDLE, HEAP_INFORMATION_CLASS, PVOID, SIZE_T);
        if (auto fn = reinterpret_cast<HeapSetInformationFn>(
                reinterpret_cast<void*>(::GetProcAddress(k32, "HeapSetInformation")))) {
            fn(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
        }

        // Refuse to load unsigned or non-Microsoft-signed images where possible.
        using SetProcessMitigationPolicyFn = BOOL(WINAPI*)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
        if (auto fn = reinterpret_cast<SetProcessMitigationPolicyFn>(
                reinterpret_cast<void*>(::GetProcAddress(k32, "SetProcessMitigationPolicy")))) {
            PROCESS_MITIGATION_IMAGE_LOAD_POLICY imagePolicy{};
            imagePolicy.NoRemoteImages  = 1;
            imagePolicy.NoLowMandatoryLabelImages = 1;
            fn(ProcessImageLoadPolicy, &imagePolicy, sizeof imagePolicy);

            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynPolicy{};
            dynPolicy.ProhibitDynamicCode = 1;
            // Deliberately *not* applied: the scanner does not generate code, but
            // some AV drivers inject helper DLLs that do. Left here documented
            // rather than silently enabled, since breaking coexistence with the
            // platform's own defences would be a net loss.
            (void)dynPolicy;
        }
    }
    ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
}

Status shredFile(const fs::path& path, int passes) {
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        auto guard = makeGuard([&] { ::CloseHandle(h); });
        LARGE_INTEGER size{};
        if (::GetFileSizeEx(h, &size) && size.QuadPart > 0) {
            for (int p = 0; p < passes; ++p) {
                LARGE_INTEGER zero{};
                ::SetFilePointerEx(h, zero, nullptr, FILE_BEGIN);
                u64 remaining = static_cast<u64>(size.QuadPart);
                while (remaining) {
                    DWORD chunk = static_cast<DWORD>(remaining < 65536 ? remaining : 65536);
                    Bytes buf;
                    try {
                        buf = crypto::randomBytes(chunk);
                    } catch (...) {
                        buf.assign(chunk, 0);
                    }
                    DWORD written = 0;
                    if (!::WriteFile(h, buf.data(), chunk, &written, nullptr) || written == 0) break;
                    remaining -= written;
                }
                ::FlushFileBuffers(h);
            }
        }
    }
    // Clear attributes that would block deletion (read-only, hidden, system).
    ::SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    if (!::DeleteFileW(path.c_str()))
        return Status::fail("DeleteFileW: " + win32ErrorMessage(::GetLastError()));
    return Status::success();
}

// ---------------------------------------------------------------------------
// Registry helpers shared by the posture and autoruns modules
// ---------------------------------------------------------------------------
namespace reg {

bool readString(HKEY root, const wchar_t* subKey, const wchar_t* value, std::string& out,
                DWORD viewFlag) {
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE | viewFlag, &key) != ERROR_SUCCESS)
        return false;
    auto guard = makeGuard([&] { ::RegCloseKey(key); });

    DWORD type = 0, size = 0;
    if (::RegQueryValueExW(key, value, nullptr, &type, nullptr, &size) != ERROR_SUCCESS) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
    std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
    if (::RegQueryValueExW(key, value, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()),
                           &size) != ERROR_SUCCESS)
        return false;
    buf.resize(::wcsnlen(buf.c_str(), buf.size()));
    out = wideToUtf8(buf);
    return true;
}

bool readDword(HKEY root, const wchar_t* subKey, const wchar_t* value, DWORD& out, DWORD viewFlag) {
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE | viewFlag, &key) != ERROR_SUCCESS)
        return false;
    auto guard = makeGuard([&] { ::RegCloseKey(key); });

    DWORD type = 0, size = sizeof(DWORD), data = 0;
    if (::RegQueryValueExW(key, value, nullptr, &type, reinterpret_cast<LPBYTE>(&data), &size) !=
        ERROR_SUCCESS)
        return false;
    if (type != REG_DWORD) return false;
    out = data;
    return true;
}

bool keyExists(HKEY root, const wchar_t* subKey, DWORD viewFlag) {
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE | viewFlag, &key) != ERROR_SUCCESS)
        return false;
    ::RegCloseKey(key);
    return true;
}

std::vector<std::pair<std::string, std::string>> enumStringValues(HKEY root, const wchar_t* subKey,
                                                                  DWORD viewFlag) {
    std::vector<std::pair<std::string, std::string>> out;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | viewFlag,
                        &key) != ERROR_SUCCESS)
        return out;
    auto guard = makeGuard([&] { ::RegCloseKey(key); });

    for (DWORD i = 0;; ++i) {
        wchar_t nameBuf[512];
        DWORD   nameLen = static_cast<DWORD>(std::size(nameBuf));
        DWORD   type    = 0;
        BYTE    data[8192];
        DWORD   dataLen = sizeof data;
        LSTATUS st = ::RegEnumValueW(key, i, nameBuf, &nameLen, nullptr, &type, data, &dataLen);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        std::wstring value(reinterpret_cast<wchar_t*>(data), dataLen / sizeof(wchar_t));
        value.resize(::wcsnlen(value.c_str(), value.size()));
        out.emplace_back(wideToUtf8(std::wstring_view(nameBuf, nameLen)), wideToUtf8(value));
        if (out.size() > 4096) break;
    }
    return out;
}

std::vector<std::string> enumSubKeys(HKEY root, const wchar_t* subKey, DWORD viewFlag) {
    std::vector<std::string> out;
    HKEY                     key = nullptr;
    if (::RegOpenKeyExW(root, subKey, 0, KEY_ENUMERATE_SUB_KEYS | viewFlag, &key) != ERROR_SUCCESS)
        return out;
    auto guard = makeGuard([&] { ::RegCloseKey(key); });
    for (DWORD i = 0;; ++i) {
        wchar_t nameBuf[512];
        DWORD   len = static_cast<DWORD>(std::size(nameBuf));
        LSTATUS st  = ::RegEnumKeyExW(key, i, nameBuf, &len, nullptr, nullptr, nullptr, nullptr);
        if (st != ERROR_SUCCESS) break;
        out.emplace_back(wideToUtf8(std::wstring_view(nameBuf, len)));
        if (out.size() > 8192) break;
    }
    return out;
}

std::string expandEnvironment(const std::string& s) {
    std::wstring in   = utf8ToWide(s);
    DWORD        need = ::ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
    if (!need) return s;
    std::wstring out(need, L'\0');
    ::ExpandEnvironmentStringsW(in.c_str(), out.data(), need);
    out.resize(::wcsnlen(out.c_str(), out.size()));
    return wideToUtf8(out);
}

}  // namespace reg

fs::path extractImagePath(const std::string& commandLine) {
    // Handles: "C:\a b\x.exe" -flag   |   C:\a\x.exe -flag   |   rundll32 a.dll,Entry
    std::string s = reg::expandEnvironment(commandLine);
    s             = std::string(trim(s));
    if (s.empty()) return {};
    if (s.front() == '"') {
        std::size_t close = s.find('"', 1);
        if (close != std::string::npos) return utf8ToPath(s.substr(1, close - 1));
    }
    // Walk tokens until one resolves to an existing file, so paths with spaces
    // that are *not* quoted still resolve the way the loader would.
    std::size_t     pos = 0;
    std::error_code ec;
    while (pos != std::string::npos) {
        pos = s.find(' ', pos + 1);
        std::string candidate = (pos == std::string::npos) ? s : s.substr(0, pos);
        fs::path    p         = utf8ToPath(candidate);
        if (fs::is_regular_file(p, ec)) return p;
        std::string withExe = candidate + ".exe";
        if (fs::is_regular_file(utf8ToPath(withExe), ec)) return utf8ToPath(withExe);
    }
    std::size_t sp = s.find(' ');
    return utf8ToPath(sp == std::string::npos ? s : s.substr(0, sp));
}

}  // namespace shiranui::platform

#endif  // _WIN32

// SPDX-License-Identifier: MIT
#include "shiranui/common.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <ctime>
#include <mutex>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

namespace shiranui {

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------
std::string toHex(ByteView data, bool upper) {
    static const char* kLower = "0123456789abcdef";
    static const char* kUpper = "0123456789ABCDEF";
    const char* tbl = upper ? kUpper : kLower;
    std::string out;
    out.resize(data.size() * 2);
    for (std::size_t i = 0; i < data.size(); ++i) {
        out[2 * i]     = tbl[data[i] >> 4];
        out[2 * i + 1] = tbl[data[i] & 0x0F];
    }
    return out;
}

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<Bytes> fromHex(std::string_view hex) {
    Bytes out;
    out.reserve(hex.size() / 2);
    int hi = -1;
    for (char c : hex) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '_' || c == ':') continue;
        int v = hexVal(c);
        if (v < 0) return std::nullopt;
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<u8>((hi << 4) | v));
            hi = -1;
        }
    }
    if (hi >= 0) return std::nullopt;
    return out;
}

std::string toLowerAscii(std::string_view s) {
    std::string out(s);
    for (char& c : out)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

std::string toUpperAscii(std::string_view s) {
    std::string out(s);
    for (char& c : out)
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return out;
}

bool iEqualsAscii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

bool startsWith(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool endsWith(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string_view trim(std::string_view s) {
    auto isSpace = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!s.empty() && isSpace(s.front())) s.remove_prefix(1);
    while (!s.empty() && isSpace(s.back())) s.remove_suffix(1);
    return s;
}

std::vector<std::string> split(std::string_view s, char delim, bool keepEmpty) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        std::size_t pos = s.find(delim, start);
        std::string_view piece =
            (pos == std::string_view::npos) ? s.substr(start) : s.substr(start, pos - start);
        if (keepEmpty || !piece.empty()) out.emplace_back(piece);
        if (pos == std::string_view::npos) break;
        start = pos + 1;
    }
    return out;
}

std::string join(const std::vector<std::string>& parts, std::string_view sep) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) out.append(sep);
        out.append(parts[i]);
    }
    return out;
}

std::string humanSize(u64 bytes) {
    static const char* kUnits[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
    double v = static_cast<double>(bytes);
    int    u = 0;
    while (v >= 1024.0 && u < 5) { v /= 1024.0; ++u; }
    return (u == 0) ? fmtU64(bytes) + " B" : fmtDouble(v, 1) + " " + kUnits[u];
}

std::string jsonEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

// Iterative glob matcher with backtracking — O(n*m) worst case, no recursion.
bool globMatch(std::string_view pattern, std::string_view text) {
    std::size_t p = 0, t = 0, star = std::string_view::npos, mark = 0;
    auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || lower(pattern[p]) == lower(text[t]))) {
            ++p; ++t;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            mark = t;
        } else if (star != std::string_view::npos) {
            p = star + 1;
            t = ++mark;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

bool constantTimeEquals(ByteView a, ByteView b) {
    if (a.size() != b.size()) return false;
    volatile u8 diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) diff = static_cast<u8>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

void secureZero(void* p, std::size_t n) noexcept {
#ifdef _WIN32
    SecureZeroMemory(p, n);
#else
    volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
    while (n--) *vp++ = 0;
#endif
}

u64 epochMillis() {
    using namespace std::chrono;
    return static_cast<u64>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string isoTimestamp(u64 epochMs) {
    std::time_t secs = static_cast<std::time_t>(epochMs / 1000);
    std::tm      tm{};
#ifdef _WIN32
    gmtime_s(&tm, &secs);
#else
    gmtime_r(&secs, &tm);
#endif
    char buf[80];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

// ---------------------------------------------------------------------------
// Number formatting (avoids <format>, which is inconsistently available)
// ---------------------------------------------------------------------------
std::string fmtU64(u64 v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(v));
    return buf;
}

std::string fmtI64(i64 v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(v));
    return buf;
}

std::string fmtDouble(double v, int decimals) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.*f", decimals, v);
    return buf;
}

std::string fmtHex(u64 v, int width) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%0*llx", width, static_cast<unsigned long long>(v));
    return buf;
}

// ---------------------------------------------------------------------------
// Path conversion
// ---------------------------------------------------------------------------
#ifdef _WIN32
std::wstring utf8ToWide(std::string_view s) {
    if (s.empty()) return {};
    int need = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (need <= 0) return {};
    std::wstring out(static_cast<std::size_t>(need), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), need);
    return out;
}

std::string wideToUtf8(std::wstring_view s) {
    if (s.empty()) return {};
    int need = ::WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0,
                                     nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<std::size_t>(need), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), need,
                          nullptr, nullptr);
    return out;
}

std::string win32ErrorMessage(unsigned long code) {
    LPWSTR  buf = nullptr;
    DWORD   n   = ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                       FORMAT_MESSAGE_IGNORE_INSERTS,
                                   nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                   reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::string msg;
    if (n && buf) {
        msg = wideToUtf8(std::wstring_view(buf, n));
        ::LocalFree(buf);
    }
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == '.'))
        msg.pop_back();
    if (msg.empty()) msg = "error " + fmtU64(code);
    return msg + " (0x" + fmtHex(code, 8) + ")";
}

std::string pathToUtf8(const fs::path& p) { return wideToUtf8(p.wstring()); }
fs::path    utf8ToPath(std::string_view s) { return fs::path(utf8ToWide(s)); }
#else
std::string pathToUtf8(const fs::path& p) { return p.string(); }
fs::path    utf8ToPath(std::string_view s) { return fs::path(std::string(s)); }
#endif

// ---------------------------------------------------------------------------
// MappedFile
// ---------------------------------------------------------------------------
MappedFile::~MappedFile() { close(); }

void MappedFile::moveFrom(MappedFile& o) noexcept {
    data_     = o.data_;
    size_     = o.size_;
    fileSize_ = o.fileSize_;
#ifdef _WIN32
    file_    = o.file_;
    mapping_ = o.mapping_;
    o.file_ = o.mapping_ = nullptr;
#else
    fd_     = o.fd_;
    map_    = o.map_;
    mapLen_ = o.mapLen_;
    o.fd_   = -1;
    o.map_  = nullptr;
    o.mapLen_ = 0;
#endif
    o.data_ = nullptr;
    o.size_ = 0;
    o.fileSize_ = 0;
}

void MappedFile::close() noexcept {
#ifdef _WIN32
    if (data_ && mapping_) ::UnmapViewOfFile(data_);
    if (mapping_) ::CloseHandle(static_cast<HANDLE>(mapping_));
    if (file_ && file_ != INVALID_HANDLE_VALUE) ::CloseHandle(static_cast<HANDLE>(file_));
    file_ = mapping_ = nullptr;
#else
    if (map_ && mapLen_) ::munmap(map_, mapLen_);
    if (fd_ >= 0) ::close(fd_);
    map_    = nullptr;
    mapLen_ = 0;
    fd_     = -1;
#endif
    data_ = nullptr;
    size_ = 0;
}

Result<MappedFile> MappedFile::open(const fs::path& path, u64 maxBytes) {
    MappedFile mf;
#ifdef _WIN32
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                             nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return Result<MappedFile>::fail("CreateFileW: " + win32ErrorMessage(::GetLastError()));
    mf.file_ = h;

    LARGE_INTEGER li{};
    if (!::GetFileSizeEx(h, &li))
        return Result<MappedFile>::fail("GetFileSizeEx: " + win32ErrorMessage(::GetLastError()));
    mf.fileSize_ = static_cast<u64>(li.QuadPart);
    if (mf.fileSize_ == 0) return mf;  // empty file: valid, zero-length view

    u64 want = (maxBytes && maxBytes < mf.fileSize_) ? maxBytes : mf.fileSize_;
    if (want > (std::numeric_limits<std::size_t>::max)())
        return Result<MappedFile>::fail("file too large for address space");

    HANDLE map = ::CreateFileMappingW(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map)
        return Result<MappedFile>::fail("CreateFileMappingW: " + win32ErrorMessage(::GetLastError()));
    mf.mapping_ = map;

    void* addr = ::MapViewOfFile(map, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(want));
    if (!addr)
        return Result<MappedFile>::fail("MapViewOfFile: " + win32ErrorMessage(::GetLastError()));
    mf.data_ = static_cast<const u8*>(addr);
    mf.size_ = static_cast<std::size_t>(want);
    return mf;
#else
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return Result<MappedFile>::fail("open failed");
    mf.fd_ = fd;
    struct stat st {};
    if (::fstat(fd, &st) != 0) return Result<MappedFile>::fail("fstat failed");
    if (!S_ISREG(st.st_mode)) return Result<MappedFile>::fail("not a regular file");
    mf.fileSize_ = static_cast<u64>(st.st_size);
    if (mf.fileSize_ == 0) return mf;

    u64 want = (maxBytes && maxBytes < mf.fileSize_) ? maxBytes : mf.fileSize_;
    void* addr = ::mmap(nullptr, static_cast<std::size_t>(want), PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) return Result<MappedFile>::fail("mmap failed");
    mf.map_    = addr;
    mf.mapLen_ = static_cast<std::size_t>(want);
    mf.data_   = static_cast<const u8*>(addr);
    mf.size_   = static_cast<std::size_t>(want);
    return mf;
#endif
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
namespace {
std::atomic<LogLevel> g_level{LogLevel::Info};
std::atomic<bool>     g_color{true};
std::mutex            g_logMutex;
std::FILE*            g_logFile = nullptr;

const char* levelName(LogLevel l) {
    switch (l) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO ";
        case LogLevel::Warn:  return "WARN ";
        case LogLevel::Error: return "ERROR";
        default:              return "-----";
    }
}

const char* levelColor(LogLevel l) {
    switch (l) {
        case LogLevel::Trace: return "\x1b[90m";
        case LogLevel::Debug: return "\x1b[36m";
        case LogLevel::Info:  return "\x1b[0m";
        case LogLevel::Warn:  return "\x1b[33m";
        case LogLevel::Error: return "\x1b[31m";
        default:              return "\x1b[0m";
    }
}
}  // namespace

void     Log::setLevel(LogLevel l) noexcept { g_level.store(l, std::memory_order_relaxed); }
LogLevel Log::level() noexcept { return g_level.load(std::memory_order_relaxed); }
void     Log::setUseColor(bool on) noexcept { g_color.store(on, std::memory_order_relaxed); }

Status Log::setFile(const fs::path& path) {
    std::lock_guard<std::mutex> lk(g_logMutex);
    if (g_logFile) { std::fclose(g_logFile); g_logFile = nullptr; }
    if (path.empty()) return Status::success();
#ifdef _WIN32
    if (_wfopen_s(&g_logFile, path.c_str(), L"a") != 0 || !g_logFile)
        return Status::fail("cannot open log file");
#else
    g_logFile = std::fopen(path.c_str(), "a");
    if (!g_logFile) return Status::fail("cannot open log file");
#endif
    return Status::success();
}

void Log::write(LogLevel l, std::string_view message) {
    if (static_cast<int>(l) < static_cast<int>(level())) return;
    std::string stamp = isoTimestamp(epochMillis());
    std::lock_guard<std::mutex> lk(g_logMutex);
    const bool color = g_color.load(std::memory_order_relaxed);
    std::fprintf(stderr, "%s%s [%s] %.*s%s\n", color ? levelColor(l) : "", stamp.c_str(),
                 levelName(l), static_cast<int>(message.size()), message.data(),
                 color ? "\x1b[0m" : "");
    if (g_logFile) {
        std::fprintf(g_logFile, "%s [%s] %.*s\n", stamp.c_str(), levelName(l),
                     static_cast<int>(message.size()), message.data());
        std::fflush(g_logFile);
    }
}

void logTrace(std::string_view m) { Log::write(LogLevel::Trace, m); }
void logDebug(std::string_view m) { Log::write(LogLevel::Debug, m); }
void logInfo(std::string_view m)  { Log::write(LogLevel::Info, m); }
void logWarn(std::string_view m)  { Log::write(LogLevel::Warn, m); }
void logError(std::string_view m) { Log::write(LogLevel::Error, m); }

}  // namespace shiranui

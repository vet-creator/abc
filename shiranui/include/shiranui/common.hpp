// SPDX-License-Identifier: MIT
// SHIRANUI (不知火) — Endpoint Threat Detection Engine for Windows
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace shiranui {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

using Bytes    = std::vector<u8>;
using ByteView = std::span<const u8>;
namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Result<T> — a minimal, allocation-light expected type.
// ---------------------------------------------------------------------------
template <class T>
class Result {
public:
    Result(T v) : value_(std::move(v)) {}  // NOLINT(google-explicit-constructor)

    static Result fail(std::string message) {
        Result r;
        r.error_ = std::move(message);
        return r;
    }

    [[nodiscard]] bool ok() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return ok(); }

    T&       operator*() { return *value_; }
    const T& operator*() const { return *value_; }
    T*       operator->() { return &*value_; }
    const T* operator->() const { return &*value_; }

    [[nodiscard]] const std::string& error() const noexcept { return error_; }
    [[nodiscard]] T valueOr(T fallback) const { return value_ ? *value_ : std::move(fallback); }

private:
    Result() = default;
    std::optional<T> value_;
    std::string      error_;
};

struct Status {
    bool        ok = true;
    std::string message;

    static Status success() { return {}; }
    static Status fail(std::string m) { return Status{false, std::move(m)}; }
    explicit operator bool() const noexcept { return ok; }
};

// ---------------------------------------------------------------------------
// Scope guard
// ---------------------------------------------------------------------------
template <class F>
class ScopeGuard {
public:
    explicit ScopeGuard(F f) : f_(std::move(f)) {}
    ~ScopeGuard() { if (active_) f_(); }
    ScopeGuard(const ScopeGuard&)            = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;
    ScopeGuard(ScopeGuard&& o) noexcept : f_(std::move(o.f_)), active_(o.active_) { o.active_ = false; }
    void dismiss() noexcept { active_ = false; }

private:
    F    f_;
    bool active_ = true;
};

template <class F>
ScopeGuard<F> makeGuard(F f) { return ScopeGuard<F>(std::move(f)); }

// ---------------------------------------------------------------------------
// String / byte helpers
// ---------------------------------------------------------------------------
std::string                toHex(ByteView data, bool upper = false);
std::optional<Bytes>       fromHex(std::string_view hex);
std::string                toLowerAscii(std::string_view s);
std::string                toUpperAscii(std::string_view s);
bool                       iEqualsAscii(std::string_view a, std::string_view b);
bool                       startsWith(std::string_view s, std::string_view prefix);
bool                       endsWith(std::string_view s, std::string_view suffix);
std::string_view           trim(std::string_view s);
std::vector<std::string>   split(std::string_view s, char delim, bool keepEmpty = false);
std::string                join(const std::vector<std::string>& parts, std::string_view sep);
std::string                humanSize(u64 bytes);
std::string                jsonEscape(std::string_view s);
/// Case-insensitive glob supporting '*' and '?'. Used for path exclusions.
bool                       globMatch(std::string_view pattern, std::string_view text);
/// Byte-for-byte comparison in constant time (length is not secret).
bool                       constantTimeEquals(ByteView a, ByteView b);
/// Wipes a buffer in a way the optimiser may not remove.
void                       secureZero(void* p, std::size_t n) noexcept;

/// Milliseconds since the Unix epoch.
u64         epochMillis();
/// ISO-8601 UTC timestamp, e.g. 2026-08-09T12:34:56Z
std::string isoTimestamp(u64 epochMs);

// ---------------------------------------------------------------------------
// Native path <-> UTF-8 conversion (Windows uses UTF-16 natively)
// ---------------------------------------------------------------------------
std::string  pathToUtf8(const fs::path& p);
fs::path     utf8ToPath(std::string_view s);

#ifdef _WIN32
std::wstring utf8ToWide(std::string_view s);
std::string  wideToUtf8(std::wstring_view s);
/// Formats a Win32 error code (GetLastError / HRESULT) as UTF-8 text.
std::string  win32ErrorMessage(unsigned long code);
#endif

// ---------------------------------------------------------------------------
// Memory-mapped read-only file (falls back to a plain read for tiny files).
// ---------------------------------------------------------------------------
class MappedFile {
public:
    MappedFile() = default;
    ~MappedFile();
    MappedFile(const MappedFile&)            = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& o) noexcept { moveFrom(o); }
    MappedFile& operator=(MappedFile&& o) noexcept {
        if (this != &o) { close(); moveFrom(o); }
        return *this;
    }

    /// Opens `path` for reading. `maxBytes` caps how much is mapped (0 = whole file).
    static Result<MappedFile> open(const fs::path& path, u64 maxBytes = 0);

    void close() noexcept;

    [[nodiscard]] ByteView   view() const noexcept { return ByteView(data_, size_); }
    [[nodiscard]] const u8*  data() const noexcept { return data_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] u64        fileSize() const noexcept { return fileSize_; }
    [[nodiscard]] bool       truncated() const noexcept { return fileSize_ > size_; }

private:
    void moveFrom(MappedFile& o) noexcept;

    const u8*   data_     = nullptr;
    std::size_t size_     = 0;
    u64         fileSize_ = 0;
#ifdef _WIN32
    void* file_    = nullptr;   // HANDLE
    void* mapping_ = nullptr;   // HANDLE
#else
    int   fd_ = -1;
    void* map_ = nullptr;
    std::size_t mapLen_ = 0;
#endif
};

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
enum class LogLevel { Trace = 0, Debug, Info, Warn, Error, Off };

class Log {
public:
    static void        setLevel(LogLevel l) noexcept;
    static LogLevel    level() noexcept;
    /// Mirrors output into a file (append mode). Empty path disables.
    static Status      setFile(const fs::path& path);
    static void        setUseColor(bool on) noexcept;
    static void        write(LogLevel l, std::string_view message);
};

void logTrace(std::string_view m);
void logDebug(std::string_view m);
void logInfo(std::string_view m);
void logWarn(std::string_view m);
void logError(std::string_view m);

/// Minimal ostringstream-free number formatting helpers used across the engine.
std::string fmtU64(u64 v);
std::string fmtI64(i64 v);
std::string fmtDouble(double v, int decimals = 2);
std::string fmtHex(u64 v, int width = 0);

}  // namespace shiranui

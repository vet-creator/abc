// SPDX-License-Identifier: MIT
// Windows platform integration.
//
// Everything here is declared unconditionally and stubbed out on other systems,
// so the engine, the CLI and the whole test suite build and run on Linux/macOS
// for development. Only the implementations under src/win are Windows-specific.
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "shiranui/common.hpp"

namespace shiranui::platform {

// ---------------------------------------------------------------------------
// Capability probes
// ---------------------------------------------------------------------------
bool isWindows() noexcept;
bool authenticodeSupported() noexcept;
/// True when the current process holds an elevated administrator token.
bool isElevated();
/// Enables ANSI escape processing on the console; returns false if unavailable.
bool enableVirtualTerminal();
/// Best-effort hardening of the current process (mitigation policies, DLL search
/// path lockdown). A security tool is itself a target.
void hardenCurrentProcess();

// ---------------------------------------------------------------------------
// Authenticode
// ---------------------------------------------------------------------------
struct SignatureResult {
    bool        valid    = false;
    bool        present  = false;
    std::string signerName;
    std::string timestamp;
    std::string status;      ///< human-readable outcome
    std::string thumbprint;  ///< SHA-1 thumbprint of the signing certificate
};

SignatureResult verifyAuthenticode(const fs::path& file);

// ---------------------------------------------------------------------------
// System security posture
// ---------------------------------------------------------------------------
struct PostureItem {
    std::string id;
    std::string title;
    std::string state;        ///< "enabled", "disabled", "unknown", ...
    bool        healthy = true;
    std::string recommendation;
    std::string evidence;     ///< where the value came from
};

/// Reads a broad set of platform security settings. Read-only: this never
/// changes machine configuration, it only reports.
std::vector<PostureItem> auditPosture();

// ---------------------------------------------------------------------------
// Persistence (autorun) enumeration
// ---------------------------------------------------------------------------
struct AutorunEntry {
    std::string category;     ///< "run-key", "service", "scheduled-task", ...
    std::string location;     ///< registry path, task folder, ...
    std::string name;
    std::string command;      ///< raw command line
    fs::path    imagePath;    ///< resolved executable, when it could be extracted
};

std::vector<AutorunEntry> enumerateAutoruns();

// ---------------------------------------------------------------------------
// Running processes
// ---------------------------------------------------------------------------
struct ProcessInfo {
    u32         pid       = 0;
    u32         parentPid = 0;
    std::string name;
    fs::path    imagePath;
    std::string commandLine;
    std::string user;
    u64         createTimeMs = 0;
};

std::vector<ProcessInfo> enumerateProcesses();

// ---------------------------------------------------------------------------
// Real-time monitoring
// ---------------------------------------------------------------------------
struct FileEvent {
    enum class Kind { Created, Modified, Renamed, Deleted } kind = Kind::Created;
    fs::path path;
    u64      timestampMs = 0;
};

struct ProcessEvent {
    enum class Kind { Started, Stopped } kind = Kind::Started;
    ProcessInfo info;
    u64         timestampMs = 0;
};

/// Watches directory trees for file changes. Windows uses ReadDirectoryChangesW
/// bound to an I/O completion port; other platforms report unsupported.
class FileWatcher {
public:
    using Handler = std::function<void(const FileEvent&)>;

    FileWatcher();
    ~FileWatcher();
    FileWatcher(const FileWatcher&)            = delete;
    FileWatcher& operator=(const FileWatcher&) = delete;

    Status addRoot(const fs::path& directory);
    Status start(Handler handler);
    void   stop();
    [[nodiscard]] bool running() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Watches process creation and exit by polling the process list. Very
/// short-lived processes can be missed; `backend()` reports the mechanism in
/// use so a caller never has to assume. See src/win/procmon.cpp for why polling
/// is preferred over an ETW kernel session here.
class ProcessWatcher {
public:
    using Handler = std::function<void(const ProcessEvent&)>;

    ProcessWatcher();
    ~ProcessWatcher();
    ProcessWatcher(const ProcessWatcher&)            = delete;
    ProcessWatcher& operator=(const ProcessWatcher&) = delete;

    Status start(Handler handler);
    void   stop();
    [[nodiscard]] bool running() const;
    /// "etw" or "polling" once started.
    [[nodiscard]] std::string backend() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Windows service hosting
// ---------------------------------------------------------------------------
namespace service {

constexpr const char* kServiceName        = "ShiranuiSvc";
constexpr const char* kServiceDisplayName = "SHIRANUI Endpoint Protection";

Status install(const fs::path& exePath, const std::string& arguments);
Status uninstall();
Status queryState(std::string& stateOut);
/// Runs the service dispatcher. `body` is invoked on a worker thread and must
/// return promptly once `stopRequested()` becomes true.
Status runDispatcher(const std::function<void(const std::function<bool()>& stopRequested)>& body);

}  // namespace service

// ---------------------------------------------------------------------------
// Secure deletion helper (used by the quarantine purge path)
// ---------------------------------------------------------------------------
/// Overwrites the file's contents before unlinking. On modern SSDs this is not
/// a guarantee of unrecoverability — it is a best-effort measure and documented
/// as such rather than promising more than the hardware can deliver.
Status shredFile(const fs::path& path, int passes = 1);

}  // namespace shiranui::platform

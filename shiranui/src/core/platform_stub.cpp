// SPDX-License-Identifier: MIT
// Portable fallbacks so the engine, CLI and tests build on non-Windows hosts.
#ifndef _WIN32

#include <cstdio>
#include <fstream>

#include "shiranui/crypto.hpp"
#include "shiranui/platform.hpp"

namespace shiranui::platform {

bool isWindows() noexcept { return false; }
bool authenticodeSupported() noexcept { return false; }
bool isElevated() { return false; }
bool enableVirtualTerminal() { return true; }
void hardenCurrentProcess() {}

SignatureResult verifyAuthenticode(const fs::path&) {
    SignatureResult r;
    r.status = "Authenticode verification is only available on Windows";
    return r;
}

std::vector<PostureItem> auditPosture() { return {}; }
std::vector<AutorunEntry> enumerateAutoruns() { return {}; }
std::vector<ProcessInfo> enumerateProcesses() { return {}; }

struct FileWatcher::Impl {};
FileWatcher::FileWatcher() = default;
FileWatcher::~FileWatcher() = default;
Status FileWatcher::addRoot(const fs::path&) { return Status::fail("file watching requires Windows"); }
Status FileWatcher::start(Handler) { return Status::fail("file watching requires Windows"); }
void   FileWatcher::stop() {}
bool   FileWatcher::running() const { return false; }

struct ProcessWatcher::Impl {};
ProcessWatcher::ProcessWatcher() = default;
ProcessWatcher::~ProcessWatcher() = default;
Status ProcessWatcher::start(Handler) { return Status::fail("process watching requires Windows"); }
void   ProcessWatcher::stop() {}
bool   ProcessWatcher::running() const { return false; }
std::string ProcessWatcher::backend() const { return "unsupported"; }

namespace service {
Status install(const fs::path&, const std::string&) { return Status::fail("services require Windows"); }
Status uninstall() { return Status::fail("services require Windows"); }
Status queryState(std::string&) { return Status::fail("services require Windows"); }
Status runDispatcher(const std::function<void(const std::function<bool()>&)>&) {
    return Status::fail("services require Windows");
}
}  // namespace service

Status shredFile(const fs::path& path, int passes) {
    std::error_code ec;
    auto size = fs::file_size(path, ec);
    if (!ec && size > 0) {
        std::fstream f(path, std::ios::binary | std::ios::in | std::ios::out);
        if (f) {
            for (int p = 0; p < passes; ++p) {
                f.seekp(0);
                u64 remaining = size;
                while (remaining) {
                    std::size_t chunk = static_cast<std::size_t>(remaining < 65536 ? remaining : 65536);
                    Bytes       buf   = crypto::randomBytes(chunk);
                    f.write(reinterpret_cast<const char*>(buf.data()),
                            static_cast<std::streamsize>(chunk));
                    remaining -= chunk;
                }
                f.flush();
            }
        }
    }
    fs::remove(path, ec);
    if (ec) return Status::fail("remove failed: " + ec.message());
    return Status::success();
}

}  // namespace shiranui::platform

#endif  // !_WIN32

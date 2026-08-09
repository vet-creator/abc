// SPDX-License-Identifier: MIT
// Process start/stop watcher.
//
// Implementation note: this uses snapshot polling rather than ETW. An ETW
// session on Microsoft-Windows-Kernel-Process gives lower latency and catches
// processes that live for less than one poll interval, but it requires
// SeSystemProfilePrivilege, an exclusive-ish session name, and careful teardown
// to avoid leaving an orphaned kernel session behind on a crash. Polling has
// none of those failure modes and degrades honestly: the documented tradeoff is
// that very short-lived processes can be missed. `backend()` reports which
// mechanism is live so callers never have to guess.
#ifdef _WIN32

#include "shiranui/win/winutil.hpp"

#include <tlhelp32.h>

#include <atomic>
#include <chrono>
#include <iterator>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace shiranui::platform {

namespace {

constexpr auto kPollInterval = std::chrono::milliseconds(500);

/// Cheap snapshot: pid -> executable name. Deliberately avoids OpenProcess so a
/// poll over a few hundred processes stays well under a millisecond.
std::unordered_map<u32, std::string> snapshotPids() {
    std::unordered_map<u32, std::string> out;
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return out;
    auto guard = makeGuard([&] { ::CloseHandle(snapshot); });

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof entry;
    if (!::Process32FirstW(snapshot, &entry)) return out;
    do {
        out.emplace(entry.th32ProcessID, wideToUtf8(entry.szExeFile));
    } while (::Process32NextW(snapshot, &entry));
    return out;
}

}  // namespace

struct ProcessWatcher::Impl {
    std::thread             worker;
    std::atomic<bool>       running{false};
    std::mutex              mutex;
    std::condition_variable cv;
    Handler                 handler;
};

ProcessWatcher::ProcessWatcher() : impl_(std::make_unique<Impl>()) {}

ProcessWatcher::~ProcessWatcher() { stop(); }

Status ProcessWatcher::start(Handler handler) {
    if (impl_->running.load()) return Status::fail("process watcher is already running");
    impl_->handler = std::move(handler);
    impl_->running.store(true);

    impl_->worker = std::thread([this] {
        std::unordered_map<u32, std::string> previous = snapshotPids();

        while (impl_->running.load()) {
            {
                std::unique_lock<std::mutex> lock(impl_->mutex);
                impl_->cv.wait_for(lock, kPollInterval, [this] { return !impl_->running.load(); });
            }
            if (!impl_->running.load()) break;

            std::unordered_map<u32, std::string> current = snapshotPids();
            if (current.empty()) continue;

            for (const auto& [pid, name] : current) {
                auto it = previous.find(pid);
                // A pid whose image name changed is a reused pid, so the old
                // process ended and a new one began — report both.
                if (it != previous.end() && it->second == name) continue;
                if (it != previous.end()) {
                    ProcessEvent stopped;
                    stopped.kind        = ProcessEvent::Kind::Stopped;
                    stopped.info.pid    = pid;
                    stopped.info.name   = it->second;
                    stopped.timestampMs = epochMillis();
                    if (impl_->handler) impl_->handler(stopped);
                }

                ProcessEvent ev;
                ev.kind        = ProcessEvent::Kind::Started;
                ev.timestampMs = epochMillis();
                ev.info.pid    = pid;
                ev.info.name   = name;

                HANDLE process = ::OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (!process)
                    process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (process) {
                    auto    guard = makeGuard([&] { ::CloseHandle(process); });
                    wchar_t path[MAX_PATH * 2];
                    DWORD   len = static_cast<DWORD>(std::size(path));
                    if (::QueryFullProcessImageNameW(process, 0, path, &len))
                        ev.info.imagePath = fs::path(std::wstring(path, len));
                }
                if (impl_->handler) impl_->handler(ev);
            }

            for (const auto& [pid, name] : previous) {
                if (current.count(pid)) continue;
                ProcessEvent ev;
                ev.kind        = ProcessEvent::Kind::Stopped;
                ev.info.pid    = pid;
                ev.info.name   = name;
                ev.timestampMs = epochMillis();
                if (impl_->handler) impl_->handler(ev);
            }

            previous.swap(current);
        }
    });
    return Status::success();
}

void ProcessWatcher::stop() {
    if (!impl_) return;
    if (impl_->running.exchange(false)) {
        impl_->cv.notify_all();
        if (impl_->worker.joinable()) impl_->worker.join();
    }
}

bool ProcessWatcher::running() const { return impl_ && impl_->running.load(); }

std::string ProcessWatcher::backend() const { return "polling"; }

}  // namespace shiranui::platform

#endif  // _WIN32

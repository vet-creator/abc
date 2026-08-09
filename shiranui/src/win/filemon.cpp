// SPDX-License-Identifier: MIT
// Directory tree watcher built on ReadDirectoryChangesW bound to an I/O
// completion port. One worker thread services every watched root, so watching
// a dozen trees costs one thread rather than a dozen.
#ifdef _WIN32

#include "shiranui/win/winutil.hpp"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

namespace shiranui::platform {

namespace {

constexpr DWORD kNotifyFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
                                FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION;

/// 64 KiB is the documented ceiling for a buffer used over a network share and
/// a comfortable size locally. A larger buffer would silently fail on UNC roots.
constexpr std::size_t kBufferBytes = 64 * 1024;

struct RootContext {
    OVERLAPPED         overlapped{};
    HANDLE             directory = INVALID_HANDLE_VALUE;
    fs::path           path;
    std::vector<DWORD> buffer;   ///< DWORD-typed so the alignment FILE_NOTIFY_INFORMATION
                                 ///< requires is guaranteed by the allocator.

    RootContext() : buffer(kBufferBytes / sizeof(DWORD)) {}

    ~RootContext() {
        if (directory != INVALID_HANDLE_VALUE) ::CloseHandle(directory);
    }

    bool arm() {
        std::memset(&overlapped, 0, sizeof overlapped);
        return ::ReadDirectoryChangesW(directory, buffer.data(),
                                       static_cast<DWORD>(buffer.size() * sizeof(DWORD)),
                                       TRUE,  // watch the whole subtree
                                       kNotifyFilter, nullptr, &overlapped, nullptr) != 0;
    }
};

}  // namespace

struct FileWatcher::Impl {
    HANDLE                                    iocp = nullptr;
    std::vector<std::unique_ptr<RootContext>> roots;
    std::thread                               worker;
    std::atomic<bool>                         running{false};
    Handler                                   handler;
};

FileWatcher::FileWatcher() : impl_(std::make_unique<Impl>()) {}

FileWatcher::~FileWatcher() { stop(); }

Status FileWatcher::addRoot(const fs::path& directory) {
    std::error_code ec;
    if (!fs::is_directory(directory, ec))
        return Status::fail(pathToUtf8(directory) + " is not a directory");
    if (impl_->running.load())
        return Status::fail("roots cannot be added while the watcher is running");

    if (!impl_->iocp) {
        impl_->iocp = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        if (!impl_->iocp)
            return Status::fail("CreateIoCompletionPort: " + win32ErrorMessage(::GetLastError()));
    }

    auto ctx  = std::make_unique<RootContext>();
    ctx->path = directory;
    ctx->directory =
        ::CreateFileW(directory.c_str(), FILE_LIST_DIRECTORY,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (ctx->directory == INVALID_HANDLE_VALUE)
        return Status::fail("cannot open " + pathToUtf8(directory) + ": " +
                            win32ErrorMessage(::GetLastError()));

    if (!::CreateIoCompletionPort(ctx->directory, impl_->iocp,
                                  reinterpret_cast<ULONG_PTR>(ctx.get()), 1))
        return Status::fail("CreateIoCompletionPort(bind): " +
                            win32ErrorMessage(::GetLastError()));

    impl_->roots.push_back(std::move(ctx));
    return Status::success();
}

Status FileWatcher::start(Handler handler) {
    if (impl_->running.load()) return Status::fail("watcher is already running");
    if (impl_->roots.empty()) return Status::fail("no roots have been added");

    impl_->handler = std::move(handler);
    for (auto& root : impl_->roots)
        if (!root->arm())
            return Status::fail("ReadDirectoryChangesW on " + pathToUtf8(root->path) + ": " +
                                win32ErrorMessage(::GetLastError()));

    impl_->running.store(true);
    impl_->worker = std::thread([this] {
        while (impl_->running.load()) {
            DWORD        transferred = 0;
            ULONG_PTR    key         = 0;
            OVERLAPPED*  overlapped  = nullptr;
            BOOL ok = ::GetQueuedCompletionStatus(impl_->iocp, &transferred, &key, &overlapped,
                                                  INFINITE);
            if (!impl_->running.load()) break;
            if (!ok || key == 0 || overlapped == nullptr) {
                if (!ok && overlapped == nullptr) break;   // port closed
                continue;
            }

            auto* ctx = reinterpret_cast<RootContext*>(key);

            // transferred == 0 means the kernel overflowed the buffer and dropped
            // the individual records. Report the root itself so the caller can
            // rescan rather than silently missing the events.
            if (transferred == 0) {
                if (impl_->handler) {
                    FileEvent ev;
                    ev.kind        = FileEvent::Kind::Modified;
                    ev.path        = ctx->path;
                    ev.timestampMs = epochMillis();
                    impl_->handler(ev);
                }
                ctx->arm();
                continue;
            }

            const auto* base   = reinterpret_cast<const BYTE*>(ctx->buffer.data());
            DWORD       offset = 0;
            while (offset + sizeof(FILE_NOTIFY_INFORMATION) <= transferred) {
                const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(base + offset);
                // Bounds-check the variable-length name against what was actually
                // transferred: this record comes from the kernel, but a truncated
                // final entry would still walk off the buffer.
                if (offset + offsetof(FILE_NOTIFY_INFORMATION, FileName) + info->FileNameLength >
                    transferred)
                    break;

                std::wstring name(info->FileName, info->FileNameLength / sizeof(wchar_t));
                FileEvent    ev;
                ev.path        = ctx->path / name;
                ev.timestampMs = epochMillis();
                switch (info->Action) {
                    case FILE_ACTION_ADDED:
                    case FILE_ACTION_RENAMED_NEW_NAME: ev.kind = FileEvent::Kind::Created; break;
                    case FILE_ACTION_REMOVED:
                    case FILE_ACTION_RENAMED_OLD_NAME: ev.kind = FileEvent::Kind::Deleted; break;
                    default:                           ev.kind = FileEvent::Kind::Modified; break;
                }
                if (info->Action == FILE_ACTION_RENAMED_NEW_NAME)
                    ev.kind = FileEvent::Kind::Renamed;

                if (impl_->handler) impl_->handler(ev);

                if (info->NextEntryOffset == 0) break;
                DWORD next = offset + info->NextEntryOffset;
                if (next <= offset) break;   // malformed chain; refuse to spin
                offset = next;
            }
            ctx->arm();
        }
    });
    return Status::success();
}

void FileWatcher::stop() {
    if (!impl_) return;
    if (impl_->running.exchange(false)) {
        for (auto& root : impl_->roots)
            if (root->directory != INVALID_HANDLE_VALUE) ::CancelIoEx(root->directory, nullptr);
        if (impl_->iocp) ::PostQueuedCompletionStatus(impl_->iocp, 0, 0, nullptr);
        if (impl_->worker.joinable()) impl_->worker.join();
    }
    impl_->roots.clear();
    if (impl_->iocp) {
        ::CloseHandle(impl_->iocp);
        impl_->iocp = nullptr;
    }
}

bool FileWatcher::running() const { return impl_ && impl_->running.load(); }

}  // namespace shiranui::platform

#endif  // _WIN32

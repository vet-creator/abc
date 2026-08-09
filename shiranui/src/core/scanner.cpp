// SPDX-License-Identifier: MIT
#include "shiranui/scanner.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <thread>

#include "shiranui/analysis.hpp"
#include "shiranui/crypto.hpp"
#include "shiranui/platform.hpp"

namespace shiranui {

std::string ScanStats::summary() const {
    return "scanned " + fmtU64(filesScanned.load()) + " file(s) / " +
           humanSize(bytesScanned.load()) + " in " + fmtDouble(static_cast<double>(elapsedMs) / 1000.0, 2) +
           "s; " + fmtU64(malicious.load()) + " malicious, " + fmtU64(suspicious.load()) +
           " suspicious, " + fmtU64(filesSkipped.load()) + " skipped, " + fmtU64(errors.load()) +
           " error(s)";
}

ScanEngine::ScanEngine(const sig::RuleSet& rules, ScanOptions options)
    : rules_(rules), options_(std::move(options)), heuristics_(options_.heuristics) {}

ScanEngine::~ScanEngine() = default;

bool ScanEngine::shouldSkip(const fs::path& path) const {
    std::string p = pathToUtf8(path);
    for (const std::string& g : options_.excludeGlobs)
        if (globMatch(g, p)) return true;
    if (!options_.includeExtensions.empty()) {
        std::string ext = toLowerAscii(pathToUtf8(path.extension()));
        bool        hit = false;
        for (const std::string& e : options_.includeExtensions) {
            std::string want = toLowerAscii(e);
            if (!want.empty() && want[0] != '.') want.insert(want.begin(), '.');
            if (ext == want) { hit = true; break; }
        }
        if (!hit) return true;
    }
    return false;
}

FileVerdict ScanEngine::scanFile(const fs::path& path) const {
    FileVerdict v;
    v.path = path;

    std::error_code ec;
    auto            fileSize = fs::file_size(path, ec);
    if (ec) {
        v.disposition = Disposition::Error;
        v.error       = "cannot stat file: " + ec.message();
        return v;
    }
    v.size = static_cast<u64>(fileSize);

    if (v.size == 0) {
        v.sha256 = crypto::Sha256::hex(ByteView{});
        return v;
    }

    // Hash the whole file even when the content scan is capped, so exact-hash
    // intelligence still works on very large samples.
    {
        auto mapped = MappedFile::open(path, options_.maxFileSize);
        if (!mapped) {
            v.disposition = Disposition::Error;
            v.error       = mapped.error();
            return v;
        }
        ByteView all = mapped->view();
        v.sha256     = crypto::Sha256::hex(all);
        if (options_.computeFuzzyHash && all.size() <= 32ull * 1024 * 1024)
            v.fuzzyHash = analysis::FuzzyHash::compute(all);

        // ---- Exact-hash intelligence ---------------------------------
        if (const auto* he = rules_.lookupSha256(v.sha256)) {
            Detection d;
            d.source      = "hash";
            d.name        = he->name;
            d.description = "SHA-256 matches a known-bad entry" +
                            (he->family.empty() ? std::string() : " (" + he->family + ")");
            d.severity = he->severity;
            d.weight   = 100.0;
            v.detections.push_back(std::move(d));
        }

        ByteView deep = all;
        if (deep.size() > options_.deepScanLimit) deep = deep.subspan(0, options_.deepScanLimit);

        // ---- Format analysis -----------------------------------------
        v.isPe = pe::looksLikePe(all);
        if (v.isPe) {
            v.peInfo = pe::parse(all);
            if (v.peInfo.valid && !v.peInfo.imphash.empty()) {
                if (const auto* he = rules_.lookupImphash(v.peInfo.imphash)) {
                    Detection d;
                    d.source      = "hash";
                    d.name        = he->name;
                    d.description = "Import hash matches a known-bad entry";
                    d.severity    = he->severity;
                    d.weight      = 60.0;
                    v.detections.push_back(std::move(d));
                }
            }
        }

        // ---- Authenticode --------------------------------------------
        if (options_.verifySignatures && v.isPe && platform::authenticodeSupported()) {
            platform::SignatureResult sr = platform::verifyAuthenticode(path);
            v.signatureChecked           = true;
            v.signatureValid             = sr.valid;
            v.signerName                 = sr.signerName;
            v.signatureStatus            = sr.status;
        }

        // ---- Signature rules -----------------------------------------
        for (const sig::RuleHit& hit : rules_.scan(deep)) {
            Detection d;
            d.source      = "signature";
            d.name        = hit.rule->name;
            d.description = hit.rule->description.empty()
                                ? ("matched rule " + hit.rule->name)
                                : hit.rule->description;
            d.severity       = hit.rule->severity;
            d.offset         = hit.firstOffset;
            d.matchedStrings = hit.matchedStrings;
            switch (hit.rule->severity) {
                case Severity::Critical: d.weight = 100.0; break;
                case Severity::High:     d.weight = 55.0;  break;
                case Severity::Medium:   d.weight = 25.0;  break;
                case Severity::Low:      d.weight = 8.0;   break;
                default:                 d.weight = 2.0;   break;
            }
            v.detections.push_back(std::move(d));
        }

        heuristics_.evaluate(v, deep);
    }
    return v;
}

void ScanEngine::scanPath(const fs::path& root, const ResultCallback& onResult, ScanStats& stats,
                          const ProgressCallback& onProgress) {
    const auto started = std::chrono::steady_clock::now();

    unsigned nThreads = options_.threads;
    if (nThreads == 0) nThreads = std::max(1u, std::thread::hardware_concurrency());

    std::deque<fs::path>    queue;
    std::mutex              queueMutex;
    std::condition_variable queueCv;
    std::mutex              resultMutex;
    bool                    producerDone = false;

    auto emit = [&](const FileVerdict& v) {
        std::lock_guard<std::mutex> lk(resultMutex);
        switch (v.disposition) {
            case Disposition::Malicious:  stats.malicious.fetch_add(1); break;
            case Disposition::Suspicious: stats.suspicious.fetch_add(1); break;
            case Disposition::Error:      stats.errors.fetch_add(1); break;
            default: break;
        }
        if (onResult) onResult(v);
    };

    auto worker = [&]() {
        for (;;) {
            fs::path item;
            {
                std::unique_lock<std::mutex> lk(queueMutex);
                queueCv.wait(lk, [&] { return !queue.empty() || producerDone; });
                if (queue.empty()) {
                    if (producerDone) return;
                    continue;
                }
                item = std::move(queue.front());
                queue.pop_front();
            }
            if (cancelled()) return;

            FileVerdict v = scanFile(item);
            stats.filesScanned.fetch_add(1);
            stats.bytesScanned.fetch_add(v.size);
            emit(v);
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(nThreads);
    for (unsigned i = 0; i < nThreads; ++i) pool.emplace_back(worker);

    auto push = [&](fs::path p) {
        {
            std::lock_guard<std::mutex> lk(queueMutex);
            queue.push_back(std::move(p));
        }
        queueCv.notify_one();
    };

    std::error_code ec;
    if (fs::is_regular_file(root, ec)) {
        stats.filesSeen.fetch_add(1);
        if (shouldSkip(root)) stats.filesSkipped.fetch_add(1);
        else                  push(root);
    } else if (fs::is_directory(root, ec)) {
        auto opts = options_.followSymlinks ? fs::directory_options::follow_directory_symlink
                                            : fs::directory_options::skip_permission_denied;
        if (!options_.followSymlinks)
            opts |= fs::directory_options::skip_permission_denied;

        fs::recursive_directory_iterator it(root, opts, ec), end;
        if (ec) {
            FileVerdict v;
            v.path        = root;
            v.disposition = Disposition::Error;
            v.error       = "cannot open directory: " + ec.message();
            emit(v);
        }
        for (; it != end; it.increment(ec)) {
            if (cancelled()) break;
            if (ec) { stats.errors.fetch_add(1); ec.clear(); continue; }

            const fs::path& p = it->path();
            std::error_code sec;
            if (it->is_directory(sec)) {
                stats.directories.fetch_add(1);
                // Never descend into a reparse point unless explicitly allowed:
                // junction loops otherwise make traversal unbounded.
                if (!options_.followSymlinks && fs::is_symlink(p, sec)) it.disable_recursion_pending();
                if (shouldSkip(p)) it.disable_recursion_pending();
                continue;
            }
            if (!it->is_regular_file(sec)) continue;

            stats.filesSeen.fetch_add(1);
            if (shouldSkip(p)) { stats.filesSkipped.fetch_add(1); continue; }

            // Back-pressure: never let the queue grow without bound.
            for (;;) {
                std::size_t depth;
                {
                    std::lock_guard<std::mutex> lk(queueMutex);
                    depth = queue.size();
                }
                if (depth < static_cast<std::size_t>(nThreads) * 64 || cancelled()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            push(p);

            if (onProgress && (stats.filesSeen.load() % 256) == 0) {
                std::lock_guard<std::mutex> lk(resultMutex);
                onProgress(stats, p);
            }
        }
    } else {
        FileVerdict v;
        v.path        = root;
        v.disposition = Disposition::Error;
        v.error       = "path is neither a regular file nor a directory";
        emit(v);
    }

    {
        std::lock_guard<std::mutex> lk(queueMutex);
        producerDone = true;
    }
    queueCv.notify_all();
    for (std::thread& t : pool) t.join();

    stats.elapsedMs = static_cast<u64>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started)
            .count());
}

}  // namespace shiranui

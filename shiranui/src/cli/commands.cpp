// SPDX-License-Identifier: MIT
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

#include "cli.hpp"
#include "shiranui/analysis.hpp"
#include "shiranui/crypto.hpp"
#include "shiranui/pe.hpp"
#include "shiranui/platform.hpp"
#include "shiranui/quarantine.hpp"
#include "shiranui/scanner.hpp"
#include "shiranui/signature.hpp"

namespace shiranui::cli {

namespace {

std::atomic<bool> g_interrupted{false};

void onSignal(int) { g_interrupted.store(true); }

/// Rules ship next to the executable; a developer build finds them one level up.
fs::path locateRules(const Args& args) {
    std::string explicitDir = args.value("rules");
    if (!explicitDir.empty()) return utf8ToPath(explicitDir);

    std::error_code ec;
    fs::path        exeDir = executableDirectory();
    for (const fs::path& candidate :
         {exeDir / "rules", exeDir.parent_path() / "rules", fs::current_path(ec) / "rules"})
        if (fs::is_directory(candidate, ec)) return candidate;
    return exeDir / "rules";
}

Result<sig::RuleSet> loadRules(const Args& args) {
    auto     rules = std::make_unique<sig::RuleSet>();
    fs::path dir   = locateRules(args);

    std::error_code ec;
    if (!fs::is_directory(dir, ec))
        return Result<sig::RuleSet>::fail("rule directory not found: " + pathToUtf8(dir) +
                                          " (use --rules to point at it)");
    Status s = rules->loadDirectory(dir);
    if (!s) return Result<sig::RuleSet>::fail(s.message);
    rules->compile();
    return std::move(*rules);
}

std::string severityColor(Severity s, std::string_view text) {
    switch (s) {
        case Severity::Critical: return Style::red(text);
        case Severity::High:     return Style::red(text);
        case Severity::Medium:   return Style::yellow(text);
        case Severity::Low:      return Style::cyan(text);
        default:                 return Style::dim(text);
    }
}

std::string dispositionBadge(Disposition d) {
    switch (d) {
        case Disposition::Malicious:  return Style::red("MALICIOUS ");
        case Disposition::Suspicious: return Style::yellow("SUSPICIOUS");
        case Disposition::Error:      return Style::dim("ERROR     ");
        default:                      return Style::green("clean     ");
    }
}

void printDetections(const FileVerdict& v, const std::string& indent) {
    for (const Detection& d : v.detections) {
        std::string line = indent + severityColor(d.severity, std::string(severityName(d.severity)));
        line += "  " + Style::bold(d.name);
        if (d.weight != 0.0)
            line += Style::dim(" (" + std::string(d.weight > 0 ? "+" : "") + fmtDouble(d.weight, 1) + ")");
        std::cout << line << "\n";
        if (!d.description.empty())
            std::cout << indent << "      " << Style::dim(d.description) << "\n";
        if (!d.matchedStrings.empty()) {
            std::string joined = join(d.matchedStrings, ", ");
            if (joined.size() > 160) joined = joined.substr(0, 157) + "...";
            std::cout << indent << "      " << Style::dim("matched: " + joined) << "\n";
        }
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------
int runScan(const Args& args) {
    if (args.positional.empty()) {
        std::cerr << "usage: shiranui scan <path> [path...] [options]\n";
        return 2;
    }

    auto rules = loadRules(args);
    if (!rules) {
        std::cerr << Style::red("error: ") << rules.error() << "\n";
        return 2;
    }

    ScanOptions options;
    options.threads          = static_cast<unsigned>(args.number("threads", 0));
    options.computeFuzzyHash = !args.has("no-fuzzy");
    options.verifySignatures = !args.has("no-signature-check");
    options.followSymlinks   = args.has("follow-symlinks");
    if (args.has("max-size")) options.maxFileSize = args.number("max-size", 256) * 1024 * 1024;
    options.excludeGlobs      = args.values("exclude");
    options.includeExtensions = args.values("ext");

    const bool json    = args.has("json");
    const bool showAll = args.has("all");
    const bool quiet   = args.has("quiet") || json;
    const bool doQuarantine = args.has("quarantine");

    std::unique_ptr<Quarantine> store;
    if (doQuarantine) {
        std::string dir = args.value("quarantine-dir");
        store = std::make_unique<Quarantine>(dir.empty() ? Quarantine::defaultRoot()
                                                         : utf8ToPath(dir));
        Status s = store->open();
        if (!s) {
            std::cerr << Style::red("error: ") << "cannot open quarantine store: " << s.message
                      << "\n";
            return 2;
        }
    }

    ScanEngine engine(*rules, options);
    ScanStats  stats;

    std::signal(SIGINT, onSignal);

    if (!quiet) {
        std::cout << Style::bold("SHIRANUI") << Style::dim(" — scanning with ")
                  << fmtU64(rules->ruleCount()) << Style::dim(" rules, ")
                  << fmtU64(rules->patternCount()) << Style::dim(" patterns")
                  << (options.threads ? Style::dim(", " + fmtU64(options.threads) + " threads") : "")
                  << "\n\n";
    }

    std::atomic<u64> flagged{0};
    auto onResult = [&](const FileVerdict& v) {
        if (g_interrupted.load()) engine.cancel();

        const bool interesting = v.disposition == Disposition::Malicious ||
                                 v.disposition == Disposition::Suspicious;
        if (interesting) ++flagged;

        if (json) {
            if (interesting || showAll) std::cout << v.toJson() << "\n";
            return;
        }
        if (!interesting && !showAll) return;

        std::cout << dispositionBadge(v.disposition) << " " << pathToUtf8(v.path)
                  << Style::dim("  " + humanSize(v.size) + "  score " + fmtDouble(v.score, 1))
                  << "\n";
        if (!v.sha256.empty()) std::cout << "      " << Style::dim("sha256 " + v.sha256) << "\n";
        printDetections(v, "      ");

        if (doQuarantine && v.disposition == Disposition::Malicious) {
            auto rec = store->quarantineFile(v.path, v);
            if (rec)
                std::cout << "      " << Style::magenta("quarantined as " + rec->id) << "\n";
            else
                std::cout << "      " << Style::red("quarantine failed: " + rec.error()) << "\n";
        }
        std::cout << "\n";
    };

    auto started = std::chrono::steady_clock::now();
    for (const std::string& target : args.positional) {
        if (g_interrupted.load()) break;
        engine.scanPath(utf8ToPath(target), onResult, stats);
    }
    stats.elapsedMs = static_cast<u64>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                              started)
            .count());

    if (!json) {
        std::cout << Style::bold("── summary ──") << "\n" << stats.summary() << "\n";
        if (g_interrupted.load()) std::cout << Style::yellow("scan was interrupted\n");
    }

    if (stats.malicious.load() > 0) return 1;
    if (stats.suspicious.load() > 0) return 3;
    return 0;
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------
int runInspect(const Args& args) {
    if (args.positional.empty()) {
        std::cerr << "usage: shiranui inspect <file>\n";
        return 2;
    }
    fs::path path   = utf8ToPath(args.positional.front());
    auto     mapped = MappedFile::open(path);
    if (!mapped) {
        std::cerr << Style::red("error: ") << mapped.error() << "\n";
        return 2;
    }
    ByteView data = mapped->view();

    std::cout << Style::bold(pathToUtf8(path)) << "\n";
    std::cout << "  size        " << humanSize(data.size()) << " (" << fmtU64(data.size())
              << " bytes)\n";
    std::cout << "  sha256      " << crypto::Sha256::hex(data) << "\n";
    std::cout << "  entropy     " << fmtDouble(analysis::shannonEntropy(data), 4) << " bits/byte\n";
    std::cout << "  printable   " << fmtDouble(analysis::printableRatio(data) * 100.0, 1) << "%\n";
    std::cout << "  ssdeep-like " << analysis::FuzzyHash::compute(data) << "\n";

    if (platform::authenticodeSupported()) {
        auto sig = platform::verifyAuthenticode(path);
        std::cout << "  signature   "
                  << (sig.valid ? Style::green("valid") : Style::yellow(sig.status));
        if (!sig.signerName.empty()) std::cout << "  " << Style::dim(sig.signerName);
        std::cout << "\n";
    }

    if (!pe::looksLikePe(data)) {
        std::cout << Style::dim("\n  not a PE image\n");
        return 0;
    }

    pe::Info info = pe::parse(data);
    if (!info.valid) {
        std::cout << Style::red("\n  PE parse failed: ") << info.parseError << "\n";
        return 1;
    }

    std::cout << "\n" << Style::bold("  PE header") << "\n";
    std::cout << "    machine     " << info.machineName() << (info.is64Bit ? " (64-bit)" : " (32-bit)")
              << "\n";
    std::cout << "    subsystem   " << info.subsystemName() << "\n";
    std::cout << "    kind        "
              << (info.isDriver ? "driver" : (info.isDll ? "DLL" : "executable"))
              << (info.isDotNet ? " [.NET]" : "") << "\n";
    std::cout << "    timestamp   " << (info.timestamp ? isoTimestamp(u64(info.timestamp) * 1000)
                                                       : std::string("0 (removed or reproducible)"))
              << "\n";
    std::cout << "    image base  0x" << fmtHex(info.imageBase, 8) << "\n";
    std::cout << "    entry       0x" << fmtHex(info.entryPointRva, 8);
    if (info.entryPointSection >= 0 &&
        static_cast<std::size_t>(info.entryPointSection) < info.sections.size())
        std::cout << " in " << info.sections[info.entryPointSection].name;
    std::cout << "\n";
    std::cout << "    checksum    0x" << fmtHex(info.headerChecksum, 8)
              << (info.checksumValid ? Style::green("  valid") : Style::yellow("  mismatch")) << "\n";
    if (!info.imphash.empty()) std::cout << "    imphash     " << info.imphash << "\n";
    if (!info.pdbPath.empty()) std::cout << "    pdb         " << info.pdbPath << "\n";

    std::cout << "\n" << Style::bold("  sections") << "\n";
    for (const pe::Section& s : info.sections) {
        std::string flags;
        flags += s.code() ? 'C' : '-';
        flags += s.executable() ? 'X' : '-';
        flags += s.writable() ? 'W' : '-';
        std::string line = "    " + s.name;
        line.resize(14, ' ');
        line += "va 0x" + fmtHex(s.virtualAddress, 8) + "  raw " + humanSize(s.rawSize);
        line.resize(56, ' ');
        line += flags + "  H=" + fmtDouble(s.entropy, 3);
        if (s.executable() && s.writable()) line = Style::red(line) + Style::red("  W+X");
        else if (s.entropy > 7.2) line = Style::yellow(line);
        std::cout << line << "\n";
    }

    if (!info.imports.empty()) {
        std::cout << "\n" << Style::bold("  imports") << Style::dim(" (" + fmtU64(info.imports.size()) + " modules)") << "\n";
        for (const pe::ImportedDll& dll : info.imports) {
            std::cout << "    " << dll.name << Style::dim(dll.delayLoad ? " [delay-load]" : "")
                      << Style::dim("  " + fmtU64(dll.functions.size()) + " functions") << "\n";
            if (args.has("verbose"))
                for (const std::string& fn : dll.functions)
                    std::cout << "        " << Style::dim(fn) << "\n";
        }
    }

    if (!info.exports.empty()) {
        std::cout << "\n" << Style::bold("  exports") << Style::dim(" (" + fmtU64(info.exports.size()) + ")") << "\n";
        std::size_t shown = 0;
        for (const std::string& e : info.exports) {
            std::cout << "    " << e << "\n";
            if (++shown >= 40 && !args.has("verbose")) {
                std::cout << Style::dim("    ... " + fmtU64(info.exports.size() - shown) + " more\n");
                break;
            }
        }
    }

    if (info.overlaySize) {
        std::cout << "\n" << Style::bold("  overlay") << "\n";
        std::cout << "    offset 0x" << fmtHex(info.overlayOffset, 8) << "  size "
                  << humanSize(info.overlaySize) << "  H=" << fmtDouble(info.overlayEntropy, 3)
                  << "\n";
    }

    if (!info.anomalies.empty()) {
        std::cout << "\n" << Style::bold("  anomalies") << "\n";
        for (const std::string& a : info.anomalies)
            std::cout << "    " << Style::yellow("• ") << a << "\n";
    }
    return 0;
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------
int runAudit(const Args& args) {
    if (!platform::isWindows()) {
        std::cerr << Style::yellow("posture auditing is only available on Windows\n");
        return 2;
    }
    auto items = platform::auditPosture();
    if (items.empty()) {
        std::cerr << Style::yellow("no posture data could be read\n");
        return 2;
    }

    if (args.has("json")) {
        std::cout << "[";
        for (std::size_t i = 0; i < items.size(); ++i) {
            const auto& it = items[i];
            std::cout << (i ? "," : "") << "{\"id\":\"" << jsonEscape(it.id) << "\",\"title\":\""
                      << jsonEscape(it.title) << "\",\"state\":\"" << jsonEscape(it.state)
                      << "\",\"healthy\":" << (it.healthy ? "true" : "false")
                      << ",\"recommendation\":\"" << jsonEscape(it.recommendation)
                      << "\",\"evidence\":\"" << jsonEscape(it.evidence) << "\"}";
        }
        std::cout << "]\n";
        return 0;
    }

    std::size_t bad = 0;
    std::cout << Style::bold("system security posture") << "\n\n";
    for (const auto& it : items) {
        if (!it.healthy) ++bad;
        std::string mark = it.healthy ? Style::green("  OK  ") : Style::red(" WARN ");
        std::string title = it.title;
        title.resize(44, ' ');
        std::cout << mark << " " << title << Style::dim(it.state) << "\n";
        if (!it.healthy && !it.recommendation.empty())
            std::cout << "        " << Style::dim(it.recommendation) << "\n";
    }
    std::cout << "\n"
              << fmtU64(items.size() - bad) << " of " << fmtU64(items.size())
              << " checks healthy\n";
    return bad ? 3 : 0;
}

// ---------------------------------------------------------------------------
// autoruns
// ---------------------------------------------------------------------------
int runAutoruns(const Args& args) {
    if (!platform::isWindows()) {
        std::cerr << Style::yellow("autorun enumeration is only available on Windows\n");
        return 2;
    }
    auto entries = platform::enumerateAutoruns();
    const bool doScan = args.has("scan");

    std::unique_ptr<sig::RuleSet> rules;
    std::unique_ptr<ScanEngine>   engine;
    if (doScan) {
        auto loaded = loadRules(args);
        if (!loaded) {
            std::cerr << Style::red("error: ") << loaded.error() << "\n";
            return 2;
        }
        rules  = std::make_unique<sig::RuleSet>(std::move(*loaded));
        engine = std::make_unique<ScanEngine>(*rules, ScanOptions{});
    }

    if (args.has("json")) {
        std::cout << "[";
        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto& e = entries[i];
            std::cout << (i ? "," : "") << "{\"category\":\"" << jsonEscape(e.category)
                      << "\",\"location\":\"" << jsonEscape(e.location) << "\",\"name\":\""
                      << jsonEscape(e.name) << "\",\"command\":\"" << jsonEscape(e.command)
                      << "\",\"image\":\"" << jsonEscape(pathToUtf8(e.imagePath)) << "\"}";
        }
        std::cout << "]\n";
        return 0;
    }

    std::cout << Style::bold("persistence points") << Style::dim(" (" + fmtU64(entries.size()) + ")")
              << "\n\n";
    std::string lastCategory;
    int         findings = 0;
    for (const auto& e : entries) {
        if (e.category != lastCategory) {
            std::cout << "\n" << Style::cyan(e.category) << "\n";
            lastCategory = e.category;
        }
        std::cout << "  " << Style::bold(e.name) << "\n";
        std::cout << "    " << Style::dim(e.command) << "\n";

        if (engine && !e.imagePath.empty()) {
            std::error_code ec;
            if (!fs::is_regular_file(e.imagePath, ec)) {
                std::cout << "    " << Style::yellow("image not found on disk") << "\n";
                continue;
            }
            FileVerdict v = engine->scanFile(e.imagePath);
            if (v.disposition != Disposition::Clean) {
                ++findings;
                std::cout << "    " << dispositionBadge(v.disposition) << " score "
                          << fmtDouble(v.score, 1) << "\n";
                printDetections(v, "      ");
            }
        }
    }
    if (engine)
        std::cout << "\n" << fmtU64(static_cast<u64>(findings)) << " autorun target(s) flagged\n";
    return findings ? 3 : 0;
}

// ---------------------------------------------------------------------------
// ps
// ---------------------------------------------------------------------------
int runProcesses(const Args& args) {
    if (!platform::isWindows()) {
        std::cerr << Style::yellow("process listing is only available on Windows\n");
        return 2;
    }
    auto procs = platform::enumerateProcesses();

    if (args.has("json")) {
        std::cout << "[";
        for (std::size_t i = 0; i < procs.size(); ++i) {
            const auto& p = procs[i];
            std::cout << (i ? "," : "") << "{\"pid\":" << p.pid << ",\"ppid\":" << p.parentPid
                      << ",\"name\":\"" << jsonEscape(p.name) << "\",\"image\":\""
                      << jsonEscape(pathToUtf8(p.imagePath)) << "\",\"user\":\""
                      << jsonEscape(p.user) << "\",\"command_line\":\""
                      << jsonEscape(p.commandLine) << "\"}";
        }
        std::cout << "]\n";
        return 0;
    }

    std::unique_ptr<sig::RuleSet> rules;
    std::unique_ptr<ScanEngine>   engine;
    if (args.has("scan")) {
        auto loaded = loadRules(args);
        if (!loaded) {
            std::cerr << Style::red("error: ") << loaded.error() << "\n";
            return 2;
        }
        rules  = std::make_unique<sig::RuleSet>(std::move(*loaded));
        engine = std::make_unique<ScanEngine>(*rules, ScanOptions{});
    }

    int findings = 0;
    std::cout << Style::bold("  PID   PPID  IMAGE") << "\n";
    for (const auto& p : procs) {
        std::string pid = fmtU64(p.pid);
        pid.insert(pid.begin(), 5 - std::min<std::size_t>(5, pid.size()), ' ');
        std::string ppid = fmtU64(p.parentPid);
        ppid.insert(ppid.begin(), 6 - std::min<std::size_t>(6, ppid.size()), ' ');
        std::cout << pid << " " << ppid << "  "
                  << (p.imagePath.empty() ? p.name : pathToUtf8(p.imagePath));
        if (!p.user.empty()) std::cout << Style::dim("  " + p.user);
        std::cout << "\n";

        if (engine && !p.imagePath.empty()) {
            std::error_code ec;
            if (!fs::is_regular_file(p.imagePath, ec)) continue;
            FileVerdict v = engine->scanFile(p.imagePath);
            if (v.disposition != Disposition::Clean) {
                ++findings;
                std::cout << "        " << dispositionBadge(v.disposition) << " score "
                          << fmtDouble(v.score, 1) << "\n";
                printDetections(v, "        ");
            }
        }
    }
    return findings ? 3 : 0;
}

// ---------------------------------------------------------------------------
// monitor
// ---------------------------------------------------------------------------
int runMonitor(const Args& args) {
    if (!platform::isWindows()) {
        std::cerr << Style::yellow("real-time monitoring is only available on Windows\n");
        return 2;
    }
    if (args.positional.empty()) {
        std::cerr << "usage: shiranui monitor <directory> [directory...] [--quarantine]\n";
        return 2;
    }

    auto rules = loadRules(args);
    if (!rules) {
        std::cerr << Style::red("error: ") << rules.error() << "\n";
        return 2;
    }

    ScanOptions options;
    options.computeFuzzyHash = false;   // latency matters more than similarity here
    ScanEngine engine(*rules, options);

    std::unique_ptr<Quarantine> store;
    if (args.has("quarantine")) {
        store = std::make_unique<Quarantine>(Quarantine::defaultRoot());
        Status s = store->open();
        if (!s) {
            std::cerr << Style::red("error: ") << s.message << "\n";
            return 2;
        }
    }

    platform::FileWatcher watcher;
    for (const std::string& dir : args.positional) {
        Status s = watcher.addRoot(utf8ToPath(dir));
        if (!s) {
            std::cerr << Style::red("error: ") << s.message << "\n";
            return 2;
        }
        std::cout << Style::dim("watching ") << dir << "\n";
    }

    std::atomic<u64> examined{0}, flagged{0};
    Status started = watcher.start([&](const platform::FileEvent& ev) {
        if (ev.kind == platform::FileEvent::Kind::Deleted) return;
        std::error_code ec;
        if (!fs::is_regular_file(ev.path, ec)) return;

        // A file being written is often incomplete; a short settle delay avoids
        // scanning a half-flushed download and reporting nonsense.
        std::this_thread::sleep_for(std::chrono::milliseconds(120));

        FileVerdict v = engine.scanFile(ev.path);
        ++examined;
        if (v.disposition == Disposition::Clean) return;
        ++flagged;

        std::cout << Style::dim(isoTimestamp(ev.timestampMs)) << " " << dispositionBadge(v.disposition)
                  << " " << pathToUtf8(v.path) << "\n";
        printDetections(v, "      ");

        if (store && v.disposition == Disposition::Malicious) {
            auto rec = store->quarantineFile(v.path, v);
            if (rec) std::cout << "      " << Style::magenta("quarantined as " + rec->id) << "\n";
            else std::cout << "      " << Style::red("quarantine failed: " + rec.error()) << "\n";
        }
    });
    if (!started) {
        std::cerr << Style::red("error: ") << started.message << "\n";
        return 2;
    }

    platform::ProcessWatcher processes;
    if (args.has("processes")) {
        Status s = processes.start([&](const platform::ProcessEvent& ev) {
            if (ev.kind != platform::ProcessEvent::Kind::Started) return;
            if (ev.info.imagePath.empty()) return;
            FileVerdict v = engine.scanFile(ev.info.imagePath);
            if (v.disposition == Disposition::Clean) return;
            std::cout << Style::dim(isoTimestamp(ev.timestampMs)) << " "
                      << dispositionBadge(v.disposition) << " pid " << fmtU64(ev.info.pid) << " "
                      << pathToUtf8(ev.info.imagePath) << "\n";
            printDetections(v, "      ");
        });
        if (s) std::cout << Style::dim("watching process starts (" + processes.backend() + ")\n");
    }

    std::signal(SIGINT, onSignal);
    std::cout << Style::dim("press Ctrl-C to stop\n\n");
    while (!g_interrupted.load()) std::this_thread::sleep_for(std::chrono::milliseconds(200));

    watcher.stop();
    processes.stop();
    std::cout << "\n" << fmtU64(examined.load()) << " file(s) examined, " << fmtU64(flagged.load())
              << " flagged\n";
    return 0;
}

// ---------------------------------------------------------------------------
// quarantine
// ---------------------------------------------------------------------------
int runQuarantine(const Args& args) {
    std::string sub = args.positional.empty() ? "list" : args.positional.front();
    std::string dir = args.value("quarantine-dir");
    Quarantine  store(dir.empty() ? Quarantine::defaultRoot() : utf8ToPath(dir));

    Status opened = store.open();
    if (!opened) {
        std::cerr << Style::red("error: ") << opened.message << "\n";
        return 2;
    }

    if (sub == "list") {
        auto items = store.list();
        if (args.has("json")) {
            std::cout << "[";
            for (std::size_t i = 0; i < items.size(); ++i)
                std::cout << (i ? "," : "") << items[i].toJson();
            std::cout << "]\n";
            return 0;
        }
        if (items.empty()) {
            std::cout << Style::dim("quarantine is empty (" + pathToUtf8(store.root()) + ")\n");
            return 0;
        }
        std::cout << Style::bold("quarantined items") << Style::dim(" — " + pathToUtf8(store.root()))
                  << "\n\n";
        for (const auto& r : items) {
            std::cout << Style::bold(r.id) << "  "
                      << severityColor(r.severity, severityName(r.severity)) << "  "
                      << Style::dim(isoTimestamp(r.quarantinedAtMs)) << "\n";
            std::cout << "    " << pathToUtf8(r.originalPath) << "\n";
            std::cout << "    " << Style::dim(r.detectionName + "  " + humanSize(r.originalSize))
                      << "\n";
        }
        return 0;
    }

    if (sub == "restore") {
        if (args.positional.size() < 2) {
            std::cerr << "usage: shiranui quarantine restore <id> [--dest PATH]\n";
            return 2;
        }
        std::string dest = args.value("dest");
        Status s = store.restore(args.positional[1], dest.empty() ? fs::path{} : utf8ToPath(dest));
        if (!s) {
            std::cerr << Style::red("error: ") << s.message << "\n";
            return 1;
        }
        std::cout << Style::green("restored ") << args.positional[1] << "\n";
        return 0;
    }

    if (sub == "purge") {
        if (args.positional.size() < 2) {
            std::cerr << "usage: shiranui quarantine purge <id>\n";
            return 2;
        }
        Status s = store.purge(args.positional[1]);
        if (!s) {
            std::cerr << Style::red("error: ") << s.message << "\n";
            return 1;
        }
        std::cout << Style::green("purged ") << args.positional[1] << "\n";
        return 0;
    }

    if (sub == "purge-all") {
        if (!args.has("yes")) {
            std::cerr << "this permanently destroys every quarantined file; re-run with --yes\n";
            return 2;
        }
        Status s = store.purgeAll();
        if (!s) {
            std::cerr << Style::red("error: ") << s.message << "\n";
            return 1;
        }
        std::cout << Style::green("quarantine emptied\n");
        return 0;
    }

    std::cerr << "unknown quarantine subcommand: " << sub << "\n";
    return 2;
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------
int runRules(const Args& args) {
    auto rules = loadRules(args);
    if (!rules) {
        std::cerr << Style::red("error: ") << rules.error() << "\n";
        return 2;
    }
    std::cout << Style::bold("loaded ") << fmtU64(rules->ruleCount()) << " rules, "
              << fmtU64(rules->hashCount()) << " hashes, " << fmtU64(rules->patternCount())
              << " compiled patterns\n\n";
    for (const sig::Rule& r : rules->rules()) {
        std::cout << severityColor(r.severity, severityName(r.severity)) << "  "
                  << Style::bold(r.name);
        if (!r.family.empty()) std::cout << Style::dim("  [" + r.family + "]");
        std::cout << "\n";
        if (!r.description.empty()) std::cout << "    " << Style::dim(r.description) << "\n";
        if (args.has("verbose")) {
            std::cout << "    " << Style::dim(r.sourceFile + ":" + fmtU64(r.sourceLine)) << "\n";
            for (const sig::StringDef& s : r.strings)
                std::cout << "      " << s.id << " " << Style::dim(s.preview) << "\n";
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// service
// ---------------------------------------------------------------------------
int runService(const Args& args) {
    if (!platform::isWindows()) {
        std::cerr << Style::yellow("service management is only available on Windows\n");
        return 2;
    }
    std::string sub = args.positional.empty() ? "status" : args.positional.front();

    if (sub == "status") {
        std::string state;
        Status      s = platform::service::queryState(state);
        if (!s) {
            std::cerr << Style::red("error: ") << s.message << "\n";
            return 2;
        }
        std::cout << platform::service::kServiceName << ": " << state << "\n";
        return 0;
    }
    if (sub == "install") {
        fs::path    exe  = executableDirectory() / "shiranui.exe";
        std::string tail = "service run";
        for (const std::string& dir : args.values("watch")) tail += " --watch " + dir;
        Status s = platform::service::install(exe, tail);
        if (!s) {
            std::cerr << Style::red("error: ") << s.message << "\n";
            return 1;
        }
        std::cout << Style::green("service installed\n");
        return 0;
    }
    if (sub == "uninstall") {
        Status s = platform::service::uninstall();
        if (!s) {
            std::cerr << Style::red("error: ") << s.message << "\n";
            return 1;
        }
        std::cout << Style::green("service removed\n");
        return 0;
    }
    if (sub == "run") {
        auto rules = loadRules(args);
        if (!rules) return 2;
        ScanOptions options;
        options.computeFuzzyHash = false;
        auto engine = std::make_shared<ScanEngine>(*rules, options);
        auto keep   = std::make_shared<sig::RuleSet>(std::move(*rules));

        Status s = platform::service::runDispatcher([&](const std::function<bool()>& stopRequested) {
            platform::FileWatcher watcher;
            for (const std::string& dir : args.values("watch")) watcher.addRoot(utf8ToPath(dir));
            watcher.start([&](const platform::FileEvent& ev) {
                std::error_code ec;
                if (!fs::is_regular_file(ev.path, ec)) return;
                FileVerdict v = engine->scanFile(ev.path);
                if (v.disposition == Disposition::Malicious)
                    logWarn("malicious file detected: " + pathToUtf8(v.path) + " (" +
                            (v.detections.empty() ? "" : v.detections.front().name) + ")");
            });
            while (!stopRequested()) std::this_thread::sleep_for(std::chrono::milliseconds(250));
            watcher.stop();
        });
        if (!s) {
            std::cerr << Style::red("error: ") << s.message << "\n";
            return 1;
        }
        return 0;
    }

    std::cerr << "unknown service subcommand: " << sub << "\n";
    return 2;
}

}  // namespace shiranui::cli

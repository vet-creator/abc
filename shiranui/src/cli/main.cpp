// SPDX-License-Identifier: MIT
#include <cstdio>
#include <iostream>

#include "cli.hpp"
#include "shiranui/platform.hpp"
#include "shiranui/quarantine.hpp"

#ifndef _WIN32
#  include <unistd.h>
#endif

#ifndef SHIRANUI_VERSION
#  define SHIRANUI_VERSION "0.1.0"
#endif
#ifndef SHIRANUI_COMMIT
#  define SHIRANUI_COMMIT "unknown"
#endif

namespace shiranui::cli {

void printUsage() {
    std::cout << Style::bold("SHIRANUI") << Style::dim(" 不知火 — endpoint threat detection engine")
              << "\n\n";
    std::cout <<
        "usage: shiranui <command> [options]\n"
        "\n"
        "commands\n"
        "  scan <path>...            Scan files or directory trees\n"
        "  inspect <file>            Detailed static analysis of one file\n"
        "  monitor <dir>...          Watch directories and scan changes as they happen\n"
        "  audit                     Report the machine's security posture (read-only)\n"
        "  autoruns                  Enumerate persistence points\n"
        "  ps                        List running processes\n"
        "  quarantine <sub>          list | restore <id> | purge <id> | purge-all\n"
        "  rules                     Show the loaded rule set\n"
        "  service <sub>             status | install | uninstall | run\n"
        "  version                   Print version information\n"
        "\n"
        "common options\n"
        "  --rules DIR               Rule directory (default: rules/ next to the binary)\n"
        "  --json                    Machine-readable output\n"
        "  --no-color                Disable ANSI colour\n"
        "  --verbose                 Include additional detail\n"
        "\n"
        "scan options\n"
        "  --threads N               Worker threads (default: hardware concurrency)\n"
        "  --all                     Report clean files too\n"
        "  --quarantine              Move malicious files into the encrypted store\n"
        "  --exclude GLOB            Skip matching paths (repeatable)\n"
        "  --ext .exe                Restrict to these extensions (repeatable)\n"
        "  --max-size MB             Skip content analysis above this size\n"
        "  --no-fuzzy                Skip fuzzy-hash computation\n"
        "  --no-signature-check      Skip Authenticode verification\n"
        "  --follow-symlinks         Descend into reparse points (off by default)\n"
        "\n"
        "monitor options\n"
        "  --processes               Also scan the image of every process that starts\n"
        "  --quarantine              Quarantine malicious files automatically\n"
        "\n"
        "exit status\n"
        "  0 nothing found   1 malicious   2 usage or setup error   3 suspicious only\n";
}

}  // namespace shiranui::cli

int main(int argc, char** argv) {
    using namespace shiranui;

    platform::hardenCurrentProcess();

    cli::Args args = cli::Args::parse(argc, argv);

    bool color = !args.has("no-color");
#ifdef _WIN32
    if (color) color = platform::enableVirtualTerminal();
#else
    if (color && !::isatty(1)) color = false;
#endif
    cli::Style::enable(color);

    if (args.command.empty() || args.command == "help" || args.has("help") || args.has("h")) {
        cli::printUsage();
        return args.command.empty() ? 2 : 0;
    }

    if (args.command == "version") {
        std::cout << "shiranui " << SHIRANUI_VERSION << " (" << SHIRANUI_COMMIT << ")\n";
        std::cout << "  platform            " << (platform::isWindows() ? "windows" : "portable build")
                  << "\n";
        std::cout << "  authenticode        "
                  << (platform::authenticodeSupported() ? "available" : "unavailable") << "\n";
        std::cout << "  elevated            " << (platform::isElevated() ? "yes" : "no") << "\n";
        std::cout << "  quarantine store    " << pathToUtf8(Quarantine::defaultRoot()) << "\n";
        return 0;
    }

    try {
        if (args.command == "scan")       return cli::runScan(args);
        if (args.command == "inspect")    return cli::runInspect(args);
        if (args.command == "audit")      return cli::runAudit(args);
        if (args.command == "autoruns")   return cli::runAutoruns(args);
        if (args.command == "ps")         return cli::runProcesses(args);
        if (args.command == "monitor")    return cli::runMonitor(args);
        if (args.command == "quarantine") return cli::runQuarantine(args);
        if (args.command == "rules")      return cli::runRules(args);
        if (args.command == "service")    return cli::runService(args);
    } catch (const std::exception& e) {
        std::cerr << cli::Style::red("fatal: ") << e.what() << "\n";
        return 2;
    }

    std::cerr << "unknown command: " << args.command << "\n\n";
    cli::printUsage();
    return 2;
}

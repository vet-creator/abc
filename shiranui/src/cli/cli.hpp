// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <vector>

#include "shiranui/common.hpp"

namespace shiranui::cli {

/// ANSI styling that silently becomes a no-op when colour is disabled or the
/// output is redirected.
class Style {
public:
    static void enable(bool on);
    static bool enabled();

    static std::string dim(std::string_view s);
    static std::string bold(std::string_view s);
    static std::string red(std::string_view s);
    static std::string yellow(std::string_view s);
    static std::string green(std::string_view s);
    static std::string cyan(std::string_view s);
    static std::string magenta(std::string_view s);
};

struct Args {
    std::string              command;
    std::vector<std::string> positional;

    [[nodiscard]] bool        has(std::string_view flag) const;
    [[nodiscard]] std::string value(std::string_view flag, std::string fallback = {}) const;
    [[nodiscard]] u64         number(std::string_view flag, u64 fallback) const;
    [[nodiscard]] std::vector<std::string> values(std::string_view flag) const;

    static Args parse(int argc, char** argv);

    std::vector<std::pair<std::string, std::string>> flags;
};

/// Directory containing the running executable, used to locate bundled rules.
fs::path executableDirectory();

int runScan(const Args& args);
int runInspect(const Args& args);
int runAudit(const Args& args);
int runAutoruns(const Args& args);
int runProcesses(const Args& args);
int runMonitor(const Args& args);
int runQuarantine(const Args& args);
int runRules(const Args& args);
int runService(const Args& args);

void printUsage();

}  // namespace shiranui::cli

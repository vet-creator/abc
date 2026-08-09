// SPDX-License-Identifier: MIT
#include "cli.hpp"

#include <cstdlib>
#include <iostream>

#ifdef _WIN32
#  include "shiranui/win/winutil.hpp"
#else
#  include <unistd.h>
#endif

namespace shiranui::cli {

namespace {
bool g_color = false;

std::string wrap(std::string_view code, std::string_view s) {
    if (!g_color) return std::string(s);
    return std::string("\x1b[").append(code).append("m").append(s).append("\x1b[0m");
}
}  // namespace

void Style::enable(bool on) { g_color = on; }
bool Style::enabled() { return g_color; }

std::string Style::dim(std::string_view s) { return wrap("2", s); }
std::string Style::bold(std::string_view s) { return wrap("1", s); }
std::string Style::red(std::string_view s) { return wrap("31;1", s); }
std::string Style::yellow(std::string_view s) { return wrap("33;1", s); }
std::string Style::green(std::string_view s) { return wrap("32;1", s); }
std::string Style::cyan(std::string_view s) { return wrap("36", s); }
std::string Style::magenta(std::string_view s) { return wrap("35;1", s); }

bool Args::has(std::string_view flag) const {
    for (const auto& [k, v] : flags)
        if (k == flag) return true;
    return false;
}

std::string Args::value(std::string_view flag, std::string fallback) const {
    for (const auto& [k, v] : flags)
        if (k == flag && !v.empty()) return v;
    return fallback;
}

u64 Args::number(std::string_view flag, u64 fallback) const {
    std::string v = value(flag);
    if (v.empty()) return fallback;
    char* end = nullptr;
    u64   out = std::strtoull(v.c_str(), &end, 10);
    if (end == v.c_str()) return fallback;
    return out;
}

std::vector<std::string> Args::values(std::string_view flag) const {
    std::vector<std::string> out;
    for (const auto& [k, v] : flags)
        if (k == flag && !v.empty()) out.push_back(v);
    return out;
}

Args Args::parse(int argc, char** argv) {
    Args args;
    int  i = 1;
    if (i < argc && argv[i][0] != '-') args.command = argv[i++];

    for (; i < argc; ++i) {
        std::string token = argv[i];
        if (startsWith(token, "--")) {
            std::string key = token.substr(2);
            std::string val;
            std::size_t eq = key.find('=');
            if (eq != std::string::npos) {
                val = key.substr(eq + 1);
                key = key.substr(0, eq);
            } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                // Only consume the next token as a value for flags that take one;
                // otherwise `scan --json C:\dir` would swallow the path.
                static const char* kValueFlags[] = {"rules",   "threads", "max-size", "exclude",
                                                    "ext",     "output",  "log",      "dest",
                                                    "quarantine-dir", "min-severity"};
                for (const char* f : kValueFlags)
                    if (key == f) {
                        val = argv[++i];
                        break;
                    }
            }
            args.flags.emplace_back(std::move(key), std::move(val));
        } else if (startsWith(token, "-") && token.size() > 1) {
            args.flags.emplace_back(token.substr(1), std::string{});
        } else {
            args.positional.push_back(std::move(token));
        }
    }
    return args;
}

fs::path executableDirectory() {
#ifdef _WIN32
    wchar_t buffer[MAX_PATH * 2];
    DWORD   len = ::GetModuleFileNameW(nullptr, buffer, static_cast<DWORD>(std::size(buffer)));
    if (len > 0 && len < std::size(buffer)) return fs::path(std::wstring(buffer, len)).parent_path();
    return fs::current_path();
#else
    std::error_code ec;
    fs::path        self = fs::read_symlink("/proc/self/exe", ec);
    if (!ec) return self.parent_path();
    return fs::current_path();
#endif
}

}  // namespace shiranui::cli

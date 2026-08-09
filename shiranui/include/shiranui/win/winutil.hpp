// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>

// Present since the Windows 10 SDK, but some older or minimal SDKs omit it.
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#  define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#include <string>
#include <utility>
#include <vector>

#include "shiranui/common.hpp"
#include "shiranui/platform.hpp"

namespace shiranui::platform {

/// Thin, exception-free registry accessors. `viewFlag` selects the 32/64-bit
/// registry view (KEY_WOW64_64KEY by default) — malware frequently hides in the
/// view the reader is not looking at, so both are queried by callers.
namespace reg {

bool readString(HKEY root, const wchar_t* subKey, const wchar_t* value, std::string& out,
                DWORD viewFlag = KEY_WOW64_64KEY);
bool readDword(HKEY root, const wchar_t* subKey, const wchar_t* value, DWORD& out,
               DWORD viewFlag = KEY_WOW64_64KEY);
bool keyExists(HKEY root, const wchar_t* subKey, DWORD viewFlag = KEY_WOW64_64KEY);

std::vector<std::pair<std::string, std::string>> enumStringValues(HKEY root, const wchar_t* subKey,
                                                                  DWORD viewFlag = KEY_WOW64_64KEY);
std::vector<std::string> enumSubKeys(HKEY root, const wchar_t* subKey,
                                     DWORD viewFlag = KEY_WOW64_64KEY);
std::string expandEnvironment(const std::string& s);

}  // namespace reg

/// Best-effort extraction of the executable from a raw command line.
fs::path extractImagePath(const std::string& commandLine);

}  // namespace shiranui::platform

#endif  // _WIN32

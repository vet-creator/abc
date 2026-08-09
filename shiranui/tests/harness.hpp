// SPDX-License-Identifier: MIT
// Minimal assertion harness. No external dependency: a security tool's test
// suite should build with nothing but a compiler, on every CI runner.
#pragma once

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "shiranui/common.hpp"

namespace shiranui::test {

struct Registry {
    struct Case {
        std::string           name;
        std::function<void()> body;
    };
    std::vector<Case> cases;
    std::size_t       checks = 0;
    std::size_t       failures = 0;
    std::string       currentCase;

    static Registry& instance() {
        static Registry r;
        return r;
    }
};

struct Registrar {
    Registrar(const char* name, std::function<void()> body) {
        Registry::instance().cases.push_back({name, std::move(body)});
    }
};

inline void reportFailure(const char* file, int line, const std::string& message) {
    Registry& r = Registry::instance();
    ++r.failures;
    std::printf("\n  FAIL %s\n       %s:%d\n       %s\n", r.currentCase.c_str(), file, line,
                message.c_str());
}

inline void recordCheck() { ++Registry::instance().checks; }

int runAll();

}  // namespace shiranui::test

#define SHIRANUI_CONCAT_(a, b) a##b
#define SHIRANUI_CONCAT(a, b) SHIRANUI_CONCAT_(a, b)

#define TEST(name)                                                                    \
    static void SHIRANUI_CONCAT(shiranui_test_, __LINE__)();                          \
    static ::shiranui::test::Registrar SHIRANUI_CONCAT(shiranui_reg_, __LINE__)(      \
        name, &SHIRANUI_CONCAT(shiranui_test_, __LINE__));                            \
    static void SHIRANUI_CONCAT(shiranui_test_, __LINE__)()

#define CHECK(expr)                                                                   \
    do {                                                                              \
        ::shiranui::test::recordCheck();                                              \
        if (!(expr)) ::shiranui::test::reportFailure(__FILE__, __LINE__, #expr);      \
    } while (0)

#define CHECK_EQ(a, b)                                                                \
    do {                                                                              \
        ::shiranui::test::recordCheck();                                              \
        auto&& lhs_ = (a);                                                            \
        auto&& rhs_ = (b);                                                            \
        if (!(lhs_ == rhs_))                                                          \
            ::shiranui::test::reportFailure(                                          \
                __FILE__, __LINE__,                                                   \
                std::string(#a " == " #b) + "\n         left  = " +                   \
                    ::shiranui::test::show(lhs_) + "\n         right = " +            \
                    ::shiranui::test::show(rhs_));                                    \
    } while (0)

#define CHECK_NEAR(a, b, tol)                                                         \
    do {                                                                              \
        ::shiranui::test::recordCheck();                                              \
        double diff_ = double(a) - double(b);                                         \
        if (diff_ < 0) diff_ = -diff_;                                                \
        if (diff_ > (tol))                                                            \
            ::shiranui::test::reportFailure(__FILE__, __LINE__,                       \
                                            std::string(#a " ~= " #b) + " (delta " +  \
                                                ::shiranui::fmtDouble(diff_, 6) + ")"); \
    } while (0)

namespace shiranui::test {
inline std::string show(const std::string& s) { return "\"" + s + "\""; }
inline std::string show(const char* s) { return std::string("\"") + s + "\""; }
inline std::string show(bool b) { return b ? "true" : "false"; }
inline std::string show(double d) { return fmtDouble(d, 6); }
template <class T>
inline std::string show(const T& v) {
    if constexpr (std::is_integral_v<T>) return fmtI64(static_cast<i64>(v));
    else return "<value>";
}
}  // namespace shiranui::test

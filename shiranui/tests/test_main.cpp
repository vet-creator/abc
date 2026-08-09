// SPDX-License-Identifier: MIT
#include "harness.hpp"

#include <chrono>

namespace shiranui::test {

int runAll() {
    Registry& r       = Registry::instance();
    auto      started = std::chrono::steady_clock::now();

    std::printf("running %zu test case(s)\n", r.cases.size());
    for (const Registry::Case& c : r.cases) {
        r.currentCase        = c.name;
        std::size_t before   = r.failures;
        try {
            c.body();
        } catch (const std::exception& e) {
            reportFailure(__FILE__, __LINE__, c.name + " threw: " + e.what());
        }
        std::printf(r.failures == before ? "." : "!");
        std::fflush(stdout);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - started)
                       .count();
    std::printf("\n\n%zu checks in %lld ms, %zu failure(s)\n", r.checks,
                static_cast<long long>(elapsed), r.failures);
    return r.failures == 0 ? 0 : 1;
}

}  // namespace shiranui::test

int main() { return shiranui::test::runAll(); }

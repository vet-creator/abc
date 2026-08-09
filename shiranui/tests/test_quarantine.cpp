// SPDX-License-Identifier: MIT
#include "harness.hpp"

#include <fstream>
#include <random>

#include "shiranui/crypto.hpp"
#include "shiranui/quarantine.hpp"

using namespace shiranui;

namespace {

fs::path makeTempDir(const char* tag) {
    std::mt19937_64 rng(std::random_device{}());
    fs::path        dir = fs::temp_directory_path() /
                   ("shiranui_" + std::string(tag) + "_" + fmtHex(rng(), 16));
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

void writeFile(const fs::path& p, std::string_view content) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string readFile(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

}  // namespace

TEST("quarantine round-trip restores byte-identical content") {
    fs::path root    = makeTempDir("qroot");
    fs::path workDir = makeTempDir("qwork");
    auto     cleanup = makeGuard([&] {
        std::error_code ec;
        fs::remove_all(root, ec);
        fs::remove_all(workDir, ec);
    });

    Quarantine store(root);
    CHECK(store.open().ok);

    fs::path    victim  = workDir / "payload.bin";
    std::string content = "malicious content \x00 with embedded nulls and \xff high bytes";
    content.append(5000, 'Z');
    writeFile(victim, content);

    FileVerdict verdict;
    verdict.path   = victim;
    verdict.size   = content.size();
    verdict.sha256 = crypto::Sha256::hex(
        ByteView(reinterpret_cast<const u8*>(content.data()), content.size()));
    verdict.detections.push_back(
        {"signature", "Test_Rule", "desc", Severity::Critical, 100.0, 0, {}});

    auto record = store.quarantineFile(victim, verdict);
    CHECK(record.ok());
    if (!record) return;

    // The original must be gone and the container must exist.
    std::error_code ec;
    CHECK(!fs::exists(victim, ec));
    CHECK(fs::exists(record->containerPath, ec));

    // The container must not contain the plaintext anywhere.
    std::string container = readFile(record->containerPath);
    CHECK(container.find("malicious content") == std::string::npos);
    CHECK(container.find(std::string(500, 'Z')) == std::string::npos);

    auto listed = store.list();
    CHECK_EQ(listed.size(), std::size_t(1));

    CHECK(store.restore(record->id).ok);
    CHECK(fs::exists(victim, ec));
    CHECK_EQ(readFile(victim), content);
    CHECK_EQ(store.list().size(), std::size_t(0));
}

TEST("quarantine refuses a container whose header was edited") {
    fs::path root    = makeTempDir("qtamper");
    fs::path workDir = makeTempDir("qtwork");
    auto     cleanup = makeGuard([&] {
        std::error_code ec;
        fs::remove_all(root, ec);
        fs::remove_all(workDir, ec);
    });

    Quarantine store(root);
    CHECK(store.open().ok);

    fs::path victim = workDir / "sample.bin";
    writeFile(victim, "content to protect");

    FileVerdict verdict;
    auto        record = store.quarantineFile(victim, verdict);
    CHECK(record.ok());
    if (!record) return;

    // Flip one byte inside the authenticated header region (offset 8 onwards is
    // the JSON that records where this file came from).
    std::string blob = readFile(record->containerPath);
    CHECK(blob.size() > 40);
    blob[20] = static_cast<char>(blob[20] ^ 0x01);
    writeFile(record->containerPath, blob);

    Status restored = store.restore(record->id);
    CHECK(!restored.ok);
    CHECK(restored.message.find("authentication") != std::string::npos);

    std::error_code ec;
    CHECK(!fs::exists(victim, ec));   // nothing was written on a failed restore
}

TEST("quarantine refuses a container whose ciphertext was edited") {
    fs::path root    = makeTempDir("qct");
    fs::path workDir = makeTempDir("qctwork");
    auto     cleanup = makeGuard([&] {
        std::error_code ec;
        fs::remove_all(root, ec);
        fs::remove_all(workDir, ec);
    });

    Quarantine store(root);
    CHECK(store.open().ok);

    fs::path victim = workDir / "sample2.bin";
    writeFile(victim, std::string(2000, 'Q'));

    FileVerdict verdict;
    auto        record = store.quarantineFile(victim, verdict);
    CHECK(record.ok());
    if (!record) return;

    std::string blob = readFile(record->containerPath);
    blob[blob.size() - 10] = static_cast<char>(blob[blob.size() - 10] ^ 0xFF);
    writeFile(record->containerPath, blob);

    CHECK(!store.restore(record->id).ok);
}

TEST("quarantine will not overwrite an existing file on restore") {
    fs::path root    = makeTempDir("qover");
    fs::path workDir = makeTempDir("qoverwork");
    auto     cleanup = makeGuard([&] {
        std::error_code ec;
        fs::remove_all(root, ec);
        fs::remove_all(workDir, ec);
    });

    Quarantine store(root);
    CHECK(store.open().ok);

    fs::path victim = workDir / "collide.bin";
    writeFile(victim, "original");

    FileVerdict verdict;
    auto        record = store.quarantineFile(victim, verdict);
    CHECK(record.ok());
    if (!record) return;

    writeFile(victim, "something else now lives here");
    Status restored = store.restore(record->id);
    CHECK(!restored.ok);
    CHECK_EQ(readFile(victim), std::string("something else now lives here"));
}

TEST("each quarantine item uses a distinct derived key") {
    fs::path root    = makeTempDir("qkeys");
    fs::path workDir = makeTempDir("qkeyswork");
    auto     cleanup = makeGuard([&] {
        std::error_code ec;
        fs::remove_all(root, ec);
        fs::remove_all(workDir, ec);
    });

    Quarantine store(root);
    CHECK(store.open().ok);

    std::string identical(4096, 'K');
    fs::path    a = workDir / "a.bin";
    fs::path    b = workDir / "b.bin";
    writeFile(a, identical);
    writeFile(b, identical);

    FileVerdict verdict;
    auto        ra = store.quarantineFile(a, verdict);
    auto        rb = store.quarantineFile(b, verdict);
    CHECK(ra.ok());
    CHECK(rb.ok());
    if (!ra || !rb) return;

    CHECK(ra->id != rb->id);
    // Same plaintext, different per-item key and nonce: the ciphertexts must
    // differ, otherwise identical files would be linkable inside the store.
    std::string ca = readFile(ra->containerPath);
    std::string cb = readFile(rb->containerPath);
    CHECK(ca.substr(ca.size() - 1024) != cb.substr(cb.size() - 1024));
}

TEST("purge removes an item permanently") {
    fs::path root    = makeTempDir("qpurge");
    fs::path workDir = makeTempDir("qpurgework");
    auto     cleanup = makeGuard([&] {
        std::error_code ec;
        fs::remove_all(root, ec);
        fs::remove_all(workDir, ec);
    });

    Quarantine store(root);
    CHECK(store.open().ok);

    fs::path victim = workDir / "gone.bin";
    writeFile(victim, "to be destroyed");

    FileVerdict verdict;
    auto        record = store.quarantineFile(victim, verdict);
    CHECK(record.ok());
    if (!record) return;

    CHECK(store.purge(record->id).ok);
    std::error_code ec;
    CHECK(!fs::exists(record->containerPath, ec));
    CHECK_EQ(store.list().size(), std::size_t(0));
    CHECK(!store.purge(record->id).ok);   // second purge reports the missing id
}

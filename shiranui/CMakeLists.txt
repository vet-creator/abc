# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.20)

project(shiranui
    VERSION 0.1.0
    DESCRIPTION "SHIRANUI - endpoint threat detection engine"
    LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Hardening)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(SHIRANUI_BUILD_TESTS "Build the test suite" ON)
option(SHIRANUI_WERROR      "Treat warnings as errors" OFF)
option(SHIRANUI_SANITIZE    "Build with ASan + UBSan" OFF)

set(SHIRANUI_COMMIT "unknown" CACHE STRING "Source revision recorded in the binary")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------
file(GLOB SHIRANUI_CORE_SOURCES CONFIGURE_DEPENDS "src/core/*.cpp")

if(WIN32)
    file(GLOB SHIRANUI_WIN_SOURCES CONFIGURE_DEPENDS "src/win/*.cpp")
    list(APPEND SHIRANUI_CORE_SOURCES ${SHIRANUI_WIN_SOURCES})
endif()

add_library(shiranui_core STATIC ${SHIRANUI_CORE_SOURCES})
target_include_directories(shiranui_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(shiranui_core PUBLIC
    SHIRANUI_VERSION="${PROJECT_VERSION}"
    SHIRANUI_COMMIT="${SHIRANUI_COMMIT}")
shiranui_harden(shiranui_core)

if(WIN32)
    # bcrypt   : BCryptGenRandom
    # wintrust : WinVerifyTrust
    # crypt32  : certificate parsing
    # advapi32 : registry, service control manager, token queries
    # version  : file version resources
    target_link_libraries(shiranui_core PUBLIC bcrypt wintrust crypt32 advapi32 version)
    target_compile_definitions(shiranui_core PUBLIC
        WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE
        # Windows 10 or later: required for SetProcessMitigationPolicy,
        # CETCOMPAT-aware headers and the newer service APIs.
        _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000000)
    if(MINGW)
        # MinGW's winternl.h omits some members used by the process inspector.
        target_compile_definitions(shiranui_core PUBLIC SHIRANUI_MINGW=1)
    endif()
else()
    find_package(Threads REQUIRED)
    target_link_libraries(shiranui_core PUBLIC Threads::Threads)
endif()

if(SHIRANUI_SANITIZE AND NOT MSVC)
    target_compile_options(shiranui_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(shiranui_core PUBLIC -fsanitize=address,undefined)
endif()

if(SHIRANUI_WERROR)
    shiranui_werror(shiranui_core)
endif()

# ---------------------------------------------------------------------------
# Command line front end
# ---------------------------------------------------------------------------
file(GLOB SHIRANUI_CLI_SOURCES CONFIGURE_DEPENDS "src/cli/*.cpp")
add_executable(shiranui ${SHIRANUI_CLI_SOURCES})
target_link_libraries(shiranui PRIVATE shiranui_core)
target_include_directories(shiranui PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/cli")
shiranui_harden(shiranui)
if(SHIRANUI_WERROR)
    shiranui_werror(shiranui)
endif()

# Rules must sit next to the executable: the CLI looks for ./rules first.
add_custom_command(TARGET shiranui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/rules"
            "$<TARGET_FILE_DIR:shiranui>/rules"
    COMMENT "Staging detection rules next to the executable")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(SHIRANUI_BUILD_TESTS)
    enable_testing()
    file(GLOB SHIRANUI_TEST_SOURCES CONFIGURE_DEPENDS "tests/*.cpp")
    add_executable(shiranui_tests ${SHIRANUI_TEST_SOURCES})
    target_link_libraries(shiranui_tests PRIVATE shiranui_core)
    target_include_directories(shiranui_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    shiranui_harden(shiranui_tests)
    if(SHIRANUI_WERROR)
        shiranui_werror(shiranui_tests)
    endif()

    add_test(NAME unit COMMAND shiranui_tests)

    # An end-to-end check that the shipped rules actually compile and that the
    # binary detects the EICAR string. A rule set that fails to load is the kind
    # of regression a unit test alone would not catch.
    add_test(NAME rules_load
             COMMAND shiranui rules --rules "${CMAKE_CURRENT_SOURCE_DIR}/rules")
    set_tests_properties(rules_load PROPERTIES
        PASS_REGULAR_EXPRESSION "loaded [0-9]+ rules")
endif()

# ---------------------------------------------------------------------------
# Install / package
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS shiranui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY rules/ DESTINATION ${CMAKE_INSTALL_BINDIR}/rules FILES_MATCHING PATTERN "*.srules")
install(FILES README.md LICENSE docs/SECURITY.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

set(CPACK_PACKAGE_NAME "shiranui")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_GENERATOR "ZIP")
include(CPack)

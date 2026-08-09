# SPDX-License-Identifier: MIT
#
# Exploit-mitigation and warning settings.
#
# A security product is a high-value target: it runs early, often elevated, and
# parses hostile input by design. Every mitigation the toolchain offers is worth
# more here than the handful of cycles it costs.

function(shiranui_harden target)
    if(MSVC)
        target_compile_options(${target} PRIVATE
            /W4                 # high warning level
            /permissive-        # standard conformance
            /utf-8              # source and execution charset
            /EHsc
            /GS                 # stack buffer security checks
            /guard:cf           # Control Flow Guard
            /Zc:__cplusplus
            /Zc:inline
            /sdl                # additional security checks
            /wd4324             # structure padded due to alignas: intentional
        )
        target_link_options(${target} PRIVATE
            /DYNAMICBASE        # ASLR
            /NXCOMPAT           # DEP
            /guard:cf
            /CETCOMPAT          # shadow-stack compatible
        )
        # High-entropy ASLR only applies to 64-bit images.
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_link_options(${target} PRIVATE /HIGHENTROPYVA)
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic
            -Wcast-qual -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual
            -Wformat=2 -Wundef
            -fstack-protector-strong
        )
        if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
            target_compile_definitions(${target} PRIVATE _FORTIFY_SOURCE=2)
        endif()
        if(NOT APPLE AND NOT WIN32)
            target_link_options(${target} PRIVATE -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
        endif()
    endif()
endfunction()

# Treating warnings as errors is opt-in: it belongs in CI, not in the hands of
# someone trying a slightly different compiler version for the first time.
function(shiranui_werror target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /WX)
    else()
        target_compile_options(${target} PRIVATE -Werror)
    endif()
endfunction()

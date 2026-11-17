# libyara (https://github.com/VirusTotal/yara, BSD-3-Clause), pinned to a release tarball by SHA-256.
# libyara has no CMake build of its own; this file builds the static library from its sources with
# the flags its autotools build would use on Linux, minus process scanning and most modules.
#
# Offline builds: pass -DFETCHCONTENT_SOURCE_DIR_LIBYARA=/path/to/yara-4.5.8 to skip the download, after running
# cmake -P cmake/patch-libyara.cmake in that directory (PATCH_COMMAND does not run for a local source dir).
# Upgrading: change the version and the hash together (sha256sum of the release tarball), then run
# the GoogleTest suite (./gradlew :core:scanner:connectedNativeTest).

include(FetchContent)

set(BLACKSHIELD_YARA_VERSION 4.5.8)
FetchContent_Declare(libyara
    URL https://github.com/VirusTotal/yara/archive/refs/tags/v${BLACKSHIELD_YARA_VERSION}.tar.gz
    URL_HASH SHA256=c322414975ff6f701149856613afdcd92a7e6939c284c798ae3c85618197efaa
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    # There is no CMakeLists.txt to add; only fetch the sources.
    SOURCE_SUBDIR not-a-cmake-project
    # Fixes for undefined behaviour found by the sanitizer builds (see the file).
    PATCH_COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_LIST_DIR}/patch-libyara.cmake
)
FetchContent_MakeAvailable(libyara)

set(BLACKSHIELD_YARA_DIR ${libyara_SOURCE_DIR}/libyara)

add_library(yara STATIC
    ${BLACKSHIELD_YARA_DIR}/ahocorasick.c
    ${BLACKSHIELD_YARA_DIR}/arena.c
    ${BLACKSHIELD_YARA_DIR}/atoms.c
    ${BLACKSHIELD_YARA_DIR}/base64.c
    ${BLACKSHIELD_YARA_DIR}/bitmask.c
    ${BLACKSHIELD_YARA_DIR}/compiler.c
    ${BLACKSHIELD_YARA_DIR}/endian.c
    ${BLACKSHIELD_YARA_DIR}/exec.c
    ${BLACKSHIELD_YARA_DIR}/exefiles.c
    ${BLACKSHIELD_YARA_DIR}/filemap.c
    ${BLACKSHIELD_YARA_DIR}/grammar.c
    ${BLACKSHIELD_YARA_DIR}/hash.c
    ${BLACKSHIELD_YARA_DIR}/hex_grammar.c
    ${BLACKSHIELD_YARA_DIR}/hex_lexer.c
    ${BLACKSHIELD_YARA_DIR}/lexer.c
    ${BLACKSHIELD_YARA_DIR}/libyara.c
    ${BLACKSHIELD_YARA_DIR}/mem.c
    ${BLACKSHIELD_YARA_DIR}/modules.c
    ${BLACKSHIELD_YARA_DIR}/notebook.c
    ${BLACKSHIELD_YARA_DIR}/object.c
    ${BLACKSHIELD_YARA_DIR}/parser.c
    ${BLACKSHIELD_YARA_DIR}/proc.c
    ${BLACKSHIELD_YARA_DIR}/proc/none.c
    ${BLACKSHIELD_YARA_DIR}/re.c
    ${BLACKSHIELD_YARA_DIR}/re_grammar.c
    ${BLACKSHIELD_YARA_DIR}/re_lexer.c
    ${BLACKSHIELD_YARA_DIR}/rules.c
    ${BLACKSHIELD_YARA_DIR}/scan.c
    ${BLACKSHIELD_YARA_DIR}/scanner.c
    ${BLACKSHIELD_YARA_DIR}/simple_str.c
    ${BLACKSHIELD_YARA_DIR}/sizedstr.c
    ${BLACKSHIELD_YARA_DIR}/stack.c
    ${BLACKSHIELD_YARA_DIR}/stopwatch.c
    ${BLACKSHIELD_YARA_DIR}/stream.c
    ${BLACKSHIELD_YARA_DIR}/strutils.c
    ${BLACKSHIELD_YARA_DIR}/threading.c
    ${BLACKSHIELD_YARA_DIR}/modules/dex/dex.c
    ${BLACKSHIELD_YARA_DIR}/modules/math/math.c
)
target_include_directories(yara
    # Our module list must be found before libyara's own (see yara-modules/modules/module_list).
    PRIVATE ${CMAKE_CURRENT_LIST_DIR}/yara-modules ${BLACKSHIELD_YARA_DIR}
    PUBLIC ${BLACKSHIELD_YARA_DIR}/include
)
target_compile_definitions(yara PRIVATE
    _GNU_SOURCE
    NDEBUG
    USE_NO_PROC          # no process-memory scanning
    BUCKETS_128=1
    CHECKSUM_1B=1
    # Present in bionic since API 21+.
    HAVE_STDBOOL_H=1
    HAVE_STRLCPY=1
    HAVE_STRLCAT=1
    HAVE_MEMMEM=1
    HAVE_CLOCK_GETTIME=1
)
target_compile_options(yara PRIVATE
    -O2                  # matching speed matters more than a few KiB
    -w                   # third-party code: its warnings are not ours to fix (ours stay -Werror)
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
)
target_link_libraries(yara PRIVATE m)

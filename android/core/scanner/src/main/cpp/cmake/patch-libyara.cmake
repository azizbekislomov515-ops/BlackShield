# Source fixes applied to the pinned libyara tarball (PATCH_COMMAND, run in the source directory).
# Each fix replaces exact text and fails the build if neither the old nor the patched text is there, so an
# upgrade cannot drop a fix silently. Running the script twice is harmless.
#
# 1. compiler.c, scanner.c: yr_object_destroy (void, takes YR_OBJECT*) is cast to int (*)(void*) and called
#    through that pointer when hash tables are destroyed. Calling a function through an incompatible pointer
#    type is undefined behaviour (UBSan -fsanitize=function reports it). A wrapper with the right type replaces
#    the cast.
# 2. modules/dex/dex.c, read_uleb128_bounded: `cur << 28` shifts an int (the byte, promoted) into the sign bit,
#    which is undefined behaviour for bytes >= 0x08 (found by the yara_scan_fuzzer target with UBSan). The shift
#    is done on uint32_t; converting back to int32_t keeps the value the code had on every compiler.
# 3. modules/dex/dex.c, map list: the 32-bit list size is read through a uint32_t* at an offset taken from the
#    file, so it can be misaligned (UB; can fault on 32-bit ARM). It is copied out with __builtin_memcpy instead (found by
#    the fuzzer with UBSan -fsanitize=alignment). The DEX structs are declared packed, so their reads are fine.

# Replaces every `old` with `new` in `file`. Already patched (only `new` present) is fine; neither is an error.
function(blackshield_patch file old new)
    file(READ "${file}" content)
    string(FIND "${content}" "${old}" found)
    if(found EQUAL -1)
        string(FIND "${content}" "${new}" done)
        if(done EQUAL -1)
            message(FATAL_ERROR "libyara patch: expected text not found in ${file}; re-check cmake/patch-libyara.cmake")
        endif()
        return()
    endif()
    string(REPLACE "${old}" "${new}" content "${content}")
    file(WRITE "${file}" "${content}")
endfunction()

set(wrapper "
/* BlackShield: called through YR_HASH_TABLE_FREE_VALUE_FUNC, so it must have exactly that type. */
static int blackshield_destroy_object_value(void* value)
{
  yr_object_destroy((YR_OBJECT*) value);
  return ERROR_SUCCESS;
}
")

foreach(source libyara/compiler.c libyara/scanner.c)
    file(READ "${source}" content)
    string(FIND "${content}" "blackshield_destroy_object_value(void* value)" defined)
    if(defined EQUAL -1)
        # The wrapper goes right after the last #include, before any function that uses it.
        string(REGEX MATCHALL "#include [<\"][^\n]+[>\"]\n" includes "${content}")
        list(GET includes -1 last_include)
        string(FIND "${content}" "${last_include}" at REVERSE)
        string(LENGTH "${last_include}" length)
        math(EXPR at "${at} + ${length}")
        string(SUBSTRING "${content}" 0 ${at} head)
        string(SUBSTRING "${content}" ${at} -1 tail)
        file(WRITE "${source}" "${head}${wrapper}${tail}")
    endif()
    blackshield_patch("${source}" "(YR_HASH_TABLE_FREE_VALUE_FUNC) yr_object_destroy)" "blackshield_destroy_object_value)")
endforeach()

blackshield_patch(libyara/modules/dex/dex.c
    "result |= cur << 28;"
    "result = (int32_t) ((uint32_t) result | ((uint32_t) cur << 28));")

blackshield_patch(libyara/modules/dex/dex.c
    "    uint32_t* map_list_size =
        (uint32_t*) (dex->data + yr_le32toh(dex_header->map_offset));"
    "    uint32_t map_list_size_value;
    __builtin_memcpy(&map_list_size_value, dex->data + yr_le32toh(dex_header->map_offset), sizeof(uint32_t));
    uint32_t* map_list_size = &map_list_size_value;")

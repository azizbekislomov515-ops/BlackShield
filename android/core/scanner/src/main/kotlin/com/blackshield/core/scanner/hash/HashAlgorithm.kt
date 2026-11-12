package com.blackshield.core.scanner.hash

/**
 * Digest algorithms supported by the native engine. [nativeId] must match
 * `blackshield::hash::HashAlgorithm` in hash/hasher.h.
 */
enum class HashAlgorithm(val nativeId: Int, val digestLength: Int) {
    /** Broken; only for matching legacy signature feeds. */
    MD5(nativeId = 0, digestLength = 16),

    /** Broken; only for matching legacy signature feeds. */
    SHA1(nativeId = 1, digestLength = 20),

    SHA256(nativeId = 2, digestLength = 32)
}

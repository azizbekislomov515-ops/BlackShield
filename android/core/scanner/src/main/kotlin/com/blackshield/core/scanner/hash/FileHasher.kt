package com.blackshield.core.scanner.hash

/** Hashes files by path. Implemented by [NativeHasher]; faked in tests. */
interface FileHasher {
    suspend fun hashFile(path: String, algorithm: HashAlgorithm): HashResult
}

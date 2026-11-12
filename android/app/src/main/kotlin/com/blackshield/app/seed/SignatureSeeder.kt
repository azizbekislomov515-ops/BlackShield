package com.blackshield.app.seed

import com.blackshield.core.data.repository.SignatureRepository
import java.time.Clock
import javax.inject.Inject
import timber.log.Timber

/**
 * Inserts the build type's built-in signatures ([BuildTypeSignatures]). Idempotent: signatures
 * are keyed by hash, so re-running replaces them. Release builds currently seed nothing; the
 * signature feed will populate the store.
 */
class SignatureSeeder
@Inject
constructor(private val signatures: SignatureRepository, private val clock: Clock) {
    suspend fun seed() {
        val seeds = BuildTypeSignatures.signatures(clock.millis())
        if (seeds.isEmpty()) return
        val result = signatures.insertAll(seeds.asSequence())
        Timber.i("Seeded %d signatures (%d rejected)", result.inserted, result.rejected)
    }
}

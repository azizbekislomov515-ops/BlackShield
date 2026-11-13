package com.blackshield.app.seed

import com.blackshield.core.data.repository.SignatureRepository
import java.time.Clock
import javax.inject.Inject
import timber.log.Timber

/**
 * Inserts the build type's built-in signatures ([BuildTypeSignatures]) that are not in the store
 * yet. Existing rows are left alone: if signature sync already delivered the same hash, that row
 * stays owned by sync (rewriting its source would make the synced count disagree with the server
 * and force a full snapshot on every sync). Release builds seed nothing.
 */
class SignatureSeeder
@Inject
constructor(private val signatures: SignatureRepository, private val clock: Clock) {
    suspend fun seed() {
        val seeds = BuildTypeSignatures.signatures(clock.millis())
        if (seeds.isEmpty()) return
        val present = signatures.findMatches(seeds.map { it.hash }).keys
        val missing = seeds.filterNot { it.hash.lowercase() in present }
        if (missing.isEmpty()) return
        val result = signatures.insertAll(missing.asSequence())
        Timber.i("Seeded %d signatures (%d rejected)", result.inserted, result.rejected)
    }
}

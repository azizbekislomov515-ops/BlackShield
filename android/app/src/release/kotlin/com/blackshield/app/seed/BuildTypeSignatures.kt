package com.blackshield.app.seed

import com.blackshield.core.data.model.MalwareSignature

/** Release builds ship no built-in signatures; the store is filled from signature feeds. */
internal object BuildTypeSignatures {
    @Suppress("UNUSED_PARAMETER")
    fun signatures(now: Long): List<MalwareSignature> = emptyList()
}

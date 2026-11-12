package com.blackshield.app.seed

import com.blackshield.core.data.model.MalwareSignature

/** Benchmark builds behave like release: no built-in signatures. */
internal object BuildTypeSignatures {
    @Suppress("UNUSED_PARAMETER")
    fun signatures(now: Long): List<MalwareSignature> = emptyList()
}

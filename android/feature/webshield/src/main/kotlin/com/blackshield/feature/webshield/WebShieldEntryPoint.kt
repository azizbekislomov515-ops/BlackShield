package com.blackshield.feature.webshield

import com.blackshield.core.data.repository.DomainSyncStore
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

/** Access for code Hilt cannot inject, such as instrumented tests running in the app process. */
@EntryPoint
@InstallIn(SingletonComponent::class)
interface WebShieldEntryPoint {
    fun webShieldController(): WebShieldController

    fun webShieldRuntime(): WebShieldRuntime

    fun blockedDomains(): DomainSyncStore
}

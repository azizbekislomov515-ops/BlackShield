package com.blackshield.core.data.repository

import com.blackshield.core.data.db.AllowListDao
import com.blackshield.core.data.db.QuarantineDao
import com.blackshield.core.data.model.AllowListEntry
import com.blackshield.core.data.model.QuarantineEntry
import java.time.Clock
import javax.inject.Inject
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

interface AllowListRepository {
    suspend fun allowedPackages(): Set<String>

    fun observeAllowedPackages(): Flow<Set<String>>

    suspend fun allow(packageName: String)

    suspend fun remove(packageName: String)
}

interface QuarantineRepository {
    fun observeAll(): Flow<List<QuarantineEntry>>

    suspend fun quarantine(packageName: String, apkSha256: String?, reason: String)

    suspend fun release(packageName: String)
}

internal class OfflineAllowListRepository
@Inject
constructor(private val dao: AllowListDao, private val clock: Clock) :
    AllowListRepository {
    override suspend fun allowedPackages(): Set<String> = dao.packageNames().toSet()

    override fun observeAllowedPackages(): Flow<Set<String>> = dao.observePackageNames().map { it.toSet() }

    override suspend fun allow(packageName: String) = dao.insert(AllowListEntry(packageName, clock.millis()))

    override suspend fun remove(packageName: String) = dao.delete(packageName)
}

internal class OfflineQuarantineRepository
@Inject
constructor(
    private val dao: QuarantineDao,
    private val clock: Clock
) : QuarantineRepository {
    override fun observeAll(): Flow<List<QuarantineEntry>> = dao.observeAll()

    override suspend fun quarantine(packageName: String, apkSha256: String?, reason: String) =
        dao.insert(QuarantineEntry(packageName, apkSha256, reason, clock.millis()))

    override suspend fun release(packageName: String) = dao.delete(packageName)
}

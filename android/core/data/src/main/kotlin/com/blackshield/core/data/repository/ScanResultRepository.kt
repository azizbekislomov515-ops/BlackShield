package com.blackshield.core.data.repository

import com.blackshield.core.data.db.ScanResultDao
import com.blackshield.core.data.db.SignatureDao
import com.blackshield.core.data.model.ScanResult
import javax.inject.Inject
import kotlinx.coroutines.flow.Flow

interface ScanResultRepository {
    /** Latest result per package, persisted across restarts. */
    fun observeLatest(): Flow<List<ScanResult>>

    suspend fun save(result: ScanResult)

    /** Removes results for packages not in [installed] (apps uninstalled since the last scan). */
    suspend fun retainOnly(installed: Set<String>)
}

internal class OfflineScanResultRepository
@Inject
constructor(private val dao: ScanResultDao) :
    ScanResultRepository {
    override fun observeLatest(): Flow<List<ScanResult>> = dao.observeAll()

    override suspend fun save(result: ScanResult) = dao.upsert(result.copy(id = 0))

    override suspend fun retainOnly(installed: Set<String>) {
        val stale = dao.packageNames().filterNot { it in installed }
        stale.chunked(SignatureDao.SQLITE_MAX_VARIABLES).forEach { dao.delete(it) }
    }
}

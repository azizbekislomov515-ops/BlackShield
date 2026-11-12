package com.blackshield.core.data.db

import androidx.room.TypeConverter
import com.blackshield.core.data.model.ScanReason
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

internal class Converters {
    @TypeConverter
    fun reasonsToJson(reasons: List<ScanReason>): String = json.encodeToString(serializer, reasons)

    @TypeConverter
    fun reasonsFromJson(value: String): List<ScanReason> = json.decodeFromString(serializer, value)

    private companion object {
        val json: Json = Json { ignoreUnknownKeys = true }

        // Explicit type: KSP cannot resolve plugin-generated serializer() during inference.
        val serializer: KSerializer<List<ScanReason>> = ListSerializer(ScanReason.serializer())
    }
}

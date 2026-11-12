package com.blackshield.core.data.db

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * v1 -> v2: adds the signature store, allow-list and quarantine, and reshapes `scan_results`
 * (generic `target` rows become per-package results). Existing v1 rows are kept: `target`
 * becomes the package name and label, with unknown version, digest and reasons.
 *
 * CREATE statements must match the exported schema (schemas/.../2.json); MigrationTest checks it.
 */
internal val MIGRATION_1_2 =
    object : Migration(1, 2) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `malware_signatures` (`hash` TEXT NOT NULL, `algorithm` TEXT NOT NULL, " +
                    "`family` TEXT NOT NULL, `source` TEXT NOT NULL, `severity` TEXT NOT NULL, " +
                    "`added_at` INTEGER NOT NULL, PRIMARY KEY(`hash`))"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `signature_algorithms` " +
                    "(`algorithm` TEXT NOT NULL, PRIMARY KEY(`algorithm`))"
            )

            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `scan_results_new` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                    "`package_name` TEXT NOT NULL, `app_label` TEXT NOT NULL, `version_code` INTEGER NOT NULL, " +
                    "`apk_sha256` TEXT, `verdict` TEXT NOT NULL, `risk_score` INTEGER NOT NULL, " +
                    "`reasons` TEXT NOT NULL, `scanned_at` INTEGER NOT NULL)"
            )
            // Keep only the newest v1 row per target: package_name is unique in v2.
            db.execSQL(
                "INSERT INTO `scan_results_new` (`package_name`, `app_label`, `version_code`, `apk_sha256`, " +
                    "`verdict`, `risk_score`, `reasons`, `scanned_at`) " +
                    "SELECT `target`, `target`, 0, NULL, " +
                    "CASE WHEN `verdict` IN ('CLEAN', 'SUSPICIOUS', 'MALICIOUS') THEN `verdict` ELSE 'CLEAN' END, " +
                    "0, '[]', `scannedAtEpochMillis` FROM `scan_results` " +
                    "WHERE `id` IN (SELECT MAX(`id`) FROM `scan_results` GROUP BY `target`)"
            )
            db.execSQL("DROP TABLE `scan_results`")
            db.execSQL("ALTER TABLE `scan_results_new` RENAME TO `scan_results`")
            db.execSQL(
                "CREATE UNIQUE INDEX IF NOT EXISTS `index_scan_results_package_name` ON `scan_results` (`package_name`)"
            )

            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `quarantine` (`package_name` TEXT NOT NULL, `apk_sha256` TEXT, " +
                    "`reason` TEXT NOT NULL, `quarantined_at` INTEGER NOT NULL, PRIMARY KEY(`package_name`))"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `allow_list` (`package_name` TEXT NOT NULL, " +
                    "`added_at` INTEGER NOT NULL, PRIMARY KEY(`package_name`))"
            )
        }
    }

internal val ALL_MIGRATIONS = arrayOf(MIGRATION_1_2)

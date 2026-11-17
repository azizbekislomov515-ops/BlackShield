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

/** v2 -> v3: Web Shield's blocklist, user allowlist and opt-in activity log. Nothing existing changes. */
internal val MIGRATION_2_3 =
    object : Migration(2, 3) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `blocked_domains` (`domain` TEXT NOT NULL, `category` TEXT NOT NULL, " +
                    "`added_at` INTEGER NOT NULL, PRIMARY KEY(`domain`))"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `web_allow_list` (`domain` TEXT NOT NULL, " +
                    "`added_at` INTEGER NOT NULL, PRIMARY KEY(`domain`))"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `web_activity` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                    "`domain` TEXT NOT NULL, `category` TEXT NOT NULL, `blocked_at` INTEGER NOT NULL)"
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_web_activity_blocked_at` ON `web_activity` (`blocked_at`)")
        }
    }

/** v3 -> v4: scan history and harmful files (detected and quarantined). Nothing existing changes. */
internal val MIGRATION_3_4 =
    object : Migration(3, 4) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `history` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                    "`occurred_at` INTEGER NOT NULL, `kind` TEXT NOT NULL, `source` TEXT NOT NULL, " +
                    "`verdict` TEXT NOT NULL, `subject` TEXT NOT NULL, `target` TEXT, " +
                    "`risk_score` INTEGER NOT NULL, `items_scanned` INTEGER NOT NULL, " +
                    "`threats_found` INTEGER NOT NULL, `duration_millis` INTEGER NOT NULL, `detail` TEXT NOT NULL)"
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_history_occurred_at` ON `history` (`occurred_at`)")
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS `file_threats` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                    "`display_name` TEXT NOT NULL, `source_path` TEXT, `source_uri` TEXT, " +
                    "`size_bytes` INTEGER NOT NULL, `sha256` TEXT, `package_name` TEXT, `app_label` TEXT, " +
                    "`verdict` TEXT NOT NULL, `risk_score` INTEGER NOT NULL, `reasons` TEXT NOT NULL, " +
                    "`detected_at` INTEGER NOT NULL, `state` TEXT NOT NULL, `vault_file` TEXT, " +
                    "`quarantined_at` INTEGER)"
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_file_threats_state` ON `file_threats` (`state`)")
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_file_threats_sha256` ON `file_threats` (`sha256`)")
        }
    }

internal val ALL_MIGRATIONS = arrayOf(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)

# Permissions

Every permission BlackShield requests, why, and where it is declared. Update this page in the same
change that adds or removes a permission. The merged manifest is the source of truth:
`android/app/build/intermediates/merged_manifest/<variant>/.../AndroidManifest.xml`.

| Permission | Declared in | Protection level | Used for |
| --- | --- | --- | --- |
| `QUERY_ALL_PACKAGES` | `:core:scanner` manifest | normal (restricted by Google Play policy) | Listing every installed app to scan it |

The Room database, DataStore and native hashing need no permissions. APK files under `/data/app` and the system
partitions can be read by any app. `INTERNET` will be added together with the signature-feed client.

## QUERY_ALL_PACKAGES

### What it does

Since Android 11 (API 30), `PackageManager` only returns packages that are *visible* to the caller. Without this
permission, `getInstalledPackages()` returns only the system packages an app can always see, plus packages that match
the app's `<queries>` declarations.

### Why BlackShield needs it

The core function of BlackShield is scanning **every** installed app for malware. Each app's base and split APKs are
hashed with the native engine and compared with the signature database (`InstalledAppScanner`). An app that is invisible
to us cannot be scanned.

### Why `<queries>` is not enough

`<queries>` entries match package names we know in advance, or intents that apps handle. Malware is exactly what we
cannot name in advance, and it commonly:

- has no launcher activity (it hides its icon), so `MAIN`/`LAUNCHER` intent queries miss it;
- exports no components that a generic intent query would match;
- uses random or changing package names.

Any `<queries>` set we could write would leave the most important packages out of view, so it does not fit this use.

### Google Play policy

Play's *Use of the broad package (App) visibility (QUERY_ALL_PACKAGES) permission* policy allows the permission only
when an app's core, user-facing functionality needs to discover all installed apps. It lists permitted use cases.
**Anti-malware / device security apps** are one of them. Every release that keeps the permission needs a Permissions
Declaration in Play Console:

| Declaration field | Answer for BlackShield |
| --- | --- |
| Core functionality | Malware scanning of all installed apps (on-device antivirus). |
| Use case category | Antivirus / anti-malware / device security. |
| Why less broad visibility is insufficient | Malware hides from intent queries and uses unpredictable package names (see above). |
| Data use | Package names, versions and APK digests are processed on the device to produce scan results. They are not shared or sold. Any future upload, such as cloud reputation lookups, must be disclosed in the privacy policy and Data safety form. |
| Demo for review | Video: open the app, tap **Scan now**, show the progress and the per-app results list. |

Re-check the current policy text in the Play Console Help Center before each submission. Policies change, and this
page is a summary, not legal advice.

### Implementation notes

- **Where it's declared:** in `:core:scanner/src/main/AndroidManifest.xml`, next to the code that needs it, with
  `tools:ignore="QueryAllPackagesPermission"` and a pointer to this page. It merges into the app.
- **What's read:** only package metadata (`GET_PERMISSIONS` for the heuristics) and the APK paths from
  `ApplicationInfo`. No other app's private data is accessed.
- **Lint:** the `QueryPermissionsNeeded` / `QueryAllPackagesPermission` checks are suppressed only at the
  declaration above. Any other use of package visibility should still get lint's warning.

# Permissions

Every permission BlackShield requests, why, and where it is declared. Update this page in the same
change that adds or removes a permission. The merged manifest is the source of truth:
`android/app/build/intermediates/merged_manifest/<variant>/.../AndroidManifest.xml`.

| Permission | Declared in | Protection level | Used for |
| --- | --- | --- | --- |
| `QUERY_ALL_PACKAGES` | `:core:scanner` manifest | normal (restricted by Google Play policy) | Listing every installed app to scan it |
| `INTERNET` | `:core:network` manifest | normal | Signature updates and reputation lookups (hashes only) |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE` | `:feature:protection` | normal | The real-time protection service |
| `RECEIVE_BOOT_COMPLETED` | `:feature:protection` | normal | Restarting real-time protection after a reboot |
| `POST_NOTIFICATIONS` | `:feature:protection` | dangerous (Android 13+) | Threat warnings and the service's status notification |
| `REQUEST_DELETE_PACKAGES` | `:feature:protection` | normal | "Uninstall" in a warning opens the system uninstall dialog |
| `READ_EXTERNAL_STORAGE` (max SDK 29) | `:feature:protection` | dangerous | Checking new APKs in Download on Android 10 and older |
| `MANAGE_EXTERNAL_STORAGE` | `:feature:protection` | special ("All files access", restricted by Google Play policy) | Checking new APKs in Download on Android 11+; optional |

The Room database, DataStore and native hashing need no permissions. APK files under `/data/app` and the system
partitions can be read by any app.

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

## Real-time protection

### Foreground service: `specialUse`

Since Android 8, `PACKAGE_ADDED` and `PACKAGE_REPLACED` are not delivered to manifest-registered receivers. Only a
receiver registered at runtime, in a running process, gets them. `RealtimeProtectionService` keeps that process alive.
On Android 14+ a foreground service must have a type. `specialUse` is the only one that fits:

- `dataSync` is limited to 6 hours a day on Android 15+, and it may not be started from `BOOT_COMPLETED`.
- `systemExempted` is reserved for apps with special system roles.
- None of the other types (location, media, phone call…) describe malware protection.

The manifest declares the required `PROPERTY_SPECIAL_USE_FGS_SUBTYPE`. Play Console asks for the same justification
plus a video of the feature:

| Declaration | Answer |
| --- | --- |
| Use case | Anti-malware real-time protection |
| Why a foreground service | Package-change broadcasts are only delivered to a running process; scans must happen as an app is installed. |
| User benefit and control | A warning within seconds of installing a harmful app. The service has a visible notification with "Turn off", and a switch in Settings. |

### Notifications (`POST_NOTIFICATIONS`)

On Android 13+ this is requested when the user turns real-time protection on in Settings. It is also requested once
at app start, after a short explanation, if protection is on but warnings could not be shown. Without it the service
still runs and scans, but warnings are invisible. Settings and the troubleshooting screen then show what is wrong,
with a button that opens the notification settings.

### Uninstall (`REQUEST_DELETE_PACKAGES`)

The "Uninstall" action in a warning starts `Intent.ACTION_DELETE` for the package. The system uninstall dialog
appears and the user confirms there, so BlackShield never removes anything by itself. Apps targeting Android 9+ need
this normal permission for the system to accept the intent.

### Storage: MediaStore and SAF first, All files access only for Downloads on Android 11+

Real-time protection can also check new APK files before they are installed. The permission needed depends on what
is watched and on the Android version:

| What | Android 10 and older | Android 11+ |
| --- | --- | --- |
| Download folder | `READ_EXTERNAL_STORAGE`, watched with `FileObserver` | **`MANAGE_EXTERNAL_STORAGE`**, watched through MediaStore |
| Folders the user picks | Storage Access Framework tree, no permission | Storage Access Framework tree, no permission |

**Why Downloads needs All files access on Android 11+.** We tried each narrower option:

- **MediaStore:** with or without `READ_EXTERNAL_STORAGE` / `READ_MEDIA_*`, an app sees media files (images, video,
  audio) and its own entries in `MediaStore.Downloads`. APKs downloaded by a browser or another app are neither, so
  they are invisible.
- **SAF:** `ACTION_OPEN_DOCUMENT_TREE` refuses to grant the `Download` directory itself (or the storage root) on
  Android 11+. Subfolders and other folders can be granted, and that is what "Other folders to check" uses.
- **`FileObserver`:** inotify does not reliably see writes made by other apps through the FUSE mount of shared
  storage on Android 11+. Even when it does, the file would not be readable without All files access.

So Downloads monitoring on Android 11+ either uses All files access or does not exist. It is **off by default and
optional**. When the user switches it on, a dialog explains why and what the access is used for, and only then sends
them to the system "All files access" screen. Without the grant, BlackShield still protects installs and
user-picked folders; Settings and the troubleshooting screen show that Downloads cannot be checked.

**What the access is used for:** reading the APK files that MediaStore reports as new in `Download/`, to hash and
parse them. No other files are read, uploaded or changed.

**Google Play.** All files access is a restricted permission. Play's policy lists **antivirus** among the permitted
core uses. The Permissions Declaration needs:

| Field | Answer |
| --- | --- |
| Core feature | Scanning newly downloaded APK files for malware before installation (on-device antivirus). |
| Why narrower access does not work | See above: MediaStore hides other apps' non-media downloads; SAF cannot grant `Download`. |
| User control | Off by default, explained in-app before the system prompt, revocable at any time. |

### Battery

The troubleshooting screen opens `ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS`, the system list where the user picks
BlackShield. It does not use `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` / `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`,
because Play restricts that permission to a narrow set of use cases. Protection is event-driven (broadcasts,
MediaStore and document notifications, debounced), with no polling, so it costs very little battery in practice.

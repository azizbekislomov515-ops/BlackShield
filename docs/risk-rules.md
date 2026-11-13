# Static analysis and risk rules

BlackShield flags suspicious apps even when no signature matches their hash. Three parts are involved, all in
`:core:scanner`:

1. **`ApkAnalyzer`** builds an `AppProfile` for each installed app. Nothing is executed.
2. **`RiskEngine`** scores the profile with rules from a JSON file and explains each point.
3. **`RiskAssessor`** combines the rule score with signature matches into the stored verdict and reasons. The scan
   details screen shows the reasons.

## 1. What is extracted (`AppProfile`)

| Field | Source |
| --- | --- |
| Requested, granted and dangerous permissions | `PackageInfo.requestedPermissions[Flags]`; protection level from `getPermissionInfo` |
| Components, `exported`, guarding permission | `PackageInfo` activities, aliases, services, receivers, providers (`MATCH_DISABLED_COMPONENTS`) |
| Intent filters (actions, categories, schemes, hosts, priority) | **Binary `AndroidManifest.xml`**, parsed by `ManifestParser`. PackageManager does not expose them. |
| Signing certificates: SHA-256, subject, self-signed, debug key, AOSP test key | `signingInfo.apkContentsSigners` (API 28+), else `signatures`; `SigningCertificates` |
| Installer and initiating app | `getInstallSourceInfo` (API 30+), else `getInstallerPackageName` |
| Target SDK, first install and last update time | `ApplicationInfo`, `PackageInfo` |
| Launcher: visible, none declared, or **hidden** (declared but disabled at runtime) | Two `MAIN`/`LAUNCHER` queries per scan, with and without `MATCH_DISABLED_COMPONENTS` |
| Application class, native library names | `ApplicationInfo.className`; the APK's zip directory |
| Accessibility service enabled, active device admin | `AccessibilityManager`, `DevicePolicyManager` (once per scan) |
| Analysis gaps | Anything that could not be read is listed; the verdict is never silently based on missing data |

**Manifest parser.** `BinaryXmlReader` reads Android binary XML (AXML) with bounds checks on every read. Malformed
input only ever produces `ManifestParseException`; this is tested by truncating a real manifest at every length and
by 5,000 seeded random corruptions. `ManifestParser` reads the manifest the way the platform does:

- `android:` attributes are identified by resource ID, not by their name string, which packers rename.
- Components count only inside the first `<application>`.
- Class names resolve like `PackageParser.buildClassName`.

On the reference emulator it parses all 264 installed manifests (7,264 components) and agrees with PackageManager on
every component (`InstalledAppsAnalysisTest`). Analysis takes about 11–17 ms per app.

## 2. Rules file

Shipped as `core/scanner/src/main/assets/risk/risk_rules.json`. A file at `noBackupFilesDir/risk/risk_rules.json`
overrides it; that is where a future backend download will put updates (`BundledRiskRulesSource`). Parsing is strict
(`RiskRulesParser`): an unknown key, condition, enum value, list reference or group rejects the **whole** file, and the
app keeps the bundled rules. A rules update written for a newer app can therefore never be half-applied.

```json
{
  "schemaVersion": 1,
  "rulesVersion": "2026-11-13.1",
  "thresholds": { "suspicious": 40, "malicious": 75 },
  "trustedInstallers": { "com.android.vending": "Google Play", "org.fdroid.fdroid": "F-Droid" },
  "allowlist": { "systemApps": true, "apps": [{ "package": "…", "certSha256": "…" }] },
  "groups": { "capability": { "maxPoints": 50 } },
  "lists": { "smsPermissions": ["android.permission.READ_SMS", "…"] },
  "rules": [
    { "id": "packed", "title": "Plain-language explanation", "points": 25, "group": null,
      "when": { "any": [{ "applicationClassIn": "@packerClasses" }, { "nativeLibraryMatches": "@packerLibraries" }] } }
  ]
}
```

### Conditions

Each condition is an object with exactly one key. Wherever a list of strings is expected, `"@name"` refers to `lists`.

| Condition | Matches when |
| --- | --- |
| `all`, `any`: `[conditions]`; `not`: `{condition}` | Combinators (nesting depth at most 16) |
| `requestsPermission`, `requestsAllPermissions`, `requestsAnyPermission` | The app requests the permission(s) |
| `dangerousPermissionsAtLeast`: n | At least n requested permissions are `dangerous` |
| `installSource`: `PREINSTALLED` / `PLAY_STORE` / `TRUSTED_STORE` / `OTHER_INSTALLER` / `UNKNOWN` | Installer category, judged with `trustedInstallers`. `OTHER_INSTALLER` is the package installer (a downloaded APK) or any other app; `UNKNOWN` is no installer (adb). |
| `componentWithPermission`: p | A component is guarded by p (e.g. `BIND_ACCESSIBILITY_SERVICE` marks an accessibility service) |
| `handlesAction`: [actions] | An intent filter declares one of the actions |
| `launcher`: `VISIBLE` / `NONE_DECLARED` / `HIDDEN` | Launcher state |
| `installedWithinDays`: n | First installed less than n days ago |
| `targetSdkBelow`: n | Known target SDK below n |
| `certificate`: `DEBUG` / `AOSP_TEST_KEY` | A signing certificate has the trait |
| `applicationClassIn`, `nativeLibraryMatches` | Application class in the list; a library file name matches a pattern (`*` wildcard, case-insensitive) |
| `obfuscatedComponents`: `{minComponents, minShare}` | At least `minShare` of at least `minComponents` components have names R8 never produces for manifest classes (simple name of 1–2 characters, or all segments 1–2 characters) |
| `accessibilityEnabled`, `deviceAdminActive`, `debuggable`: `true` | Runtime state or manifest flag. Use `not` to negate. |

## 3. Scoring

- **Exemptions.** Preinstalled system apps (`FLAG_SYSTEM`, including updated system apps) and allowlisted apps (package
  pinned to its signing certificate) are not scored. Their reason says why.
- **Points.** Rules run in file order. Each matching rule adds its points; negative points are signs of trust, such as
  an install from Google Play. The score is the sum, clamped to 0–100.
- **Group caps.** All `capability` rules together add at most 50 points. Legitimate automation apps (Tasker) and
  banking trojans have the same capabilities, so capabilities alone reach SUSPICIOUS at most. MALICIOUS also takes signs
  of concealment: a hidden icon, a packer, obfuscated names, a public test key or a legacy-SDK permission trick. A
  capped finding shows its full points too ("+15 of 20").
- **Verdict.** Below 40 is CLEAN, 40 and above SUSPICIOUS, 75 and above MALICIOUS. A signature match is MALICIOUS
  regardless, and then the rules are not run.
- **Determinism.** The result depends only on the profile, the rules and the current time; evidence lists are sorted.
  Each finding carries its rule ID, plain-language title, points and evidence; the score equals the sum of the points.

### Shipped rules (2026-11-13.1)

| Rule | Points | Signal |
| --- | --- | --- |
| `installed_from_play` / `installed_from_known_store` | −20 / −10 | Reviewed source |
| `unknown_source` | +15 | Not from a store |
| `banking_trojan_capabilities` | +35 (capability) | SMS + accessibility service + overlay |
| `device_admin_unknown_source` | +20 (capability) | Device admin, not from a store |
| `installs_other_apps_unknown_source` | +15 (capability) | `REQUEST_INSTALL_PACKAGES`, not from a store |
| `many_sensitive_permissions_unknown_source` | +15 (capability) | 10+ dangerous permissions, not from a store |
| `reads_sms_unknown_source` | +15 (capability) | Reads SMS or receives `SMS_RECEIVED`, not from a store |
| `accessibility_enabled_unknown_source` / `device_admin_active_unknown_source` | +15 / +10 (capability) | Granted and switched on |
| `hidden_launcher_icon` | +30 | Launcher activity disabled after install |
| `no_launcher_icon_unknown_source` | +10 | No icon, not from a store |
| `packed` | +25 | Known packer loader or library (Jiagu, Legu, Bangcle, Baidu, Ijiami, Alibaba) |
| `obfuscated_component_names` | +20 | Meaningless manifest class names |
| `aosp_test_key` | +50 | Signed with a public AOSP test key |
| `legacy_target_sdk_unknown_source` | +15 | Target SDK < 23 (permissions granted at install) |
| `development_build_unknown_source` | +10 | Debug-signed or debuggable |
| `recently_sideloaded` | +5 | Installed from a downloaded APK in the last 3 days. Not for adb installs, which come from developers. |

Single sideloading signals stay CLEAN. Combinations reach SUSPICIOUS. MALICIOUS takes capabilities plus concealment.
Self-signed certificates are reported but never penalized, because almost every Android app certificate is
self-signed.

## 4. Tests

- `RiskRulesBehaviourTest`: one test per shipped rule (it fires, with evidence, and stays quiet on near misses). A
  catalogue test fails if a rule is added to the JSON without a trigger.
- `RealWorldProfilesTest`: popular legitimate apps that must stay CLEAN (Google Messages, WhatsApp, Tasker, Bitwarden,
  Intune, Gboard, F-Droid apps, packed vendor-store apps, BlackShield's own debug build, system apps), sideloaded
  Tasker (SUSPICIOUS, not MALICIOUS), and malware shapes that must be flagged.
- `RiskEngineTest`: thresholds, caps, negative points, exemptions, determinism. `RiskRulesParserTest`: schema
  validation and fallback.
- `ManifestParserTest`: aapt2-compiled fixtures (`src/test/resources/manifests/*.xml` with their compiled `.axml`),
  synthetic edge cases and fuzzing. `SigningCertificatesTest`.
- Instrumented `InstalledAppsAnalysisTest`: every installed manifest parses and matches PackageManager, and no system
  app is flagged.

**Changing a rule:** edit the JSON, bump `rulesVersion`, add or adjust the rule's case in `RiskRulesBehaviourTest`,
and run `RealWorldProfilesTest` to check for new false positives.

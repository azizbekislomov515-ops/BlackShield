# Google Play policy checklist

What to verify and declare before each Play release. BlackShield is an anti-malware app, a category Google Play
explicitly allows some restricted permissions for, but each one needs a declaration, a prominent disclosure and use
that matches the declaration. Policy wording changes; re-read the linked policies before every submission and record
the date you did.

Last reviewed against the policies: [date, reviewer]

## VPN (`VpnService`) — Web Shield

Policy: [VpnService policy](https://support.google.com/googleplay/android-developer/answer/12564964). VPN use is
allowed for core functionality including "security apps (anti-malware, ...)".

- [ ] Web Shield is a core feature described in the store listing ("blocks malware and phishing websites on the
      device").
- [ ] Play Console > App content > VPN service declaration: core purpose "Security / anti-malware", explain that only
      DNS for two virtual addresses is routed through the on-device VPN, nothing leaves the device for the
      developer, and the app's own traffic is excluded.
- [ ] Prominent in-app disclosure before the system VPN consent dialog (onboarding step 3 and the Web Shield screen):
      what it does, that browsing data stays on the phone. The consent dialog is only shown after the user taps
      "Turn on".
- [ ] No data collected through the VPN (no domain logging off-device; opt-in local activity log only), no ads
      injected, no traffic redirected for monetisation. Matches [privacy.md](privacy.md).
- [ ] `BIND_VPN_SERVICE` on the service; always-on VPN supported (`SUPPORTS_ALWAYS_ON`).
- [ ] Short video for the declaration: turning Web Shield on, the consent dialog, a blocked page notification.

## Accessibility services

BlackShield does **not** use the Accessibility API (no `AccessibilityService`, no `BIND_ACCESSIBILITY_SERVICE`).

- [ ] Confirm in the merged manifest: `aapt2 dump xmltree --file AndroidManifest.xml app-release.apk | grep -i
      accessibility` prints nothing.
- [ ] Play Console accessibility declaration: "does not use the AccessibilityService API".
- [ ] If this ever changes: the [Accessibility API policy](https://support.google.com/googleplay/android-developer/answer/10964491)
      requires a prominent disclosure, consent and a declaration; anti-malware use alone does not justify it, and
      `isAccessibilityTool` must not be claimed.

## All files access (`MANAGE_EXTERNAL_STORAGE`) — download monitoring

Policy: [All files access](https://support.google.com/googleplay/android-developer/answer/10467955). "Anti-virus apps"
are a permitted use.

- [ ] Optional feature: the app works fully without it; requested only when the user turns on "Check new downloads"
      on Android 11+, through the system settings page, after an in-app explanation.
- [ ] Play Console > App content > All files access declaration: core use "antivirus: scanning APK files other apps
      download into the shared Download folder"; explain why MediaStore and SAF cannot do it
      ([permissions.md](permissions.md#storage-mediastore-and-saf-first-all-files-access-only-for-downloads-on-android-11)).
- [ ] Only reads files to scan them; writes only by deleting/quarantining a file the user chose to handle.
- [ ] Video for the declaration: turning the feature on, the explanation, the settings page, a detected download.

## `QUERY_ALL_PACKAGES`

Policy: [Package visibility](https://support.google.com/googleplay/android-developer/answer/10158779). Anti-malware is
a permitted use.

- [ ] Play Console > App content > declaration: "Antivirus / device security: scans every installed app".
- [ ] Installed-app data stays on the device ([privacy.md](privacy.md)); not sent anywhere.

## Foreground service (`specialUse`)

Policy: [Foreground service types](https://support.google.com/googleplay/android-developer/answer/13392821).

- [ ] Play Console > App content > Foreground service permissions: `FOREGROUND_SERVICE_SPECIAL_USE`, use case
      "real-time anti-malware protection", with the subtype text from the manifest property and a video.
- [ ] The service runs only while the user has real-time protection on, with a persistent notification.

## Other restricted or sensitive APIs

- [ ] `REQUEST_DELETE_PACKAGES`: used only for the user-confirmed system uninstall dialog.
- [ ] No SMS/Call Log, location, contacts, camera, microphone, exact alarms, device admin, `REQUEST_INSTALL_PACKAGES`.
- [ ] Target API level meets the current Play requirement (targetSdk 37).

## Data safety form

Based on [privacy.md](privacy.md):

| Question | Answer |
| --- | --- |
| Does the app collect or share user data? | Collects: **Crash logs** (App info and performance), only when the user opts in. Nothing shared. |
| Crash logs: required or optional? | Optional (off by default) |
| Purpose | App functionality (fixing crashes) |
| Processed ephemerally? | No (kept 90 days) |
| Encrypted in transit? | Yes (HTTPS only, TLS 1.2+; certificate pins when configured for the release, see release.md) |
| Can users request deletion? | Yes, by contact; reports carry no identifier, deleted after 90 days automatically |
| Installed apps, files, web browsing | Processed **on device only**: per Google's definition this is not "collected" (not transmitted off the device) |
| Device or other IDs | Not collected |
| Independent security review | Optional (MASA); consider after launch |

## Store listing and other

- [ ] Privacy policy URL ([privacy-policy.md](privacy-policy.md), published) set in Play Console and linked in the
      app.
- [ ] No claims that cannot be shown ("100% protection", fake scan counts); screenshots from the real app.
- [ ] Content rating questionnaire completed.
- [ ] App signing by Google Play enabled; the Play app signing certificate SHA-256 added to
      `BLACKSHIELD_RELEASE_CERT_SHA256` ([release.md](release.md)).

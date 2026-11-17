# BlackShield Privacy Policy (draft)

> **Draft for legal review.** Fill in the bracketed parts, have it reviewed for the countries you publish in (for
> example GDPR in the EU, Uzbekistan's Law on Personal Data), publish it at a public URL and link it in the Play
> Console and in the app. Keep it in step with [privacy.md](privacy.md).

**Effective date:** [date]
**Developer:** [legal name], [address]
**Contact:** [privacy email address]

BlackShield is a security app that finds malware on your phone, checks APK files you download, keeps harmful files in
an encrypted quarantine and blocks dangerous websites. This policy explains what data the app uses and why.

## The short version

- Scanning, quarantine and website blocking happen **on your phone**.
- BlackShield does **not** collect your name, contacts, location, accounts, browsing history or a list of your apps.
- The app downloads threat information (malware signatures and lists of dangerous websites) from our servers. These
  downloads do not contain information about you.
- Crash reports are sent **only if you turn them on**, and contain no personal data.
- There are no ads, analytics or tracking in BlackShield.

## What stays on your phone

To protect you, BlackShield looks at the apps installed on your phone, new APK files in your Download folder (if you
turn on download monitoring), and the website names your phone looks up (if you turn on Web Shield). It stores scan
results, a history of scans and actions (kept for one year), and the files you quarantine (encrypted). If you turn
on the Web Shield activity log, it keeps a list of blocked websites for 7 days.

This information is stored only on your phone, is not included in backups, and is deleted when you uninstall the app.
You can export your history yourself; the file goes only where you choose to save it.

## What is sent to our servers

**Threat updates.** About every 6 hours, the app asks our servers for new malware signatures, detection rules and
dangerous website lists. The request contains only which version the app already has.

**Crash reports (only if you turn them on).** If you turn on "Send crash reports" in Settings and the app crashes, it
sends the app version, your Android version, the time of the crash and the technical location in the app's code
where it failed. It never sends error messages, file names, your device model or any identifier. We keep crash
reports for 90 days and use them only to fix bugs. You can turn this off at any time; reports not yet sent are then
deleted.

When your phone connects to our servers, our systems see its IP address. We use it briefly to protect the servers
against abuse (rate limiting) and do not store it.

## Websites you visit

When Web Shield is on, BlackShield sets up a VPN on your phone so it can check website names against the list of
dangerous websites. Only website name lookups (DNS) go through it, and they are checked on your phone. Lookups that
are allowed go to your network's usual DNS server. BlackShield never sends the websites you visit to us or anyone
else, and it does not see the content of your connections.

## Permissions

The app asks for permissions only for the features that need them, for example notifications for threat warnings,
all files access for download monitoring (optional) and the VPN for Web Shield (optional). The full list and the
reason for each is at [link to permissions page].

## Sharing

We do not sell or share your data. We do not use third-party analytics, advertising or tracking services. Our servers
are hosted by [hosting provider] in [country/region].

## Children

BlackShield is not directed at children under 13 and does not knowingly collect their data.

## Your choices and rights

You can turn off download monitoring, Web Shield, the activity log and crash reports at any time in the app, and
delete all data by uninstalling it. Because we do not keep data that identifies you, we usually cannot link a crash
report to you; if you have questions or want to exercise rights under the law that applies to you, contact
[privacy email address].

## Changes

We will update this policy when the app's data handling changes and show the new effective date above. Significant
changes will be announced in the app.

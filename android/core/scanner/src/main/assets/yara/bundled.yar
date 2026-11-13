// blackshield-yara-rules version: 1
//
// BlackShield's bundled YARA rules. Written by the BlackShield project and distributed under the
// project's license (see docs/third-party.md); no third-party rules are included.
//
// Shipped inside the APK (whose signature covers this file) and replaced by newer signed rulesets
// from GET /v1/rules. Conventions, checked by YaraBundledRulesTest:
//   - every rule has meta `severity` (low | medium | high | critical) and `description`;
//   - DEX-only rules start with `is_dex`, so they never fire on the raw APK bytes;
//   - only modules built into the engine (dex, math) may be imported.
// Severity feeds the risk engine (assets/risk/risk_rules.json, rules yara_*).

private rule is_dex
{
    condition:
        uint32(0) == 0x0a786564 // "dex\n"
}

rule BlackShield_Test_File
{
    meta:
        severity = "critical"
        description = "BlackShield test file: a harmless marker used to check that detection works"
        author = "BlackShield"
    strings:
        $marker = "X5O-BLACKSHIELD-YARA-TEST-FILE-1d8e"
    condition:
        $marker
}

rule Android_Telegram_Bot_SMS_Exfiltration
{
    meta:
        severity = "high"
        description = "Reads incoming SMS messages and talks to a Telegram bot, a common way to steal one-time codes"
        author = "BlackShield"
    strings:
        $bot = "api.telegram.org/bot"
        $sms1 = "android.provider.Telephony.SMS_RECEIVED"
        $sms2 = "content://sms"
        $read1 = "getMessageBody"
        $read2 = "getDisplayMessageBody"
        $read3 = "getOriginatingAddress"
    condition:
        is_dex and $bot and any of ($sms*) and any of ($read*)
}

rule Android_DeviceAdmin_Lock_And_Wipe
{
    meta:
        severity = "high"
        description = "Code to lock the screen, change the lock password and wipe the device, as ransomware does"
        author = "BlackShield"
    strings:
        $admin = "Landroid/app/admin/DevicePolicyManager;"
        $lock = "lockNow"
        $wipe = "wipeData"
        $password1 = "resetPassword"
        $password2 = "resetPasswordWithToken"
    condition:
        is_dex and $admin and $lock and $wipe and any of ($password*)
}

rule Android_Root_Persistence_Commands
{
    meta:
        severity = "high"
        description = "Shell commands that remount the system partition and plant a setuid binary"
        author = "BlackShield"
    strings:
        $remount1 = "mount -o remount,rw /system"
        $remount2 = "mount -o rw,remount /system"
        $setuid1 = "chmod 4755"
        $setuid2 = "chmod 6755"
        $su = "/system/xbin/su"
    condition:
        is_dex and any of ($remount*) and any of ($setuid*) and $su
}

rule Android_Accessibility_Remote_Control
{
    meta:
        severity = "medium"
        description = "Uses an accessibility service to read the screen, tap and swipe on its own, and draw over other apps"
        author = "BlackShield"
    strings:
        $root = "getRootInActiveWindow"
        $gesture = "dispatchGesture"
        $global = "performGlobalAction"
        $click = "ACTION_CLICK"
        $overlay1 = "TYPE_APPLICATION_OVERLAY"
        $overlay2 = "android.settings.action.MANAGE_OVERLAY_PERMISSION"
        $keyguard = "disableKeyguard"
    condition:
        is_dex and $root and $gesture and $global and $click and any of ($overlay*) and $keyguard
}

rule Android_Dynamic_Code_From_Shared_Storage
{
    meta:
        severity = "medium"
        description = "Loads executable code from shared storage, where any app can replace it"
        author = "BlackShield"
    strings:
        $loader1 = "Ldalvik/system/DexClassLoader;"
        $loader2 = "Ldalvik/system/InMemoryDexClassLoader;"
        $path1 = "/sdcard/Download/"
        $path2 = "/storage/emulated/0/Download/"
        $path3 = "/sdcard/Android/data/"
        $ext1 = ".dex"
        $ext2 = ".jar"
    condition:
        is_dex and any of ($loader*) and any of ($path*) and any of ($ext*)
}

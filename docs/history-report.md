# History report

The History screen exports the events it currently shows, with its filters applied, as a file the user saves with the
system file picker. Nothing is uploaded. Two formats:

- **PDF**, to read, print or share: A4 pages with the filters, then one line per event (date, title, source, verdict),
  in the app's language.
- **JSON**, for tools: the shape below. It is stable within a `format` version. New fields may be added without a new
  version, so readers should ignore fields they do not know.

## JSON, format 1

```json
{
  "format": 1,
  "app": "BlackShield",
  "generatedAt": "2026-11-14T09:30:00Z",
  "filter": { "period": "WEEK", "verdicts": ["MALICIOUS"], "sources": [] },
  "events": [
    {
      "occurredAt": "2026-11-14T08:12:40Z",
      "kind": "ITEM_CHECKED",
      "source": "REAL_TIME",
      "verdict": "MALICIOUS",
      "subject": "Super Flashlight",
      "target": "com.example.flashlight",
      "riskScore": 96,
      "itemsScanned": 0,
      "threatsFound": 0,
      "durationMillis": 0,
      "detail": "Android.Banker.Gen"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `generatedAt`, `occurredAt` | ISO-8601 instants in UTC. |
| `filter.period` | `DAY`, `WEEK`, `MONTH` or `ALL`. Empty `verdicts` or `sources` means all of them. |
| `kind` | `SCAN_COMPLETED` (a full scan of installed apps), `ITEM_CHECKED` (one app or file), `QUARANTINED`, `RESTORED`, `DELETED` (a quarantined file deleted for good), `UNINSTALLED`. |
| `source` | `MANUAL`, `SCHEDULED`, `REAL_TIME` or `FILE` (a file the user picked). |
| `verdict` | `CLEAN`, `SUSPICIOUS` or `MALICIOUS`. For a full scan, the worst verdict found. |
| `subject`, `target` | App label or file name, and the package name or file name. Empty for full scans. |
| `riskScore` | 0 to 100, for single items. |
| `itemsScanned`, `threatsFound`, `durationMillis` | For full scans. |
| `detail` | The main reason (malware family or rule title); for full scans, up to five flagged app names. |

The history keeps one year of events on the device. The report contains app names and package names, so the
file itself is personal data. It is written only where the user chooses.

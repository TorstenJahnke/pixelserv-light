# TLSGateNX - Backup Verzeichnis

Dieses Verzeichnis enthält CA-Statistiken und Backup-Informationen.

## CA Statistik

Die Datei `ca_statistics.txt` enthält folgende Informationen:

- **Name der CA**: Subject und Issuer der Zertifikate
- **Anzahl der Keys**: Wie viele private Keys gefunden wurden
- **Welche Keys**: Liste der gefundenen Key-Dateien mit Details
- **Timestamp**: "Last Backup from" mit Datum und Uhrzeit

## Verwendung

Um die Statistik zu generieren/aktualisieren:

```bash
./tools/ca-statistics.sh .
```

Das Skript sucht automatisch nach CA-Zertifikaten und Keys im `rootCA/` Verzeichnis.

## Unterstützte CA-Strukturen

- **Single-Tier**: `ca.crt` + `ca.key`
- **Two-Tier**: `rootca.crt` + `ca.crt` + `ca.key`

Unterstützte Dateinamen:
- Zertifikate: `ca.crt`, `ca.pem`, `subca.crt`, `subca.pem`, `SubCA`, `rootca.crt`, `rootca.pem`, `RootCA`
- Keys: `ca.key`, `ca-key.pem`, `SubCA.key`, `subca.key`

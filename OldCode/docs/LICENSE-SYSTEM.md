# TLSGateNG License System - Konzept

> **Status:** Geplant - Implementierung wenn Code 100% produktionsreif

## Übersicht

Hardware-gebundene Zertifikatslizenzierung. Die Lizenz ist ein X.509 Zertifikat,
das an die Hardware des Servers gebunden ist.

## Hardware-Fingerprint

```
Fingerprint = SHA256(SALT + CPU_ID + BOARD_UUID + BOARD_SERIAL + SALT2)
```

> **Hinweis:** Der exakte Algorithmus (Felder, Reihenfolge, Salt) ist im Code versteckt.
> Selbst bei Kenntnis der Quellen ist ohne Salt kein gültiger Hash erstellbar.

### Quellen (Linux)

| Quelle | Pfad | Beschreibung |
|--------|------|--------------|
| Board UUID | `/sys/class/dmi/id/product_uuid` | Eindeutig pro Motherboard |
| Board Serial | `/sys/class/dmi/id/board_serial` | Seriennummer |
| CPU Info | `/proc/cpuinfo` oder CPUID | Prozessor-Identifikation |

### Stabilität

| Änderung | Fingerprint |
|----------|-------------|
| OS Neuinstallation | Bleibt gleich |
| RAM Erweiterung | Bleibt gleich |
| Netzwerkkarte tauschen | Bleibt gleich |
| Festplatte tauschen | Bleibt gleich |
| **Neues Motherboard** | **Ändert sich** |
| **Neue CPU** | **Ändert sich** |

## Lizenz-Zertifikat

Das Lizenzzertifikat enthält:

```
Subject CN     = Hardware-Fingerprint (SHA256)
Not Before     = Lizenz-Startdatum
Not After      = Lizenz-Ablaufdatum
Issuer         = TLSGateNG License CA
Signature      = RSA/ECDSA Signatur der CA
```

### Beispiel

```
Certificate:
    Subject: CN=a3f8b2c4d5e6f7...9012345678abcdef
    Issuer: CN=TLSGateNG License CA
    Validity:
        Not Before: Dec  1 00:00:00 2024 UTC
        Not After : Dec  1 00:00:00 2025 UTC
```

## Komponenten

| Komponente | Speicherort | Besitzer |
|------------|-------------|----------|
| License CA Private Key | Offline/HSM | Vendor (niemals verteilt!) |
| License CA Public Key | Im Binary eingebettet | Alle Kunden |
| license.crt | `/etc/tlsgateNG/license.crt` | Kunde |

## Verifizierung beim Start

```c
1. Lade /etc/tlsgateNG/license.crt
2. Prüfe Signatur gegen eingebettete CA (Public Key)
3. Prüfe NotAfter > now (nicht abgelaufen / Grace Period)
4. Prüfe CN == aktueller Hardware-Fingerprint
   → Alle OK = Server startet
   → Fehler = Server stoppt mit Fehlermeldung
```

## Grace Period (Übergangsfrist)

Nach Lizenzablauf läuft der Server noch X Tage weiter:

```
Lizenz abgelaufen am:     01.12.2028
Grace Period:             30 Tage
Endgültiges Ende:         31.12.2028

Verhalten:
- Tag 1-30 nach Ablauf:   Warnung im Log, Server läuft
- Ab Tag 31:              Server startet nicht mehr
```

### Konfiguration

```ini
[license]
grace_period_days=30
```

## CLI-Befehle (geplant)

### `--license-request`

Generiert CSR mit Hardware-Fingerprint für Erstkauf/Neulizenzierung:

```bash
$ ./tlsgateNG --license-request > hardware.csr

Hardware Fingerprint: a3f8b2c4d5e6f7...
CSR generated: hardware.csr
Send this file to vendor for license generation.
```

### `--license-status`

Zeigt aktuellen Lizenzstatus:

```bash
$ ./tlsgateNG --license-status

License Status:
  Hardware ID:    a3f8b2c4d5e6f7...9012345678abcdef
  License File:   /etc/tlsgateNG/license.crt
  Status:         VALID
  Issued:         2024-12-01
  Expires:        2025-12-01
  Days Left:      247
  Grace Period:   30 days (not active)
```

### `--getonline`

Automatische Lizenzverlängerung (erfordert Netzwerk):

```bash
$ ./tlsgateNG --getonline

Checking license status...
Current license expires in 15 days.
Contacting license server...
Authentication: Using current license
Hardware verification: OK
Payment status: OK
New license received!
  Valid until: 2026-12-01
Saved to: /etc/tlsgateNG/license.crt
```

## Online-Renewal Flow

Jeder Kunde hat eine eindeutige URL basierend auf dem Firmennamen-Hash:

```
Kunde: "Acme GmbH"
Hash:  SHA256("Acme GmbH") = a1b2c3d4e5f6...

URL:   https://license.example.com/a1b2c3d4e5f6
       → Dort liegt: license.crt für diesen Kunden
```

### Ablauf

```
┌─────────────────────┐                    ┌─────────────────────┐
│   Kundenserver      │                    │   License Server    │
│                     │                    │   (Statische Files) │
│ 1. Lizenz abgelaufen│                    │                     │
│ 2. Lese Firmenname  │  GET /{hash}       │                     │
│    aus Zertifikat   │ ──────────────────►│  /a1b2c3.../        │
│ 3. Hash berechnen   │                    │    license.crt      │
│ 4. Download         │  license.crt       │                     │
│                     │ ◄──────────────────│                     │
│ 5. Speichern        │                    │                     │
└─────────────────────┘                    └─────────────────────┘
```

### Vorteile

- Kein komplexer Lizenzserver nötig - nur statische Dateien (nginx/Apache)
- Keine Authentifizierung nötig (URL ist "geheim")
- Kunde nicht bezahlt? → Datei löschen
- Einfaches Deployment neuer Lizenzen

### Sicherheit

- HTTPS mit Certificate Pinning
- Firmenname-Hash als "geheime" URL
- Gestohlene Lizenz nutzlos (Hardware-Hash passt nicht)
- Rate Limiting auf Server-Seite

## Fehlermeldungen

| Code | Meldung | Bedeutung |
|------|---------|-----------|
| `LICENSE_MISSING` | No license file found | license.crt fehlt |
| `LICENSE_INVALID` | License signature invalid | Manipulation oder falsche CA |
| `LICENSE_EXPIRED` | License expired | Ablaufdatum überschritten |
| `LICENSE_GRACE` | License in grace period | Warnung, läuft noch X Tage |
| `LICENSE_HARDWARE` | Hardware mismatch | Falscher Server |

## Dateiformat

Die Lizenzdatei ist ein Standard X.509 PEM-Zertifikat:

```
-----BEGIN CERTIFICATE-----
MIICxjCCAa6gAwIBAgIUE7w...
...base64 encoded certificate...
-----END CERTIFICATE-----
```

## CA Public Key Obfuscation

Der CA Public Key ist im Binary eingebettet, aber verschleiert:

```c
// NICHT so (leicht zu finden mit `strings`):
const char *ca_pem = "-----BEGIN CERTIFICATE-----\nMIIC...";

// SONDERN so:
static const uint8_t ca_blob[] = { 0x4a, 0x8f, 0x2b, ... };  // XOR verschlüsselt
static const uint8_t ca_key[] = { 0x1f, 0xa3, 0x7c, ... };   // XOR Schlüssel

// Zur Laufzeit entschlüsseln
for (int i = 0; i < sizeof(ca_blob); i++) {
    ca_pem[i] = ca_blob[i] ^ ca_key[i % sizeof(ca_key)];
}
```

### Versteck-Methoden

| Methode | Schutz gegen |
|---------|--------------|
| XOR-Verschlüsselung | `strings binary` |
| Über mehrere Arrays verteilt | Hex-Editor Pattern-Suche |
| Zur Laufzeit zusammenbauen | Statische Analyse |
| In Fake-Daten verstecken | Automatische Extraktion |

> **Hinweis:** Der Public Key muss nicht geheim sein - Obfuscation erschwert
> nur Reverse Engineering und Binary-Patching (eigene CA einsetzen).

## Uhrzeit-Manipulation erkennen

### Problem

```
Angreifer setzt System-Uhr zurück
→ Lizenz erscheint "noch gültig"
```

### Lösung: BIOS/RTC Check

```c
#include <linux/rtc.h>
#include <sys/ioctl.h>

time_t get_bios_time(void) {
    int fd = open("/dev/rtc0", O_RDONLY);
    struct rtc_time rtc;
    ioctl(fd, RTC_RD_TIME, &rtc);
    close(fd);
    // ... convert to time_t
    return mktime(&tm);
}

// Prüfung
time_t sys_time = time(NULL);
time_t rtc_time = get_bios_time();

if (abs(sys_time - rtc_time) > 86400) {  // > 1 Tag Differenz
    LOG_ERROR("Clock tampering detected");
    exit(1);
}
```

### Warum BIOS-Zeit?

| Angriff | OS-Zeit | BIOS-Zeit |
|---------|---------|-----------|
| `date --set` | ✓ Geändert | ✗ Unverändert |
| NTP Manipulation | ✓ Geändert | ✗ Unverändert |
| Script-basiert | ✓ Einfach | ✗ Braucht root + hwclock |

> **Pragmatik:** 99% der "Angreifer" kennen nur `date --set`.
> Wer BIOS manipulieren kann, kauft wahrscheinlich eher die Lizenz.

## Sicherheitsanalyse

| Komponente | Im Binary | Kritisch? | Anmerkung |
|------------|-----------|-----------|-----------|
| CA Private Key | ❌ NEIN | — | Bleibt beim Vendor |
| CA Public Key | ✓ (obfuscated) | Nein | Ist public, Obfuscation nur gegen RE |
| Hardware-Algo | ✓ (hidden) | Nein | Security by Obscurity als Extra |
| Salt-Werte | ✓ (hidden) | Nein | Ohne Salt kein gültiger Hash |
| Fingerprint-Check | ✓ | Nein | Öffentlicher Algorithmus (X.509 verify) |
| Lizenz-URL Schema | ✓ | Nein | Ohne gültige Lizenz nutzlos |

### Fazit

Selbst bei vollständigem Reverse Engineering des Binaries:
- **Ohne CA Private Key → Keine gültigen Lizenzen erstellbar**
- **Gestohlene Lizenzen → Hardware-Hash passt nicht**
- **URL bekannt → Download bringt nichts**

## Implementierung (TODO)

- [ ] `src/license/hardware_fingerprint.c` - Hardware-Hash mit Salt generieren
- [ ] `src/license/license_verify.c` - Lizenzprüfung beim Start
- [ ] `src/license/license_ca.h` - Eingebetteter CA Public Key (obfuscated)
- [ ] `src/license/license_renew.c` - Online-Renewal via Firmenname-Hash URL
- [ ] `src/license/time_check.c` - BIOS/RTC Zeitprüfung
- [ ] CLI: `--license-request` - CSR generieren
- [ ] CLI: `--license-status` - Status anzeigen
- [ ] CLI: `--getonline` - Auto-Renewal
- [ ] Config-Parser für `[license]` Section erweitern
- [ ] Grace Period Logik
- [ ] Warnungen bei baldiger Ablauf
- [ ] CA Fingerprint Validierung

## Notizen

- Private Key der License CA **niemals** im Code oder Repository!
- Für Tests: Separate Test-CA verwenden
- HSM empfohlen für Production License CA
- Backup der License CA kritisch!

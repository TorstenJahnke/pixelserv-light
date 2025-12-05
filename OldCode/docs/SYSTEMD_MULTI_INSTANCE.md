# TLSGate NX v3 - Systemd Multi-Instance Setup

## Übersicht

Diese Anleitung zeigt, wie man **mehrere Instanzen** von TLSGate NX mit systemd verwaltet.

### Service-Struktur

```
tlsgateNG.target (Master Target - startet alles)
├── tlsgateNG-poolgen.service (Keypool Generator)
├── tlsgateNG-ipv4-all.target (Alle IPv4 Instanzen)
│   ├── tlsgateNG-ipv4@01.service
│   ├── tlsgateNG-ipv4@02.service
│   ├── tlsgateNG-ipv4@03.service
│   ├── tlsgateNG-ipv4@04.service
│   └── tlsgateNG-ipv4@05.service
└── tlsgateNG-ipv6-all.target (Alle IPv6 Instanzen)
    ├── tlsgateNG-ipv6@01.service
    ├── tlsgateNG-ipv6@02.service
    ├── tlsgateNG-ipv6@03.service
    ├── tlsgateNG-ipv6@04.service
    └── tlsgateNG-ipv6@05.service
```

## Installation

### 1. Service-Dateien kopieren

```bash
# Template Services und Targets
sudo cp tlsgateNG-poolgen.service /etc/systemd/system/
sudo cp tlsgateNG-ipv4@.service /etc/systemd/system/
sudo cp tlsgateNG-ipv6@.service /etc/systemd/system/
sudo cp tlsgateNG-ipv4-all.target /etc/systemd/system/
sudo cp tlsgateNG-ipv6-all.target /etc/systemd/system/
sudo cp tlsgateNG.target /etc/systemd/system/
```

### 2. Config-Verzeichnis erstellen

```bash
sudo mkdir -p /etc/tlsgateNG
```

### 3. Instance-Konfigurationen erstellen

Für **jede Instanz** eine eigene `.env` Datei anlegen:

**IPv4 Instanz 01:** `/etc/tlsgateNG/ipv4-01.env`
```bash
LISTEN_IP=178.162.203.162
HTTP_PORT=80
HTTPS_PORT=443
AUTO_PORT=18080
```

**IPv4 Instanz 02:** `/etc/tlsgateNG/ipv4-02.env`
```bash
LISTEN_IP=178.162.203.163
HTTP_PORT=80
HTTPS_PORT=443
AUTO_PORT=18080
```

**IPv4 Instanz 03-05:** Analog mit weiteren IPs/Ports

**IPv6 Instanz 01:** `/etc/tlsgateNG/ipv6-01.env`
```bash
LISTEN_IP=2a00:c98:2050:a02a:4::162
HTTP_PORT=80
HTTPS_PORT=443
AUTO_PORT=18080
```

**IPv6 Instanz 02-05:** Analog

### 4. Beispiel-Configs kopieren

```bash
# Beispiele als Vorlage nutzen
sudo cp examples/ipv4-01.env /etc/tlsgateNG/
sudo cp examples/ipv4-02.env /etc/tlsgateNG/
sudo cp examples/ipv6-01.env /etc/tlsgateNG/

# Weitere manuell erstellen oder anpassen
```

### 5. systemd neu laden

```bash
sudo systemctl daemon-reload
```

## Verwendung

### Alle Services auf einmal verwalten

```bash
# Alles starten (Keygen + alle IPv4 + alle IPv6 Instanzen)
sudo systemctl start tlsgateNG.target

# Status aller Services anzeigen
sudo systemctl status tlsgateNG.target

# Alles stoppen
sudo systemctl stop tlsgateNG.target

# Autostart aktivieren
sudo systemctl enable tlsgateNG.target

# Alles neu starten
sudo systemctl restart tlsgateNG.target
```

### Nur IPv4 oder IPv6 Instanzen verwalten

```bash
# Nur alle IPv4 Instanzen starten
sudo systemctl start tlsgateNG-ipv4-all.target

# Nur alle IPv6 Instanzen starten
sudo systemctl start tlsgateNG-ipv6-all.target

# Status aller IPv4 Instanzen
sudo systemctl status 'tlsgateNG-ipv4@*'

# Status aller IPv6 Instanzen
sudo systemctl status 'tlsgateNG-ipv6@*'
```

### Einzelne Instanzen verwalten

```bash
# Einzelne IPv4 Instanz starten
sudo systemctl start tlsgateNG-ipv4@01.service

# Einzelne IPv6 Instanz stoppen
sudo systemctl stop tlsgateNG-ipv6@03.service

# Status einer Instanz
sudo systemctl status tlsgateNG-ipv4@02.service

# Logs einer Instanz
sudo journalctl -u tlsgateNG-ipv4@01.service -f
```

### Instanzen hinzufügen/entfernen

**Instanz hinzufügen:**

1. Config-Datei erstellen: `/etc/tlsgateNG/ipv4-06.env`
2. Target anpassen: `tlsgateNG-ipv4-all.target` → `Wants=` Zeile erweitern
3. `sudo systemctl daemon-reload`
4. `sudo systemctl start tlsgateNG-ipv4@06.service`

**Instanz entfernen:**

1. Service stoppen: `sudo systemctl stop tlsgateNG-ipv4@05.service`
2. Aus Target entfernen: `tlsgateNG-ipv4-all.target` editieren
3. `sudo systemctl daemon-reload`

## Start-Reihenfolge

```
1. tlsgateNG-poolgen.service (Keypool Generator)
         ↓
2. tlsgateNG-ipv4@01.service
   tlsgateNG-ipv4@02.service  (parallel)
   tlsgateNG-ipv4@03.service
   tlsgateNG-ipv4@04.service
   tlsgateNG-ipv4@05.service
         ↓
3. tlsgateNG-ipv6@01.service
   tlsgateNG-ipv6@02.service  (parallel)
   tlsgateNG-ipv6@03.service
   tlsgateNG-ipv6@04.service
   tlsgateNG-ipv6@05.service
```

## Konfigurationsoptionen

Jede Instanz kann individuell konfiguriert werden über die `.env` Datei:

### Verfügbare Variablen

```bash
# IP-Adresse (IPv4 oder IPv6)
LISTEN_IP=178.162.203.162

# HTTP Port (0 = deaktiviert)
HTTP_PORT=80

# HTTPS Port (0 = deaktiviert)
HTTPS_PORT=443

# AUTO Port (0 = deaktiviert)
AUTO_PORT=18080
```

### Beispiel: Nur HTTPS auf verschiedenen Ports

**IPv4 Instanz mit Port 8443:**
```bash
LISTEN_IP=178.162.203.162
HTTP_PORT=0
HTTPS_PORT=8443
AUTO_PORT=0
```

**IPv4 Instanz mit Port 9443:**
```bash
LISTEN_IP=178.162.203.162
HTTP_PORT=0
HTTPS_PORT=9443
AUTO_PORT=0
```

## Troubleshooting

### Logs anzeigen

```bash
# Alle Services
sudo journalctl -u 'tlsgateNG*' -f

# Nur IPv4 Instanzen
sudo journalctl -u 'tlsgateNG-ipv4@*' -f

# Nur Instanz 01
sudo journalctl -u tlsgateNG-ipv4@01.service -n 100 --no-pager
```

### Config prüfen

```bash
# Zeige geladene Config einer Instanz
sudo systemctl show tlsgateNG-ipv4@01.service | grep Environment
```

### Port-Konflikte

```bash
# Prüfe welche Ports belegt sind
sudo netstat -tulpn | grep tlsgateNG
sudo ss -tulpn | grep tlsgateNG
```

### Service-Status übersichtlich

```bash
# Baumstruktur aller Services
systemctl list-dependencies tlsgateNG.target

# Nur aktive Services
systemctl list-units 'tlsgateNG*' --state=active
```

## Vorteile dieser Lösung

✅ **Ein Befehl für alles** - `systemctl start tlsgateNG.target`
✅ **Individuelle Konfiguration** - Jede Instanz mit eigener IP/Ports
✅ **Flexible Verwaltung** - Einzeln, nach Gruppe, oder alle zusammen
✅ **Automatische Reihenfolge** - Keygen → IPv4 → IPv6
✅ **Einfaches Hinzufügen** - Neue Instanzen mit `.env` Datei
✅ **Übersichtliches Logging** - Pro Instanz eigener Identifier

## Performance-Tuning

### Paralleles Starten beschleunigen

Für schnelleren Start kann man die Default-Timeout-Werte anpassen:

```bash
# In /etc/systemd/system.conf
DefaultTimeoutStartSec=30s
DefaultTimeoutStopSec=15s
```

### Resource-Limits pro Instanz

Jede Instanz kann eigene Limits haben. Einfach in der Template-Datei anpassen:

```ini
# In tlsgateNG-ipv4@.service
LimitNOFILE=2048576
LimitNPROC=1024
```

## Sicherheit

Alle Services laufen mit:
- **User/Group:** root (drops zu tlsgateNG nach Port-Binding)
- **Capabilities:** Minimal nötig für Port-Binding + Shared Memory
- **IPC Isolation:** Deaktiviert für Shared Memory Zugriff
- **Filesystem:** Read-only außer CA-Verzeichnis

## Weiterführende Dokumentation

- README.md - Allgemeine Übersicht
- docs/MULTI_INSTANCE_SETUP.md - Performance-Optimierung
- docs/SINGLE_SERVER_MULTI_INSTANCE.md - Single-Server Setup

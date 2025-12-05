# TLSGate NG - Systemd Services

## Übersicht

| Datei | Beschreibung |
|-------|--------------|
| `tlsgateNG.target` | Gruppiert alle Services |
| `tlsgateNG-poolgen.service` | Poolgen HA Manager |
| `tlsgateNG-poolgen-primary.service` | Primary Poolgen |
| `tlsgateNG-poolgen-backup.service` | Backup Poolgen (Standby) |
| `tlsgateNGv4.service` | IPv4 TLS Worker |
| `tlsgateNGv6.service` | IPv6 TLS Worker |

## Installation

```bash
# Alle Services kopieren
cp *.service *.target /etc/systemd/system/

# Systemd neu laden
systemctl daemon-reload

# Autostart aktivieren
systemctl enable tlsgateNG.target
```

## Verwendung

```bash
# Alles starten
systemctl start tlsgateNG.target

# Alles stoppen
systemctl stop tlsgateNG.target

# Status
systemctl status tlsgateNG.target
```

## Poolgen HA

Der Poolgen läuft im High-Availability Modus:

1. **Start**: Primary wird aktiv, Backup wartet
2. **Primary Crash**: Backup übernimmt (< 5 Sekunden)
3. **Lock**: `/var/run/tlsgateNG/tlsgateNG-poolgen.lock`

```bash
# Poolgen Logs
journalctl -u tlsgateNG-poolgen-primary -u tlsgateNG-poolgen-backup -f
```

## Worker (DropRoot)

Die Worker starten als root, droppen nach Port-Binding zu `tlsgateNG`:

```bash
# Worker Logs
journalctl -u tlsgateNGv4 -u tlsgateNGv6 -f
```

## Konfiguration

```
/etc/tlsgateNG/poolgen/poolgen.conf   # Poolgen
/etc/tlsgateNG/tlsgateNG.conf         # Worker
```

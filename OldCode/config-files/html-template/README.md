# HTML Template Beispiele mit Timestamp

AI Template Generator kann diese Beispiele verwenden um `include/html_index.h` zu erstellen.

---

## ⚠️ WICHTIG: Template Requirements

**KRITISCH:** Templates MÜSSEN NULL-terminierte Strings sein!

```c
// ✅ RICHTIG (NULL-terminierter String)
unsigned char index_html[] = "<!DOCTYPE html>...";
unsigned int index_html_len = sizeof(index_html) - 1;

// ❌ FALSCH (rohes Hex-Array - Buffer Overrun!)
unsigned char index_html[] = {0x3c, 0x21, 0x44, ...};
```

**Grund:** `snprintf()` benötigt NULL-Terminator für sichere Timestamp-Substitution.

---

## Example 1: Komplett leer mit Timestamp

**Datei:** `example1_empty_timestamp.h`

**Was der Browser sieht:** Nur den Timestamp-Text

```
2025-11-08 14:23:45 UTC
```

**Code:**
```c
unsigned char index_html[] = "%s";
unsigned int index_html_len = sizeof(index_html) - 1;
```

**Verwendung:** Minimale Response, Stealth-Blocking, keine HTML-Struktur

---

## Example 2: Seite mit Text und Timestamp

**Datei:** `example2_text_and_timestamp.h`

**Was der Browser sieht:** Formatierte HTML-Seite mit Text

```
Zugriff verweigert
Diese Anfrage wurde aus Sicherheitsgründen blockiert.
Irgendwas und Text hier als Beispiel für AI-generierte Inhalte.
Zeitpunkt der Blockierung: 2025-11-08 14:23:45 UTC
```

**Code:**
```c
unsigned char index_html[] =
    "<!DOCTYPE html>\n"
    "<html>\n"
    "...\n"
    "        <p class=\"timestamp\">Zeitpunkt der Blockierung: %s</p>\n"
    "...\n"
    "</html>";
unsigned int index_html_len = sizeof(index_html) - 1;
```

**Verwendung:** AI-generierte Countermeasure-Seite mit Styling

---

## Timestamp Format

Der `%s` Placeholder wird ersetzt durch:

```
2025-11-08 14:23:45 UTC
```

Format: `YYYY-MM-DD HH:MM:SS UTC` (immer UTC, keine Zeitzone)

---

## Unterschied zwischen den Beispielen

| Aspekt | Example 1 | Example 2 |
|--------|-----------|-----------|
| **HTML-Struktur** | Keine | Vollständig |
| **Styling** | Kein CSS | Mit CSS |
| **Text** | Nur Timestamp | Text + Timestamp |
| **Größe** | 2 Bytes | ~800 Bytes |
| **Verwendung** | Stealth | Sichtbare Blockierung |
| **Fingerprint** | Minimal | Mehr Inhalt |

---

## Wie AI die Templates nutzt

### Schritt 1: Angriffsmuster erkennen

AI analysiert Request und erkennt Angriff (AdBlock, Malware, etc.)

### Schritt 2: Template generieren

Basierend auf Angriffsmuster:
- **Stealth-Modus** → Example 1 (minimal, unsichtbar)
- **Sichtbare Blockierung** → Example 2 (mit Text und Styling)

### Schritt 3: `include/html_index.h` schreiben

AI überschreibt die Datei mit generiertem Template:

```c
#ifndef INCLUDE_HTML_INDEX_H
#define INCLUDE_HTML_INDEX_H

unsigned char index_html[] =
    "... AI-generierter Inhalt ...";

unsigned int index_html_len = sizeof(index_html) - 1;

#endif
```

### Schritt 4: Binary bauen

```bash
make clean && make
```

Template ist jetzt im Binary kompiliert (SICHER!)

---

## Template ohne Timestamp

Falls kein Timestamp benötigt, `%s` weglassen:

```c
unsigned char index_html[] =
    "<!DOCTYPE html>\n"
    "<html><body>Access Denied</body></html>";
unsigned int index_html_len = sizeof(index_html) - 1;
```

Code behandelt das automatisch (snprintf kopiert einfach den String).

---

## Default-Zustand (NULL Template)

Standardmäßig ist `html_index.h` leer:

```c
unsigned char index_html[] = {0x00};
unsigned int index_html_len = 0;
```

**Bedeutung:**
- Keine statische Signatur
- Keine Erkennung durch AdBlock/Malware/Ransomware
- AI generiert Template bei Bedarf dynamisch

---

## Templates testen

```bash
# Beispiel nach html_index.h kopieren
cp examples/templates/example1_empty_timestamp.h include/html_index.h

# Build
make clean && make

# Server starten
./build/tlsgateNG -p 8080

# Testen
curl http://localhost:8080/
curl http://localhost:8080/index.html
curl http://localhost:8080/default.php
```

Alle URLs sollten das Template mit aktuellem Timestamp zurückgeben.

---

## Template für AI Generator anpassen

Der AI Generator muss nur:

1. **Datei schreiben:** `include/html_index.h`
2. **Format verwenden:** NULL-terminierter String
3. **Länge berechnen:** `sizeof(index_html) - 1`
4. **Optional:** `%s` für Timestamp einfügen

Dann:
```bash
make clean && make
```

Fertig!

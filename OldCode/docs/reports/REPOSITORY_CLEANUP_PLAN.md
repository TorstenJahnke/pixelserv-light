# TLSGateNX Repository Cleanup Plan
**Datum:** 2025-11-20
**Status:** Vorschlag zur Abstimmung

---

## Aktuelle Struktur-Analyse

### Root-Verzeichnis (15 lose Dateien)
```
TLSGateNXv3/
├── Makefile                                    ✅ Behalten
├── README.md                                   ✅ Behalten
├── CHANGELOG.md                                ✅ Behalten
├── LEGACY_CRYPTO_VERIFICATION_REPORT.md        ✅ Behalten
├── OPEN_ISSUES_AND_TODOS.md                    ✅ Behalten
├── verify_legacy_crypto.c                      ⚠️ Verschieben → tests/
├── verify_legacy_crypto (binary)               ⚠️ Verschieben → build/
├── second-level-tlds.dat                       ⚠️ Verschieben → docs/reference/
├── set-permissions.sh                          ⚠️ Verschieben → tools/
├── setup.sh                                    ⚠️ Verschieben → tools/
├── signal-2025-11-12-132732_002.png            ⚠️ Verschieben → docs/images/
├── valgrind-report.txt                         ⚠️ Verschieben → docs/analysis/
```

### Verzeichnisse

#### 1. OldCodeBase/ (1.1 MB)
**Inhalt:**
- Legacy pixelserv.c Code (8251 Zeilen)
- Alte Build-Guides, Dokumentationen
- Nicht mehr verwendeter Code

**Entscheidung:** ❌ **LÖSCHEN**
- Legacy-Code wird nicht mehr verwendet
- Neue Implementation in src/ ist vollständig
- Bei Bedarf aus Git-History wiederherstellbar

---

#### 2. powerdns/ (504 KB)
**Inhalt:**
- PowerDNS Recursor Scripts
- Lua-Module für DNS-Blocking
- PDNS-AI Tooling
- Separate Funktionalität (nicht TLSGateNX)

**Entscheidung:** ❌ **LÖSCHEN** (in eigenes Repo verschieben)
- Gehört nicht zu TLSGateNX
- Sollte eigenes Repository sein: `TLSGateNX-PowerDNS`
- Kann vor Löschung exportiert werden

---

#### 3. backup/ (2 KB)
**Inhalt:**
- CA-Statistiken (ca_statistics.txt)
- README.md

**Entscheidung:** ⚠️ **VERSCHIEBEN** → `docs/backup/`
- Kleine Dateien, nützliche Info
- Gehört zur Dokumentation

---

#### 4. build/ (1.2 MB)
**Inhalt:**
- Kompilierte Binaries (tlsgateNGv4, tlsgateNGv6, tlsgateNG-poolgen)

**Entscheidung:** ✅ **BEHALTEN**
- Wird von Makefile genutzt
- .gitignore sollte build/ ignorieren

---

#### 5. src/, include/, docs/, tests/, tools/, examples/
**Entscheidung:** ✅ **BEHALTEN**
- Kern der Codebase

---

## Vorgeschlagene Zielstruktur

```
TLSGateNXv3/
├── Makefile
├── README.md
├── CHANGELOG.md
├── LICENSE
├── .gitignore
│
├── src/                          # Source code
│   ├── cert/
│   ├── config/
│   ├── core/
│   ├── crypto/
│   ├── http/
│   ├── pki/
│   └── ...
│
├── include/                      # Header files
│
├── build/                        # Build artifacts (gitignored)
│   ├── tlsgateNGv4
│   ├── tlsgateNGv6
│   └── tlsgateNG-poolgen
│
├── docs/                         # Documentation
│   ├── README.md
│   ├── backup/                   # CA statistics
│   │   ├── README.md
│   │   └── ca_statistics.txt
│   ├── reference/                # Reference data
│   │   └── second-level-tlds.dat
│   ├── images/                   # Screenshots, diagrams
│   │   └── signal-2025-11-12-132732_002.png
│   ├── analysis/                 # Analysis reports
│   │   └── valgrind-report.txt
│   └── reports/                  # Verification reports
│       ├── LEGACY_CRYPTO_VERIFICATION_REPORT.md
│       └── OPEN_ISSUES_AND_TODOS.md
│
├── tests/                        # Test files
│   ├── verify_legacy_crypto.c
│   └── ...
│
├── tools/                        # Tools and scripts
│   ├── set-permissions.sh
│   ├── setup.sh
│   └── ...
│
└── examples/                     # Example configs

```

---

## Detaillierter Aufräum-Plan

### Phase 1: Backup erstellen ✅
```bash
# Git-Status sichern
git tag backup-before-cleanup-$(date +%Y%m%d)

# PowerDNS in eigenes Repo exportieren (optional)
# git subtree split -P powerdns -b powerdns-export
```

### Phase 2: Verzeichnisse löschen ❌
```bash
# OldCodeBase löschen (1.1 MB)
git rm -rf OldCodeBase/

# PowerDNS löschen (504 KB)
git rm -rf powerdns/
```

### Phase 3: Dateien verschieben ⚠️

#### Dokumentation
```bash
# Erstelle Dokumentations-Struktur
mkdir -p docs/backup
mkdir -p docs/reference
mkdir -p docs/images
mkdir -p docs/analysis
mkdir -p docs/reports

# Verschiebe Dateien
git mv backup/README.md docs/backup/
git mv backup/ca_statistics.txt docs/backup/
git rm -rf backup/

git mv second-level-tlds.dat docs/reference/
git mv signal-2025-11-12-132732_002.png docs/images/
git mv valgrind-report.txt docs/analysis/

git mv LEGACY_CRYPTO_VERIFICATION_REPORT.md docs/reports/
git mv OPEN_ISSUES_AND_TODOS.md docs/reports/
```

#### Tests
```bash
# Verschiebe Test-Files
git mv verify_legacy_crypto.c tests/
git mv verify_legacy_crypto build/
```

#### Tools
```bash
# Verschiebe Scripts
git mv set-permissions.sh tools/
git mv setup.sh tools/
```

### Phase 4: .gitignore anpassen
```bash
# Füge build/ zu .gitignore hinzu
echo "build/" >> .gitignore
echo "*.o" >> .gitignore
echo "*.a" >> .gitignore
```

### Phase 5: README.md aktualisieren
- Verzeichnisstruktur aktualisieren
- Pfade in Dokumentation anpassen
- Build-Instructions prüfen

---

## Auswirkungen

### Gelöschte Größe
- OldCodeBase: -1.1 MB
- powerdns: -504 KB
- **Total: -1.6 MB** (~60% kleiner)

### Vorteile
1. ✅ **Klarere Struktur** - Alles an seinem Platz
2. ✅ **Kleiner** - Nur relevanter Code
3. ✅ **Besser wartbar** - Keine Legacy-Verwirrung
4. ✅ **Professioneller** - Standard-Repository-Layout
5. ✅ **Schnellere Clones** - Weniger Ballast

### Risiken
- ⚠️ **Git-History:** OldCodeBase/powerdns bleiben in History (bis `git filter-branch`)
- ⚠️ **Links:** Dokumentations-Links müssen aktualisiert werden
- ⚠️ **Dependencies:** PowerDNS-Nutzer brauchen neues Repo

---

## Vorgeschlagene Commits

### Commit 1: Backup & Tag
```bash
git tag backup-before-cleanup-20251120
git push origin backup-before-cleanup-20251120
```

### Commit 2: Entferne Legacy-Code
```bash
git rm -rf OldCodeBase/ powerdns/
git commit -m "CLEANUP: Remove legacy code and PowerDNS (1.6 MB)

Removed:
- OldCodeBase/ (1.1 MB) - Legacy pixelserv code, replaced by src/
- powerdns/ (504 KB) - Separate project, should be own repository

Reason:
- OldCodeBase is completely replaced by new implementation
- powerdns is unrelated to TLSGateNX core functionality
- Both can be restored from git history if needed

Size reduction: -1.6 MB (-60%)
"
```

### Commit 3: Reorganisiere Dateien
```bash
# (Alle mv-Befehle von oben)
git commit -m "REFACTOR: Reorganize repository structure

Moved files to appropriate directories:
- Documentation → docs/
- Test files → tests/
- Scripts → tools/
- Build artifacts → build/

New structure:
- docs/backup/ - CA statistics
- docs/reference/ - Reference data (TLD lists)
- docs/images/ - Screenshots
- docs/analysis/ - Performance/security reports
- docs/reports/ - Verification reports
- tests/ - Test files and verification tools
- tools/ - Setup and utility scripts

Result: Professional repository layout
"
```

### Commit 4: Update .gitignore
```bash
git add .gitignore
git commit -m "BUILD: Add build/ to .gitignore

Added:
- build/ directory (binary artifacts)
- *.o (object files)
- *.a (static libraries)

Reason: Build artifacts should not be in version control
"
```

---

## Nächste Schritte

**Vor Ausführung:**
1. ✅ Backup-Tag erstellen
2. ✅ Plan mit Team abstimmen
3. ✅ Dokumentation auf neue Pfade prüfen
4. ✅ Optional: PowerDNS in eigenes Repo exportieren

**Nach Ausführung:**
1. ✅ README.md aktualisieren
2. ✅ Dokumentations-Links prüfen
3. ✅ CI/CD-Scripts anpassen (falls vorhanden)
4. ✅ Team informieren über neue Struktur

---

## Fragen zur Abstimmung

1. **OldCodeBase löschen?** (1.1 MB Legacy-Code)
   - ✅ Ja, löschen (aus Git-History wiederherstellbar)
   - ❌ Nein, behalten

2. **powerdns löschen?** (504 KB separates Projekt)
   - ✅ Ja, löschen (eigenes Repo erstellen)
   - ❌ Nein, behalten

3. **Dateien verschieben?** (Dokumentation, Tests, Tools)
   - ✅ Ja, nach neuem Schema organisieren
   - ❌ Nein, im Root lassen

4. **build/ zu .gitignore?**
   - ✅ Ja, Binaries nicht committen
   - ❌ Nein, Binaries committen

---

**Status:** Bereit zur Ausführung (mit Zustimmung)

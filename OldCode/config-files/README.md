# TLSGate NG Configuration Templates

## HTML Templates (Landing Pages)

Use `python3 tools/HTML2TimeStampH.py` to convert any HTML template to `include/html_index.h`:

### `index.html` - Full Professional Page ⭐ (RECOMMENDED)
- **Size:** 8 KB
- **Features:** Aviontex branding, 16384-bit RSA showcase, animations, full design
- **When to use:** Production, professional deployments
- **Command:**
  ```bash
  python3 tools/HTML2TimeStampH.py config-files/index.html
  ```

### `index-minimal.html` - Lightweight Clean Page
- **Size:** 500 bytes
- **Features:** Minimal design, fast loading, clean look
- **When to use:** Embedded systems, bandwidth-limited environments, testing
- **Command:**
  ```bash
  python3 tools/HTML2TimeStampH.py config-files/index-minimal.html
  ```

---

## Configuration Files

### `second-level-tlds.conf` - TLD Database
- **Purpose:** Maps complex domain structures (e.g., .co.uk, .gov.uk)
- **Format:** One domain per line
- **Example:** `.co.uk`, `.gov.uk`, `.com.au`
- **Used by:** Certificate generator for wildcard domain extraction
- **Auto-loaded:** Yes (unless `second_level_tld_file` set in main config)

### `silent-blocks.conf` - Blocked/Filtered Domains
- **Purpose:** List of domains to silently block (no response sent)
- **Format:** One domain per line
- **Example:** Ads, trackers, malware domains
- **Status:** Optional feature

### `benchmark.conf` - Performance Testing Config
- **Purpose:** Configuration preset for benchmark/stress testing
- **Used for:** Performance profiling, load testing
- **Status:** Development/testing only

---

## Quick Start

**Step 1: Choose a landing page**
```bash
# Professional (recommended):
python3 tools/HTML2TimeStampH.py config-files/index.html

# Or minimal/lightweight:
python3 tools/HTML2TimeStampH.py config-files/index-minimal.html
```

**Step 2: Compile**
```bash
make
```

**Step 3: Run**
```bash
./tlsgateNGv4
```

---

## Timestamp Support

Both HTML templates include a `%s` placeholder for dynamic timestamps.
This enables **anti-detection** by making each response unique.

At runtime in C:
```c
char timestamp[256];
time_t now = time(NULL);
snprintf(timestamp, sizeof(timestamp), "%s", ctime(&now));
```

---

## Customization

To create your own template:

1. Create `config-files/my-template.html`
2. Add your HTML content
3. Include `<div class="timestamp-footer">%s</div>` somewhere
4. Convert: `python3 tools/HTML2TimeStampH.py config-files/my-template.html`
5. Recompile: `make`

---

## File Summary Table

| File | Type | Purpose | Size | Auto-used? |
|------|------|---------|------|-----------|
| `index.html` | HTML | Professional landing page | 8 KB | ✓ |
| `index-minimal.html` | HTML | Lightweight landing page | 500 B | ✗ |
| `second-level-tlds.conf` | Config | TLD database | ~20 KB | ✓ |
| `silent-blocks.conf` | Config | Blocked domains | Variable | ✗ |
| `benchmark.conf` | Config | Test configuration | ~2 KB | ✗ |

---

## Usage Tips

- **Change landing page?** Just run `HTML2TimeStampH.py` with a different HTML file
- **Forgot which page is active?** Check `include/html_index.h` header comments
- **Want to edit the page?** Edit the `.html` file, then re-run the converter
- **Want timestamps removed?** Delete `<div class="timestamp-footer">%s</div>` from HTML before converting

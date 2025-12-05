#!/usr/bin/env python3
"""
Convert HTML to binary format for runtime loading
Optionally compresses with gzip for smaller files

Usage:
    python3 tools/html2bin.py config-files/index.html output/index.html.bin
    python3 tools/html2bin.py config-files/index.html output/index.html.bin --compress
"""

import sys
import gzip
from pathlib import Path

def html_to_bin(input_file, output_file, compress=False):
    """Convert HTML to binary"""

    input_path = Path(input_file)
    output_path = Path(output_file)

    # Read HTML
    with open(input_path, 'rb') as f:
        html_data = f.read()

    # Optionally compress
    if compress:
        html_data = gzip.compress(html_data, compresslevel=9)

    # Create output directory
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write binary
    with open(output_path, 'wb') as f:
        f.write(html_data)

    orig_size = input_path.stat().st_size
    final_size = output_path.stat().st_size

    print(f"✅ Conversion successful:")
    print(f"   Input:  {input_file} ({orig_size:,} bytes)")
    print(f"   Output: {output_file} ({final_size:,} bytes)")

    if compress:
        ratio = (1 - final_size/orig_size) * 100
        print(f"   Compression: {ratio:.1f}% smaller (gzip)")

    return True

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    compress = '--compress' in sys.argv

    try:
        html_to_bin(input_file, output_file, compress)
    except Exception as e:
        print(f"❌ ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()

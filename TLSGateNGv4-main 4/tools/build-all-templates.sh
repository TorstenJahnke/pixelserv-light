#!/bin/bash
# build-all-templates.sh - Build all template variants

set -e

echo "Building all template variants..."
echo ""

for tpl in blank zero minimal default; do
    echo "╔════════════════════════════════════════╗"
    echo "║  Building template: $tpl"
    echo "╚════════════════════════════════════════╝"

    make clean > /dev/null 2>&1
    make TEMPLATE=$tpl

    cp build/tlsgateNG build/tlsgateNG-$tpl
    sha256sum build/tlsgateNG-$tpl > build/tlsgateNG-$tpl.sha256

    echo "✅ tlsgateNG-$tpl"
    echo ""
done

echo "╔════════════════════════════════════════╗"
echo "║  Summary                               ║"
echo "╚════════════════════════════════════════╝"
echo ""
ls -lh build/tlsgateNG-* | grep -v sha256
echo ""
echo "✅ All template variants built successfully!"
echo ""
echo "Checksums:"
cat build/*.sha256

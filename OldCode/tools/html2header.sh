#!/bin/bash
# html2header.sh - Convert HTML template to C header file

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <input.html> <output.h> [array_name]"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"
ARRAY_NAME="${3:-index_html}"

if [ ! -f "$INPUT" ]; then
    echo "ERROR: Input file not found: $INPUT"
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
FILE_SIZE=$(wc -c < "$INPUT")
GUARD=$(echo "$OUTPUT" | tr '[:lower:]/' '[:upper:]_' | sed 's/[^A-Z0-9_]/_/g')

# Header
{
    echo "/* Auto-generated from: $INPUT */"
    echo ""
    echo "#ifndef ${GUARD}"
    echo "#define ${GUARD}"
    echo ""
    echo "unsigned char ${ARRAY_NAME}[] = {"
} > "$OUTPUT"

# Convert bytes
if [ $FILE_SIZE -gt 0 ]; then
    od -An -tx1 -v "$INPUT" | while read -r line; do
        for byte in $line; do
            echo -n "  0x$byte,"
        done
        echo ""
    done | sed '$ s/,$//' >> "$OUTPUT"
fi

# Footer
{
    echo ""
    echo "};"
    echo "unsigned int ${ARRAY_NAME}_len = $FILE_SIZE;"
    echo ""
    echo "#endif /* ${GUARD} */"
} >> "$OUTPUT"

echo "✅ $OUTPUT ($FILE_SIZE bytes)"

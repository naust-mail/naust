#!/usr/bin/env bash
#
# Temporary script to compile all HTML templates into a single index.html file.
# This replaces {% include "template.html" %} statements with actual template content.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATES_DIR="$SCRIPT_DIR/templates"
BASE_TEMPLATE="$TEMPLATES_DIR/index.html"
OUTPUT_FILE="$SCRIPT_DIR/compiled_index.html"

echo "======================================================================"
echo "Template Compiler"
echo "======================================================================"
echo "Base template: $BASE_TEMPLATE"
echo "Output file:   $OUTPUT_FILE"
echo ""

# Check if base template exists
if [ ! -f "$BASE_TEMPLATE" ]; then
    echo "Error: Base template not found: $BASE_TEMPLATE"
    exit 1
fi

# Process the template
echo "Processing includes..."

# Read base template and process line by line
while IFS= read -r line; do
    # Check if line contains {% include "..." %} or {% include '...' %}
    if echo "$line" | grep -q '{%[[:space:]]*include[[:space:]]'; then
        # Extract template name
        template_name=$(echo "$line" | sed -n "s/.*{%[[:space:]]*include[[:space:]]*[\"']\([^\"']*\)[\"'].*%}.*/\1/p")
        template_path="$TEMPLATES_DIR/$template_name"

        if [ -f "$template_path" ]; then
            echo "  ✓ Including: $template_name" >&2
            # Output the template content
            cat "$template_path"
        else
            echo "  ✗ Warning: Template not found: $template_name" >&2
            # Output a comment instead
            echo "<!-- Template not found: $template_name -->"
        fi
    else
        # Output the line as-is
        echo "$line"
    fi
done < "$BASE_TEMPLATE" > "$OUTPUT_FILE"

echo "" >&2
echo "======================================================================" >&2
echo "✓ Compilation complete!" >&2
echo "Output file: $OUTPUT_FILE" >&2
echo "Output size: $(wc -c < "$OUTPUT_FILE") bytes" >&2
echo "======================================================================" >&2

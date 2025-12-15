#!/bin/bash
# TrapNinja Cleanup Script
# Removes redundant files from the codebase

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${YELLOW}TrapNinja Code Cleanup${NC}"
echo "========================"
echo ""

# Files to remove
FILES_TO_REMOVE=(
    "trapninja/ha.py"
    "trapninja/metrics_queue_enhancement.py"
    "trapninja/cli/README.md"
    "trapninja/.DS_Store"
    ".DS_Store"
)

# Track what was removed
removed_count=0

for file in "${FILES_TO_REMOVE[@]}"; do
    full_path="${SCRIPT_DIR}/${file}"
    if [ -f "$full_path" ]; then
        echo -e "Removing: ${file}"
        rm -f "$full_path"
        if [ $? -eq 0 ]; then
            echo -e "  ${GREEN}✓ Removed${NC}"
            ((removed_count++))
        else
            echo -e "  ${RED}✗ Failed to remove${NC}"
        fi
    else
        echo -e "Skipping: ${file} ${YELLOW}(not found)${NC}"
    fi
done

echo ""
echo -e "${GREEN}Cleanup complete!${NC}"
echo "Removed ${removed_count} file(s)"
echo ""
echo "Remaining structure:"
echo "==================="
find "${SCRIPT_DIR}/trapninja" -type f -name "*.py" | sort | head -50

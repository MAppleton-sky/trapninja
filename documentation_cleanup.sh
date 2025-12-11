#!/bin/bash
# Documentation Cleanup Script
# Removes redundant documentation files that have been consolidated

echo "TrapNinja Documentation Cleanup"
echo "================================"
echo ""

# Files to remove (consolidated into other documents)
FILES_TO_REMOVE=(
    "documentation/CLEANUP_REPORT.md"
    "documentation/REFACTORED_ARCHITECTURE.md"
    "documentation/PACKET_DUPLICATION_FIX.md"
    "documentation/HA_FORWARDING_FIX.md"
    "documentation/fixes/PACKET_RECAPTURE_LOOP_FIX.md"
    "trapninja/cli/README.md"
)

# Show what will be removed
echo "The following files have been consolidated and will be removed:"
echo ""
for file in "${FILES_TO_REMOVE[@]}"; do
    if [ -f "$file" ]; then
        echo "  - $file"
    else
        echo "  - $file (not found)"
    fi
done

echo ""
echo "These files have been consolidated into:"
echo "  - documentation/README.md (index)"
echo "  - documentation/ARCHITECTURE.md (architecture)"
echo "  - documentation/CLI.md (CLI reference)"
echo "  - documentation/HA.md (HA guide)"
echo "  - documentation/TROUBLESHOOTING.md (issues & fixes)"
echo ""

# Ask for confirmation
read -p "Proceed with cleanup? (y/N) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Removing files..."
    
    for file in "${FILES_TO_REMOVE[@]}"; do
        if [ -f "$file" ]; then
            rm -v "$file"
        fi
    done
    
    # Remove empty fixes directory
    if [ -d "documentation/fixes" ]; then
        rmdir -v "documentation/fixes" 2>/dev/null || echo "Note: documentation/fixes/ not empty or already removed"
    fi
    
    echo ""
    echo "Cleanup complete!"
    echo ""
    echo "New documentation structure:"
    ls -la documentation/
    echo ""
    echo "Suggested git commands:"
    echo "  git add -A documentation/"
    echo "  git add -A trapninja/cli/"
    echo "  git commit -m 'docs: consolidate documentation, remove redundant files'"
else
    echo "Cleanup cancelled."
fi

#!/bin/bash

# NEW Phase: Design components

echo "=== PQVPN NEW Phase ==="
echo "Design new components or changes based on ideas."
echo ""

mkdir -p docs/design

read -p "Enter design document name (e.g., feature-name): " name
if [ -n "$name" ]; then
    file="docs/design/${name}.md"
    if [ ! -f "$file" ]; then
        cat > "$file" << EOF
# Design: $name

## Overview

## Requirements

## Architecture

## Implementation Plan

## Security Considerations

## Testing Plan
EOF
        echo "Created design template at $file"
        echo "Edit it with your design details."
    else
        echo "Design file already exists: $file"
    fi
fi

echo "Update docs/ARCHITECTURE.md if needed."
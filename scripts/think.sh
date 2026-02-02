#!/bin/bash

# THINK Phase: Brainstorm ideas

echo "=== PQVPN THINK Phase ==="
echo "Brainstorm new feature ideas or improvements."
echo ""

echo "Current roadmap items:"
cat docs/ROADMAP.md | grep -A 5 "##"
echo ""

echo "Recent ideas from docs/ideas.md:"
if [ -f docs/ideas.md ]; then
    tail -10 docs/ideas.md
else
    echo "No ideas.md yet."
fi
echo ""

read -p "Enter new idea (or press Enter to skip): " idea
if [ -n "$idea" ]; then
    echo "$(date): $idea" >> docs/ideas.md
    echo "Idea logged to docs/ideas.md"
fi

echo "Consider creating a GitHub issue for detailed tracking."
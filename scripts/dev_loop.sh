#!/bin/bash

# PQVPN Development Loop Script
# Automates the development cycle as much as possible

set -e

LOG_FILE="logs/dev_loop_$(date +%Y-%m-%d).log"
mkdir -p logs

log() {
    echo "$(date): $1" | tee -a "$LOG_FILE"
}

log "Starting PQVPN Development Loop"

# Function to prompt user
prompt() {
    echo "$1"
    read -p "Press Enter to continue..."
}

# 1. THINK
log "Phase 1: THINK"
echo "Review ROADMAP.md, open issues, and brainstorm ideas."
echo "Document new ideas in docs/ideas.md or create GitHub issues."
prompt "Have you documented your ideas?"

# 2. NEW
log "Phase 2: NEW"
echo "Design new components or changes based on ideas."
echo "Create design docs in docs/design/ if needed."
prompt "Have you completed the design?"

# 3. IMPLEMENT
log "Phase 3: IMPLEMENT"
echo "Implement the code changes."
echo "Follow coding standards and commit changes."
prompt "Have you implemented the changes?"

# 4. SECURITY-CHECKS
log "Phase 4: SECURITY-CHECKS"
echo "Running security audits..."
./scripts/security_checks.sh

# 5. TESTS
log "Phase 5: TESTS"
echo "Writing and running automated tests..."
./scripts/run_tests.sh

# 6. TEST
log "Phase 6: TEST"
echo "Perform manual testing and validation."
echo "Refer to docs/manual_test_checklist.md"
prompt "Have you completed manual testing?"

log "Development loop completed successfully."
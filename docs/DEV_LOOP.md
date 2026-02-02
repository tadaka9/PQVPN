# Development Loop

This document outlines the structured development loop for the PQVPN project. The loop is designed to ensure thorough, secure, and tested development of new features and improvements.

## Cycle Overview

1. **THINK** - Brainstorm and document new feature ideas or improvements.
2. **NEW** - Design new components or changes based on the ideas.
3. **IMPLEMENT** - Code the changes.
4. **SECURITY-CHECKS** - Run security audits and vulnerability scans.
5. **TESTS** - Write and run automated unit and integration tests.
6. **TEST** - Perform manual testing and validation.

## Automation

As much as possible, the loop is automated using scripts and CI/CD pipelines.

- **Local Automation**: Use `scripts/dev_loop.sh` to guide through the loop locally.
- **CI/CD Integration**: GitHub Actions workflows handle automated checks on pushes and PRs.
- **Repeatability**: The loop is designed for ongoing development, with logs and checklists to track progress.

## Detailed Steps

### 1. THINK

**Objective**: Generate and document ideas.

**Actions**:
- Review ROADMAP.md and open issues.
- Brainstorm new features or improvements.
- Document ideas in `docs/ideas.md` or create GitHub issues.

**Automation**:
- Run `scripts/think.sh` to prompt for ideas and log them.

### 2. NEW

**Objective**: Design the changes.

**Actions**:
- Create design documents in `docs/design/`.
- Update architecture docs if needed.
- Plan implementation steps.

**Automation**:
- Run `scripts/new.sh` to generate design templates.

### 3. IMPLEMENT

**Objective**: Code the changes.

**Actions**:
- Implement the designed changes.
- Follow coding standards (ruff).
- Commit changes with descriptive messages.

**Automation**: None (manual coding).

### 4. SECURITY-CHECKS

**Objective**: Ensure security.

**Actions**:
- Run static analysis, vulnerability scans.
- Review threat model.

**Automation**:
- Local: Run `scripts/security_checks.sh`.
- CI: Workflows for CodeQL, pip-audit, scorecard, etc.

### 5. TESTS

**Objective**: Automated testing.

**Actions**:
- Write unit and integration tests.
- Run tests locally and in CI.

**Automation**:
- Local: Run `scripts/run_tests.sh` (pytest).
- CI: CI workflow runs pytest.

### 6. TEST

**Objective**: Manual validation.

**Actions**:
- Perform manual testing (e.g., run CLI, check outputs).
- Validate against requirements.
- Update checklists.

**Automation**: Checklist in `docs/manual_test_checklist.md`.

## Usage

To run the full loop locally:

```bash
./scripts/dev_loop.sh
```

This script will guide you through each phase, running automated parts and prompting for manual steps.

## Integration with Existing Structure

- Builds on existing CI workflows.
- Uses `docs/` for documentation.
- Adds scripts in `scripts/`.
- Leverages pyproject.toml for dependencies.

## Repeatability

- Each run of the loop logs progress in `logs/dev_loop_YYYY-MM-DD.log`.
- Checklists ensure nothing is missed.
- CI ensures consistency across environments.
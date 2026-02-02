# Manual Testing Checklist

Use this checklist for the TEST phase of the development loop.

## General

- [ ] Code compiles/runs without errors
- [ ] No obvious bugs in logs
- [ ] Performance is acceptable

## CLI Functionality

- [ ] `pqvpn --help` works
- [ ] `pqvpn version` returns correct version
- [ ] `pqvpn doctor` passes
- [ ] `pqvpn run --bind 127.0.0.1 --port 51820` starts without errors

## Specific Feature Testing

*(Add feature-specific tests here based on what was implemented)*

- [ ] Test new feature X
- [ ] Validate against requirements from design doc

## Security Validation

- [ ] No sensitive data logged
- [ ] Inputs are validated
- [ ] Outputs are sanitized

## Integration

- [ ] Works with existing components
- [ ] No regressions in other features

## Edge Cases

- [ ] Test with invalid inputs
- [ ] Test network failures (if applicable)
- [ ] Test resource limits

## Documentation

- [ ] README updated if needed
- [ ] Code comments added
- [ ] Design docs updated

After completing, mark items and note any issues in the dev loop log.
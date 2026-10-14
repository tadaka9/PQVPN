# Contributing to PQVPN

Thank you for your interest in PQVPN. The project is an experimental public
alpha with native C++23 node, GUI and packaging code. Focused implementation,
platform testing, documentation and security review are welcome.

## Before contributing

- Search existing issues and pull requests to avoid duplicate work.
- Open an issue before making a large change or choosing a new dependency.
- Keep each contribution focused on one clearly described change.
- Do not include credentials, private keys, personal data, or generated build
  output in a commit.

Security vulnerabilities must be reported privately as described in
[SECURITY.md](SECURITY.md).

## Development workflow

1. Develop on `future`. External contributors can create a branch in their fork from `future`.
2. Make the smallest change that solves the stated problem.
3. Add or update tests and documentation when applicable.
4. Verify the changed files locally.
5. Open a pull request into `main` from `future` (or into `future` from an external fork) explaining what changed, why it changed, and how it was
   validated.

Use the build and test commands in the project [README](README.md). Every pull
request must keep the affected native targets and hardening checks green.

## Commit and pull request guidance

- Use short, action-oriented commit messages.
- Keep formatting changes separate from behavioral changes where practical.
- Link related issues in the pull request description.
- Call out security, compatibility, or migration implications explicitly.

By contributing, you agree that your contribution is licensed under the
project's [MIT License](LICENSE).

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)

## Branch workflow

Develop and validate changes on `future`, then merge them into protected `main` through a pull request after required checks pass. Keep these two branches; synchronize `future` with `main` after integration.

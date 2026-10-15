# Branch policy: development and stable releases

PQVPN maintains exactly two permanent branches:

- **`future`** is the active working branch. Development, testing, integration,
  and **experimental beta prereleases** originate here.
- **`main`** is the protected stable-release branch. Promote changes from
  `future` to `main` only through reviewed pull requests after all required
  CI and security checks pass.

## Working cycle

1. Work on `future`; run the full Windows, macOS, Linux and security matrix.
   Any temporary topic branches must be merged back and removed.
2. Experimental betas get new, immutable `v<version>` tags only after a
   successful exact-commit CI on `future`. The tag CI is run separately, and
   all five native candidate artifact groups must be present before publication
   by the experimental prerelease publisher.
3. Promoting into `main` requires a green PR and an explicit merge. Do not
   merge `future` automatically on every push.
4. A stable release must originate from the protected `main` history and
   satisfy all mandatory **native functional qualification, trusted signature,
   exact-commit provenance, and package-lifecycle** requirements. Do not
   relabel experimental unsigned betas as stable.

The existing published `v0.0.9-10152026-David0-beta-OTA` prerelease is
retained at its **historical** exact commit on `main`; moving it or rewriting
release history is not permitted. This policy controls **future** releases.

The beta-promotion workflow listens only to successful `future` builds, and
the beta publisher rejects a tag whose source commit is not in `future`
history. Main has no automatic beta-tag or experimental publishing push hook.

Native release qualification is not yet complete for all 13 targets; until
it is, stable publication must remain blocked rather than weakened.

# Clean-room boundary

This repository is a new implementation licensed under GPL-3.0-or-later.

Implementers may use only:

- the factual protocol specification in this directory;
- sanitized byte vectors supplied in the private validation directory;
- Home Assistant's official developer documentation;
- behavior observed on hardware owned by the project maintainer.

Implementers must not read, copy, translate, or adapt:

- `../ha-352-airpurifier`;
- `../ha-352-upstream-pr`;
- the upstream repository or its Git history;
- source files, diffs, prose, translations, tests, or image assets from either
  legacy repository.

Facts such as packet layouts, numeric command identifiers, checksums, state
offsets, and device behavior may be implemented independently. Names,
structure, comments, wording, and control flow must be newly authored.

No implementer may run Git commands. The primary reviewer owns history,
commits, publishing, deployment, and the final license/provenance review.


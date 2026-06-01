# @enfinitos/sdk-auditor-py

EnfinitOS auditor-py SDK. Part of the EnfinitOS developer platform —
governed execution infrastructure for screens and substrates.

## Status

Preview. Tagged `v0.0.1-preview` for the public-source release. Stable
v0.x boundaries land alongside the EnfinitOS platform launch in
April 2027.

## Install

```
# npm / pnpm / yarn (for *-ts SDKs)
pnpm add @enfinitos/sdk-auditor-py

# pip (for *-py SDKs)
pip install enfinitos-auditor-py

# go (for *-go modules)
go get github.com/enfinitos/sdk-auditor-py
```

(Adjust to whichever package manager applies — not every SDK ships
to every registry.)

## Docs

- Platform docs: https://docs.enfinitos.com
- Developer hub: https://enfinitos.com/developers
- API reference: https://docs.enfinitos.com/api-reference/openapi

## Licence

MIT. See [LICENSE](./LICENSE).

## Reporting issues

File issues at https://github.com/enfinitos/sdk-auditor-py/issues.
Security disclosures: security@enfinitos.com.

## Source

This repository tracks the SDK source extracted from the EnfinitOS
monorepo (`packages/sdks/auditor-py/`). Upstream changes land here via
`git subtree push`; PRs against this public repo are reviewed and
merged back into the monorepo.

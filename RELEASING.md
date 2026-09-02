# Releasing and publishing

Versioning and changelogs are automated with
[release-please](https://github.com/googleapis/release-please). Publishing to
npm is wired but **switched off** until someone deliberately turns it on — see
[Publishing to npm](#publishing-to-npm).

## How a release happens

1. **Land conventional commits on `main`.** The commit type decides the bump:

   | Commit | Bump (pre-1.0) | Changelog section |
   | --- | --- | --- |
   | `fix:` | patch — `0.1.0` → `0.1.1` | Bug Fixes |
   | `feat:` | minor — `0.1.0` → `0.2.0` | Features |
   | `feat!:` / `BREAKING CHANGE:` | minor while `0.x` | Features + `⚠ BREAKING` |
   | `chore:`, `ci:`, `test:` | none | hidden |

   While the package is `0.x`, `bump-minor-pre-major` keeps a breaking change at
   a minor bump rather than jumping to `1.0.0`. Cutting `1.0.0` is a deliberate
   act — see below.

2. **release-please opens a release PR** titled `chore(main): release …`. It
   accumulates every unreleased commit, writes `CHANGELOG.md`, and bumps
   `package.json` and `.release-please-manifest.json`. It keeps the PR updated as
   more commits land; you do not rebase or edit it by hand.

3. **Merge the release PR.** That tags `vX.Y.Z` and publishes a GitHub release.

4. **The publish workflow fires** on that release — and currently skips, loudly,
   until the prerequisites below are met.

### Cutting 1.0.0

Set the floor explicitly rather than letting a commit type do it:

```bash
git commit --allow-empty -m "chore: release 1.0.0" -m "Release-As: 1.0.0"
```

## Publishing to npm

Publishing uses **npm trusted publishing (OIDC)** — no long-lived `NPM_TOKEN`
lives in this repo. Each run mints a short-lived credential from GitHub's OIDC
provider, and npm attaches [provenance](https://docs.npmjs.com/generating-provenance-statements)
automatically. A leaked repo secret cannot publish this package, because there
is no repo secret.

`publish.yml` is already written for it. What remains are decisions and a
one-time bootstrap.

### 1. Decide the package is publishable

`package.json` currently carries:

```json
{ "private": true, "license": "UNLICENSED" }
```

`private: true` is npm's hard block on publishing, and the workflow refuses to
publish while it is set. Removing it means this code goes to a registry, so
settle the licence in the same change — `UNLICENSED` is right for a package that
stays internal and wrong for one on the public registry. Pick a real SPDX
identifier (`MIT`, `Apache-2.0`, …), or keep `UNLICENSED` and publish privately
to a paid npm org.

### 2. Own the `@socket0` scope

A scoped name can only be published by someone with rights to the scope:

```bash
npm org ls socket0
npm access ls-packages @socket0
```

If the scope is not yours, claim it or rename the package. **Do not publish
under a scope you do not control.**

### 3. Choose public or restricted

Scoped packages default to **restricted**. For a public package add:

```json
"publishConfig": { "access": "public" }
```

### 4. Bootstrap the first version by hand

This is the one genuinely awkward step, and it is a limitation of npm rather
than of this setup: **a trusted publisher can only be configured on a package
that already exists.** npm requires the name to be taken before it will bind a
publisher to it, which stops someone pre-claiming a trusted publisher on a name
they do not own. So the first release cannot come from OIDC.

Publish `0.1.0` once, from your own machine, with your own npm login:

```bash
npm login                 # your account, 2FA as normal
npm run check             # typecheck, lint, tests, 100% coverage
npm pack --dry-run        # confirm exactly what ships
npm publish               # prepack rebuilds dist/ first
```

### 5. Bind the trusted publisher

Then hand publishing to CI and never use a token again — either in the npm web
UI (Package → Settings → Trusted Publisher) or from the CLI:

```bash
npm trust github @socket0/vault-sdk \
  --repo socketzero/vault-sdk \
  --file publish.yml \
  --allow-publish

npm trust list @socket0/vault-sdk    # confirm it bound
```

The `--file` value is the **workflow filename only**, not a path, and it must
match `.github/workflows/publish.yml`. Renaming that file breaks publishing
until the trusted publisher is updated — `npm trust revoke @socket0/vault-sdk
--id <id>` and re-add.

If you add `environment:` to the publish job, the same environment name must be
set on the trusted publisher, or npm rejects the OIDC token.

### 6. Remove `private` and let CI take over

With the publisher bound, drop `"private": true`, merge, and every subsequent
release publishes itself when its release PR is merged.

### Requirements the workflow already handles

- **npm CLI ≥ 11.5.1** — Node 22 ships an older npm, so the workflow installs a
  new enough CLI before publishing.
- **Node ≥ 22.14.0** — satisfied by `node-version: "22"`.
- **`id-token: write`** — granted at the workflow level; without it the OIDC
  token cannot be minted.

### Publishing by hand later

```bash
npm run check
npm pack --dry-run
npm publish
```

`npm pack --dry-run` is worth the ten seconds: `files` in `package.json` ships
`dist`, `bin` and `src` while excluding tests and fixtures, and that list is
easy to break silently.

## What the automation does not do

- **It does not run the security review.** `npm run check` enforces types, lint
  and 100% coverage; it does not re-derive the guarantees in `src/bundle/reader.ts`.
  A change to the bundle reader or the envelope deserves a human read.
- **It does not gate on a vulnerability scan.** There are no runtime
  dependencies to scan today; that stops being true the moment one is added.

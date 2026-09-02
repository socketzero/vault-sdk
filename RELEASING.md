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

The package ships as `@socket0/vault-sdk`. Four things must be true before a
release can publish, and none of them are decisions this repo should make on
your behalf.

### 1. Decide the package is publishable

`package.json` currently carries:

```json
{ "private": true, "license": "UNLICENSED" }
```

`private: true` is npm's hard block on publishing. Removing it means this code
is going to a registry, so settle the licence in the same change — `UNLICENSED`
is right for a package that stays internal, and wrong for one on the public
registry. Pick a real SPDX identifier (`MIT`, `Apache-2.0`, …) or keep it
`UNLICENSED` and publish privately (paid npm scope).

### 2. Own the `@socket0` scope

A scoped name can only be published by someone with rights to the scope:

```bash
npm org ls socket0            # who is in the org
npm access ls-packages @socket0
```

If the scope is not yours, either claim it or rename the package. **Do not
publish under a scope you do not control** — a name someone else owns is a
supply-chain problem waiting to happen.

### 3. Choose public or private on the registry

Scoped packages default to **restricted**. Add to `package.json`:

```json
"publishConfig": { "access": "public" }
```

…for a public package. Omit it (and keep a paid npm org) for a private one.

### 4. Add the `NPM_TOKEN` secret

Create an **automation** token on npm (it bypasses 2FA prompts, which is what
CI needs), then:

```bash
gh secret set NPM_TOKEN --repo socketzero/vault-sdk   # paste at the prompt
```

Grant it write access to the `@socket0` scope only — not a full-account token.

Once all four hold, merging a release PR publishes automatically with
[provenance](https://docs.npmjs.com/generating-provenance-statements) attached,
after `npm run check` passes.

### Publishing by hand

```bash
npm run check          # typecheck, lint, tests, 100% coverage gate
npm pack --dry-run     # inspect exactly what ships
npm publish            # prepack rebuilds dist/ first
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

# Changelog

## [0.3.1](https://github.com/socketzero/vault-sdk/compare/v0.3.0...v0.3.1) (2026-09-02)


### Performance

* strip comments from the published JS, keep them in the declarations ([98fdefb](https://github.com/socketzero/vault-sdk/commit/98fdefbf18d00053a6d7b44a34fa832fec639925))

## [0.3.0](https://github.com/socketzero/vault-sdk/compare/v0.2.2...v0.3.0) (2026-09-02)


### ⚠ BREAKING CHANGES

* bundles written by earlier builds are not readable, and their envelopes cannot be opened, because the identity bound into every AAD changed. Nothing had shipped on this format.

### Features

* bind the connection UUID, drop the shard from the format ([53d1278](https://github.com/socketzero/vault-sdk/commit/53d12789fb2d42b23258f283fafd5a4a9d482c05))


### Bug Fixes

* **ci:** update the consumer check for the new AAD, and de-flake the bench gate ([eff080d](https://github.com/socketzero/vault-sdk/commit/eff080da594d1f6e5fd8649707abc47a8317abf6))
* **test:** make the damaged-bucket corruption actually corrupt ([2dc9ea7](https://github.com/socketzero/vault-sdk/commit/2dc9ea7305861b2ae07060d51bd556bdc59e82f7))


### Documentation

* badge row, and a section that earns the zero-dependency one ([eb9d052](https://github.com/socketzero/vault-sdk/commit/eb9d0521856d4e9e39446713e7546c9467323ab5))
* drop shard from the README and link npm, source and the playground ([6d5d335](https://github.com/socketzero/vault-sdk/commit/6d5d335a46d64b8245ba52ec97decf2171c65f74))
* show the playground in the README ([1fcb7ee](https://github.com/socketzero/vault-sdk/commit/1fcb7ee7aac1aeffd6dd91dd9fbbdf7f3fe14f25))

## [0.2.2](https://github.com/socketzero/vault-sdk/compare/v0.2.1...v0.2.2) (2026-09-02)


### Build

* make the package publishable under MIT ([f44271d](https://github.com/socketzero/vault-sdk/commit/f44271d7e6e0b9f26a8c377f46e5760c7e9bce25))

## [0.2.1](https://github.com/socketzero/vault-sdk/compare/v0.2.0...v0.2.1) (2026-09-02)


### Bug Fixes

* **ci:** publish from the release-please workflow, not an on:release one ([033a1da](https://github.com/socketzero/vault-sdk/commit/033a1da3d88b34fce536e62b6836dafb89e97063))

## [0.2.0](https://github.com/socketzero/vault-sdk/compare/v0.1.0...v0.2.0) (2026-09-02)


### Features

* implement the vault SDK and integrate the modules ([a6dbd3c](https://github.com/socketzero/vault-sdk/commit/a6dbd3c843e2097c3bdea4d0d8e05656df55349b))
* integrate the vault SDK fixes and land rotateGroup on the surface ([88ece88](https://github.com/socketzero/vault-sdk/commit/88ece88bf52e15938bc9716933e680dcb76f8d7c))
* **tools:** bundle inspection, s0bundle CLI, e2e lifecycle and tamper tests ([69f782d](https://github.com/socketzero/vault-sdk/commit/69f782d35c3c34d92522de91d27b8d32be5f525a))


### Bug Fixes

* **envelope:** contain the whole derive path in the failure taxonomy ([a6a7af9](https://github.com/socketzero/vault-sdk/commit/a6a7af9352bd102c281566414447910e702510f4))
* **reader:** refuse a bundle whose writable slot aliases anything ([f19b499](https://github.com/socketzero/vault-sdk/commit/f19b499ee9ceb51ecf57630ae98f452193a84c9c))
* **writer:** refuse a connection whose shard differs from the header ([870b877](https://github.com/socketzero/vault-sdk/commit/870b87768568d54387c70d7b80b4af5f6d2b8558))


### Build

* keep test material out of the package, ship auditable sources ([726b37d](https://github.com/socketzero/vault-sdk/commit/726b37d16b7a569ad1a3c4e2b313af1ad2c57cae))

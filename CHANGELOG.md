# Changelog

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

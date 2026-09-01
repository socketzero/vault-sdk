# @socket0/vault-sdk

The one implementation of the Socket0 vault: the envelope, the key group and its bucket,
the API key format, and the binary bundle. No I/O, no globals, no ambient config — every
input is an argument, which is what makes one build safe in a shard, in the control plane
and on a laptop.

Three parties call it and must agree byte for byte: the control plane seals a field with a
group's public half, a shard unwraps that group's private half with a presented API key and
opens the field, and a tenant's own code generates a group, wraps it under a new API key and
seals a credential before it is ever transmitted. A disagreement between any two of them is
a credential one party wrote and another cannot read — discovered weeks later, on somebody's
first relayed call, with the plaintext long gone.

## The catalog is the specification

This repository implements a specification it does not own. The authority is the
metaframework catalog under `solutions/socket0`:

| Document | What it fixes |
|---|---|
| `product/vault-sdk/index.md` | why this package exists and what it owns |
| `product/vault-sdk/component/sealing/index.md` | the four operations and the asymmetry in them |
| `datamodel/api-key/index.md` | the key format and the two derivations |
| `datamodel/sealed-secret/construction.md` | the envelope, exactly |
| `product/vault-sdk/datamodel/bundle/index.md` | the binary layout, the index, the write-back cache |
| `product/vault-sdk/datamodel/bundle/schema.json` | what that layout encodes, logically |
| `protocol/vault-operations/` | the exported surface |
| `.../tenant/datamodel/key-group/index.md` | what a key group is and bounds |

When the code and the catalog disagree, the catalog is right and the code is a defect.
Change the catalog first.

## Invariants

These are not preferences. Each of them fails silently if broken.

**The envelope is `x25519-hkdf-aesgcm`.** Payload is
`eph_pub(32) || nonce(12) || ciphertext || tag(16)`, serialised as `"<alg>:<base64>"`.
The content key is `HKDF-SHA256(ikm=X25519(eph.priv, group_pub), salt=eph.pub || group_pub,
info="socket0/v1", 32)`.

**Sealing needs no secret.** `seal()` takes a public key. There is no code path in this
package that seals with a private half, and a reviewer confirms that property by reading
the signature rather than the implementation.

**The associated data binds identity.** A credential field binds `connection_id ||
field_name`; a bucket entry binds `group_id || key_id`. An envelope moved between fields or
between connections fails to open even for a holder of the right key, so a writer that is
compromised can replace a credential but cannot promote one.

**Two info strings over one secret, salted by the tenant id.**

    key_id   = HKDF-SHA256(api_key, salt=tenant_id, info="socket0/v1/key-id",   16)
    wrap_key = HKDF-SHA256(api_key, salt=tenant_id, info="socket0/v1/tmk-wrap", 32)

The salt is the **tenant id**, never the group's public half: the public half changes on
every rotation and `key_id` must survive it, or bucket lookup breaks halfway through the
operation that rotates it.

**The HKDF input is the raw 32 bytes**, never the display string. The prefix and the
checksum are packaging; changing them must not invalidate a key that already exists.

**The key display form is** `sk0_<live|test>_<43 chars base62 of the 32 bytes>_<6 chars
base62 of the CRC-32>` — 59 characters. The checksum is verified locally, before any
request, because a wrong key produces an authentication-tag failure that is deliberately
indistinguishable from "wrong group", so the server can never tell a user they typed it
wrong and the client must.

**The bundle is never deserialised.** It is read in place through a `DataView` at computed
offsets. No object per record, no copy, no eager open.

**The index is open-addressed.** `2^k` slots with `2^k >= 4 x connection_count`, 8-byte
slots of `fingerprint uint32 || CONN offset uint32`; `bucket = uuid_low32 & (slots - 1)` and
`fingerprint = uuid_high32`; an offset of 0 means empty; linear probing on collision. **A
fingerprint miss must not read the CONN section.** A candidate match still verifies all
sixteen bytes of the id, because a 32-bit fingerprint is a filter and not a proof.

**The write-back cache is the transport format.** Opened plaintext is written into the slot
its own ciphertext occupied — an envelope is always exactly 60 bytes larger than its
plaintext, unconditionally, so it always fits. Write the bytes, then `plain_len`, then set
`state` to 1, synchronously, **publishing the flag last**. Write into the buffer you started
from, not the one that is active when the async unwrap finishes.

**Web Crypto only.** `globalThis.crypto.subtle`. No `node:crypto`, no wasm, no third-party
crypto library.

## Toolchain

Node 22+ (developed on v25.2.1, where Web Crypto is on `globalThis`). ESM only, ES2023,
`moduleResolution: "bundler"`.

```
npm run typecheck   # tsc --noEmit, strictest practical settings
npm run lint        # biome check .
npm run test        # vitest run
npm run test:cov    # vitest run --coverage, thresholds at 100
npm run check       # typecheck && lint && test:cov
npm run build       # tsc -p tsconfig.build.json -> dist/ with declarations
```

Coverage thresholds are 100% for lines, functions, branches and statements over `src/**`,
excluding tests and the `src/index.ts` barrel. A defect here writes credentials nobody can
ever read, and does it silently; that is what the gate is for.

`any`, `@ts-ignore`, `@ts-expect-error` and coverage-ignore comments are not used and must
not be introduced to make a gate pass.

## Status

Scaffold. Every module exports its full, typed signature; the bodies throw
`not implemented`. `src/scaffold.test.ts` asserts exactly that and is meant to be dismantled
module by module as the implementations land.

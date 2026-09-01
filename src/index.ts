/**
 * `@socket0/vault-sdk` — the public surface.
 *
 * There are two tiers here, and the boundary between them is not decoration.
 *
 * **The contract** is the ten operations of `protocol/vault-operations`, listed
 * identically in its `transport.yaml`, exported under exactly the names those
 * documents use:
 *
 *   generateGroup, seal, open, wrap, unwrap, deriveKeyId, parseKey,
 *   rotateGroup, writeBundle, readBundle
 *
 * That table *is* the surface. Changing one of those ten is a protocol version.
 *
 * **Everything else** exported below is implementation reachable by a consumer,
 * not contract. The catalog says so in as many words: "A package may export more
 * than this — encoders, parsers, layout constants — but those are implementation
 * reachable by a consumer, not contract: they may change without the protocol
 * version changing, and no other component may depend on them."
 *
 * So `product/control-plane`, `product/data-plane` and the SDK's own callers
 * depend on the first block. Nothing outside this package may depend on the
 * second.
 *
 * No I/O, no globals, no ambient config — every input is an argument, which is
 * what makes one build safe in a shard, in the control plane and on a laptop.
 */

// ===========================================================================
// THE CONTRACT — the ten operations of protocol/vault-operations
// ===========================================================================

// deriveKeyId(apiKey, tenantId) — a distinct info string from the wrap key.
// parseKey(display) — shape and checksum, locally. Returns a result; never throws.
export { deriveKeyId, parseApiKey as parseKey } from "./api-key.js";
// writeBundle(input) — the publisher.
// readBundle(buffer) — a shard, and tooling. Views over the caller's buffer.
export { readBundle } from "./bundle/reader.js";
export { writeBundle } from "./bundle/writer.js";
// seal(value, groupPublicKey, aad) — needs no secret, which is what lets the
//   control plane store what it cannot read.
// open(envelope, k1Private, aad) — the mirror; needs an unwrapped private half.
export { open, seal } from "./envelope.js";
// generateGroup() — a new X25519 keypair; the private half is returned once.
// wrap(k1Private, apiKey, tenantId, groupId) / unwrap(entry, apiKey, tenantId,
//   groupId) — the bucket; tenantId is the HKDF salt, groupId binds the AAD.
// rotateGroup(oldPriv, fields, apiKeys, tenantId, groupId) — a new K1, every
//   field resealed and the bucket rebuilt, together or not at all.
export { generateGroup, rotateGroup, unwrap, wrap } from "./group.js";

// ===========================================================================
// IMPLEMENTATION — reachable, but not contract
// ---------------------------------------------------------------------------
// Everything past this line may change without a protocol version bump, and no
// other component may depend on it.
// ===========================================================================

// --- the API key format ----------------------------------------------------
//
// `generateApiKey` is the only path from nothing to key material. There is no
// exported bytes-to-display renderer: `datamodel/api-key` says a key is never
// derived from a password, chosen, influenced by a user or regenerated from
// anything reproducible, and a public renderer taking caller-supplied bytes is
// exactly the affordance that lets one be.
export {
  API_KEY_BODY_CHARS,
  API_KEY_BYTES,
  API_KEY_CHECKSUM_CHARS,
  API_KEY_DISPLAY_LENGTH,
  API_KEY_ENVIRONMENTS,
  API_KEY_ISSUER_PREFIX,
  API_KEY_SEPARATOR,
  deriveKeyIdHex,
  deriveWrapKey,
  generateApiKey,
  HKDF_INFO_KEY_ID,
  HKDF_INFO_WRAP_KEY,
  KEY_ID_BYTES,
  parseApiKey,
  WRAP_KEY_BYTES,
} from "./api-key.js";
// --- the bundle ------------------------------------------------------------
//
// `decoyUnwrap` is offered, never imposed: lookup is synchronous and cannot
// perform the decoy itself, so running it on *every* miss path is
// `component/shard`'s duty, and a library cannot make a caller run it.
export * as layout from "./bundle/layout.js";
export { decoyUnwrap, readFieldDescriptor, writeBackPlaintext, zeroTail } from "./bundle/reader.js";
export { computeChecksum, measureBundle, writeBundleWithChecksum } from "./bundle/writer.js";
// --- encoders --------------------------------------------------------------
export {
  base62Decode,
  base62Encode,
  base64Decode,
  base64Encode,
  crc32,
  hexDecode,
  hexEncode,
  timingSafeEqual,
} from "./encoding.js";
// --- envelopes and associated data -----------------------------------------
//
// `fieldAssociatedData` and `bucketAssociatedData` build the length-prefixed
// AAD of `datamodel/sealed-secret/construction.md` and are the only sanctioned
// way to build one — every `seal` and `open` on the contract takes an
// `AssociatedData` the caller must have got from here.
export {
  AAD_LENGTH_PREFIX_BYTES,
  bucketAssociatedData,
  derivePublicKey,
  ENVELOPE_OVERHEAD_BYTES,
  EPHEMERAL_PUBLIC_KEY_BYTES,
  fieldAssociatedData,
  formatEnvelope,
  generateX25519KeyPair,
  HKDF_INFO_ENVELOPE,
  NONCE_BYTES,
  parseEnvelope,
  parseEnvelopeBytes,
  TAG_BYTES,
} from "./envelope.js";
// --- key groups and buckets ------------------------------------------------
export { buildBucket, findBucketEntry, WRAPPED_PRIVATE_KEY_BYTES } from "./group.js";
// --- branded key material: the only way to make a key out of bytes ---------
//
// A public half, a private half and an API key are all 32 raw bytes and all
// distinct types, so `seal(value, pair.privateKey, aad)` does not compile. The
// brands are `unique symbol` keys and cannot be spelled by a caller, so bytes
// that arrived over a wire have to come back through these three constructors —
// which is the point of them.
export {
  API_KEY_MATERIAL_BYTES,
  asApiKeyBytes,
  asPrivateKey,
  asPublicKey,
  requireApiKey,
  X25519_PRIVATE_KEY_BYTES,
  X25519_PUBLIC_KEY_BYTES,
} from "./types.js";

// --- types -----------------------------------------------------------------

export type {
  ApiKeyBytes,
  ApiKeyEnvironment,
  ApiKeyMaterial,
  ApiKeyParseFailure,
  AssociatedData,
  BucketEntry,
  BucketEntryView,
  BucketIdentity,
  BundleHeader,
  BundleHeaderInput,
  BundleInput,
  BundleView,
  ConnectionInput,
  ConnectionRecord,
  EnvelopeParts,
  FieldDescriptor,
  FieldIdentity,
  FilterArgsView,
  FilterInput,
  GroupKeyPair,
  GroupRotation,
  KeyGroup,
  KeyGroupView,
  ParsedApiKey,
  PrivateKey,
  PublicKey,
  SealAlgorithm,
  SealedEnvelope,
  SealedField,
  SectionEntry,
  SectionKindName,
  VisibleValue,
} from "./types.js";
export {
  ApiKeyFormatError,
  BundleCapacityError,
  BundleFormatError,
  EnvelopeFormatError,
  FieldState,
  SEAL_ALGORITHM,
  UnsupportedBundleVersionError,
  VaultDecryptionError,
  VaultError,
} from "./types.js";

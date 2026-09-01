/**
 * `@socket0/vault-sdk` — the public surface.
 *
 * The nine functions named in `protocol/vault-operations/transport.yaml` are
 * exported under exactly the names that document uses:
 *
 *   generateGroup, seal, open, wrap, unwrap, deriveKeyId, parseKey,
 *   writeBundle, readBundle
 *
 * Everything else exported here is supporting material for those nine.
 *
 * No I/O, no globals, no ambient config — every input is an argument, which is
 * what makes one build safe in a shard, in the control plane and on a laptop.
 */

// --- the protocol surface --------------------------------------------------

export { deriveKeyId, parseApiKey as parseKey } from "./api-key.js";
export { readBundle } from "./bundle/reader.js";
export { writeBundle } from "./bundle/writer.js";
export { open, seal } from "./envelope.js";
export { generateGroup, unwrap, wrap } from "./group.js";

// --- supporting API --------------------------------------------------------

export {
  API_KEY_BODY_CHARS,
  API_KEY_BYTES,
  API_KEY_CHECKSUM_CHARS,
  API_KEY_DISPLAY_LENGTH,
  API_KEY_ISSUER_PREFIX,
  API_KEY_SEPARATOR,
  deriveKeyIdHex,
  deriveWrapKey,
  formatApiKey,
  generateApiKey,
  HKDF_INFO_KEY_ID,
  HKDF_INFO_WRAP_KEY,
  KEY_ID_BYTES,
  parseApiKey,
  WRAP_KEY_BYTES,
} from "./api-key.js";
export * as layout from "./bundle/layout.js";
export { decoyUnwrap, readFieldDescriptor, writeBackPlaintext, zeroTail } from "./bundle/reader.js";
export { computeChecksum, measureBundle, writeBundleWithChecksum } from "./bundle/writer.js";
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
export {
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
export { buildBucket, findBucketEntry, WRAPPED_PRIVATE_KEY_BYTES } from "./group.js";

// --- types -----------------------------------------------------------------

export type {
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
  KeyGroup,
  KeyGroupView,
  ParsedApiKey,
  SealAlgorithm,
  SealedEnvelope,
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

/**
 * Key-group bootstrap (`protocol/tenant-management`, `workflows/bootstrap.yaml`):
 * the one client-side operation that produces K1, the first API key K2 and,
 * when the tenant chooses one, the recovery key K0 (`adr/0035`), and tells the
 * control plane only the result.
 *
 *     generate K1, K2 (, K0)          on this machine, Web Crypto only
 *     custody notice → acknowledged   requirement/key-custody-handoff: a gate
 *     reserve group id                POST /tenants/{t}/key-group-ids
 *     wrap K1 under K2 (, seal to K0) against exactly the reserved id
 *     register                        POST /tenants/{t}/key-groups
 *     return K2 (and K0) show-once
 *
 * The control plane is a registrar, not an issuer: what crosses the wire is
 * K1's public half, the key id, the wrapped private half and — with a phrase —
 * K0's public half and the recovery entry. None of them opens anything.
 *
 * **Acknowledgement comes before the reservation.** The register route refuses
 * a body without `custody_acknowledged: true`, so the tenant has to have said
 * yes before the request is made; asking first also means a person reading the
 * notice slowly cannot outlive the reservation's one-hour hold.
 *
 * **No I/O of its own.** The two HTTP calls go through a `KeyGroupRegistrar`
 * the caller passes in (`httpKeyGroupRegistrar` is the stock adapter), so this
 * module keeps the package's "every input is an argument" rule.
 *
 * **Zeroizing is best effort, and only for bytes.** K1's private half and K2's
 * raw bytes are overwritten as soon as the wrap no longer needs them, and every
 * secret is overwritten on any failure. A JavaScript string cannot be
 * overwritten, so K2's display form is held as bytes and decoded only at the
 * moment it is revealed; the string the caller then holds is theirs to drop.
 *
 * **The phrase's words are not rendered here.** `adr/0035` keeps phrase
 * encoding where a person sees it, so K0 is returned as its 32-byte private
 * half for the caller's UI to turn into the 24 words.
 */

import { generateApiKey } from "./api-key.js";
import { base64Encode, utf8Decode, utf8Encode } from "./encoding.js";
import { generateGroup, wrap } from "./group.js";
import { sealRecovery } from "./recovery.js";
import {
  type ApiKeyEnvironment,
  asPrivateKey,
  type GroupKeyPair,
  type PrivateKey,
  VaultError,
} from "./types.js";

// ---------------------------------------------------------------------------
// The registrar port: the two routes of socket0-api `routes/key-groups.ts`
// ---------------------------------------------------------------------------

/** `201` of `POST /tenants/{tenantId}/key-group-ids`. */
export interface ReservedKeyGroupId {
  /** A bare, canonical lowercase UUIDv7. Wrap against exactly this string. */
  readonly id: string;
  /** Unix seconds. */
  readonly expiresAt: number;
}

/**
 * The body of `POST /tenants/{tenantId}/key-groups` (`RegisterKeyGroup`), field
 * for field. The route is a `z.strictObject`, so nothing else may be sent.
 */
export interface RegisterKeyGroupRequest {
  readonly id: string;
  readonly name: string;
  /** K1's public half, 32 bytes, base64. */
  readonly public_key: string;
  /** 32 lowercase hex characters. */
  readonly key_id: string;
  /** The 60-byte bucket entry, base64. */
  readonly wrapped: string;
  readonly label?: string;
  readonly custody_acknowledged: true;
  /** K0's public half, base64. Sent together with `recovery_entry` or not at all. */
  readonly recovery_public_key?: string;
  /** K1's private half sealed to K0, `<alg>:<base64>`. */
  readonly recovery_entry?: string;
}

/** A bucket entry as the API shows it (`ApiKeySummary`). Never carries `wrapped`. */
export interface RegisteredApiKey {
  readonly key_id: string;
  readonly label: string | null;
  readonly created_at: number;
  readonly kind: "tenant" | "service";
}

/** `201` of `POST /tenants/{tenantId}/key-groups` (`KeyGroup`). */
export interface RegisteredKeyGroup {
  readonly id: string;
  readonly name: string;
  readonly public_key: string;
  readonly generation: number;
  readonly created_at: number;
  readonly purpose: "tenant" | "broker";
  readonly keys: readonly RegisteredApiKey[];
  readonly recovery_public_key: string | null;
  readonly has_recovery: boolean;
}

/**
 * Where a group's id comes from and where the finished group is registered.
 *
 * A port, so the bootstrap carries no transport, token handling or base URL of
 * its own. Every method takes the tenant id, so there is one place it comes
 * from: the options of the bootstrap that also salts the derivations with it.
 */
export interface KeyGroupRegistrar {
  reserveKeyGroupId(tenantId: string): Promise<ReservedKeyGroupId>;
  registerKeyGroup(tenantId: string, body: RegisterKeyGroupRequest): Promise<RegisteredKeyGroup>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** The tenant did not acknowledge the custody notice. Nothing was reserved or registered. */
export class CustodyNotAcknowledgedError extends VaultError {
  constructor() {
    super("custody of the API key was not acknowledged, so no key group was registered");
    this.name = "CustodyNotAcknowledgedError";
  }
}

/** A `ShowOnce` secret was asked for after it had been revealed or discarded. */
export class ShownAlreadyError extends VaultError {
  constructor() {
    super("this secret is shown once, and it has already been shown or discarded");
    this.name = "ShownAlreadyError";
  }
}

// ---------------------------------------------------------------------------
// Show once
// ---------------------------------------------------------------------------

/**
 * A secret that can be revealed exactly once.
 *
 * It holds the secret as bytes and overwrites them on the first `reveal` or
 * `discard`; after that there is nothing left to reveal. This is the SDK's half
 * of "displayed exactly once, then zeroized" — there is no retrieval path.
 */
export class ShowOnce<T> {
  #secret: Uint8Array | undefined;
  readonly #render: (bytes: Uint8Array) => T;

  /**
   * @param secret taken over, not copied: it is overwritten on reveal or discard.
   * @param render builds what the caller receives; it must copy what it keeps.
   */
  constructor(secret: Uint8Array, render: (bytes: Uint8Array) => T) {
    this.#secret = secret;
    this.#render = render;
  }

  /** Whether the secret has already been revealed or discarded. */
  get shown(): boolean {
    return this.#secret === undefined;
  }

  /**
   * The secret, once.
   *
   * @throws {ShownAlreadyError} on every call after the first, and after `discard`.
   */
  reveal(): T {
    const secret = this.#secret;
    if (secret === undefined) {
      throw new ShownAlreadyError();
    }
    this.#secret = undefined;
    try {
      return this.#render(secret);
    } finally {
      secret.fill(0);
    }
  }

  /** Overwrite the secret without revealing it. Idempotent. */
  discard(): void {
    this.#secret?.fill(0);
    this.#secret = undefined;
  }
}

// ---------------------------------------------------------------------------
// The words the tenant acknowledges
// ---------------------------------------------------------------------------

/**
 * The custody notice of `requirement/key-custody-handoff`: whose the key is,
 * what losing every key costs, unsoftened, and which recovery choice the tenant
 * made (`adr/0035` R5).
 */
export function custodyNotice(recoveryPhrase: boolean): string {
  const common =
    "This API key is yours to keep. Socket0 keeps no copy and cannot show it again. " +
    "Store it in your own secret manager — not a ticket, a chat message or a repository. " +
    "While one API key in this group survives, you can add keys and rotate the group.";
  const choice = recoveryPhrase
    ? " You chose a recovery phrase: 24 words that recover this group without any API key. " +
      "Keep them offline and never beside an API key. If every API key and the recovery phrase " +
      "are lost, this group's sealed values are permanently unreadable."
    : " You chose no recovery phrase: if every API key in this group is lost, this group's sealed " +
      "values are permanently unreadable. There is no escrow and no support procedure.";
  return common + choice;
}

/** `recommend-second-key`, offered while the first key is still in hand. */
export const SECOND_KEY_RECOMMENDATION =
  "A group with one API key is one lost laptop away from unrecoverable. Add a second key now " +
  "and store it apart from the first: it is one more bucket entry and reseals nothing.";

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/** What `acknowledgeCustody` is shown. */
export interface CustodyNotice {
  readonly text: string;
  readonly recoveryPhrase: boolean;
}

export interface BootstrapOptions {
  readonly registrar: KeyGroupRegistrar;
  /** The tenant id: the path of both routes and the HKDF salt of the bucket entry. */
  readonly tenantId: string;
  /** The first key's environment segment. */
  readonly environment: ApiKeyEnvironment;
  /** Defaults to `default`, the group every tenant has. */
  readonly name?: string;
  /** Free text for the tenant's own accounting, stored on the first bucket entry. */
  readonly label?: string;
  /** `adr/0035` R5: the tenant's explicit choice, with no default, because the notice must state it. */
  readonly recoveryPhrase: boolean;
  /**
   * Show the notice to a person and resolve `true` only on their explicit
   * acknowledgement. Anything but `true` aborts with nothing reserved or registered.
   */
  readonly acknowledgeCustody: (notice: CustodyNotice) => boolean | Promise<boolean>;
}

export interface BootstrappedKeyGroup {
  /** The group as the API stored it. */
  readonly group: RegisteredKeyGroup;
  /** The first API key's display form, shown once. */
  readonly apiKey: ShowOnce<string>;
  /** K0's private half, shown once, for the caller to render as the 24 words. Present iff a phrase was chosen. */
  readonly recoveryKey?: ShowOnce<PrivateKey>;
  /** The second-key offer, for the same screen. */
  readonly recommendation: string;
}

/** The reserve route's id: a bare UUIDv7 in its one canonical lowercase spelling. */
const RESERVED_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const DEFAULT_GROUP_NAME = "default";

/**
 * Create a key group on this machine and register it: reserve, generate, wrap,
 * register, under an acknowledged custody notice.
 *
 * @throws {CustodyNotAcknowledgedError} when `acknowledgeCustody` resolves to
 *   anything but `true`. Nothing has been reserved or registered.
 * @throws {VaultError} when the reserved id is not a canonical UUIDv7 — wrapping
 *   against a second spelling of an id makes an entry nothing can open — or when
 *   the registration answer names another group or public half.
 * Errors from the registrar propagate unchanged. On every failure each secret
 * this call produced is overwritten before it throws.
 */
export async function bootstrapKeyGroup(options: BootstrapOptions): Promise<BootstrappedKeyGroup> {
  const { registrar, tenantId } = options;
  const k1 = await generateGroup();
  const k2 = generateApiKey(options.environment);
  const k0 = options.recoveryPhrase ? await generateGroup() : undefined;
  const display = utf8Encode(k2.display);
  let handedOver = false;

  try {
    const notice: CustodyNotice = {
      text: custodyNotice(options.recoveryPhrase),
      recoveryPhrase: options.recoveryPhrase,
    };
    if ((await options.acknowledgeCustody(notice)) !== true) {
      throw new CustodyNotAcknowledgedError();
    }

    const { id } = await registrar.reserveKeyGroupId(tenantId);
    if (!RESERVED_ID.test(id)) {
      throw new VaultError("the reserved key-group id is not a canonical lowercase UUIDv7");
    }

    const entry = await wrap(k1.privateKey, k2.bytes, tenantId, id);
    const recovery = k0 === undefined ? undefined : await recoveryFields(k1, k0, id);
    // Neither is needed again: the bucket entry and the recovery entry are the
    // only copies of K1 that leave this call, and K2's display is held apart.
    k1.privateKey.fill(0);
    k2.bytes.fill(0);

    const publicKey = base64Encode(k1.publicKey);
    const body: RegisterKeyGroupRequest = {
      id,
      name: options.name ?? DEFAULT_GROUP_NAME,
      public_key: publicKey,
      key_id: entry.keyId,
      wrapped: base64Encode(entry.wrapped),
      ...(options.label === undefined ? {} : { label: options.label }),
      custody_acknowledged: true,
      ...recovery,
    };
    const group = await registrar.registerKeyGroup(tenantId, body);
    if (group.id !== id || group.public_key !== publicKey) {
      throw new VaultError("the registered key group is not the one this bootstrap created");
    }

    handedOver = true;
    const result: BootstrappedKeyGroup = {
      group,
      apiKey: new ShowOnce(display, utf8Decode),
      recommendation: SECOND_KEY_RECOMMENDATION,
    };
    return k0 === undefined
      ? result
      : {
          ...result,
          recoveryKey: new ShowOnce(k0.privateKey, (bytes) => asPrivateKey(Uint8Array.from(bytes))),
        };
  } finally {
    if (!handedOver) {
      k1.privateKey.fill(0);
      k2.bytes.fill(0);
      k0?.privateKey.fill(0);
      display.fill(0);
    }
  }
}

/** K0's public half and K1 sealed to it, as the register body spells them. */
async function recoveryFields(
  k1: GroupKeyPair,
  k0: GroupKeyPair,
  groupId: string,
): Promise<{ recovery_public_key: string; recovery_entry: string }> {
  return {
    recovery_public_key: base64Encode(k0.publicKey),
    recovery_entry: await sealRecovery(k1.privateKey, k0.publicKey, groupId),
  };
}

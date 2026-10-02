// Cloudwarden: the key step of a device approval (TASKS #241, web/NOTICE.md).
import { Utils } from "@bitwarden/common/platform/misc/utils";
import { EncString, EncryptService, SymmetricCryptoKey } from "@bitwarden/legacy-crypto";

export interface RewrapInput {
  /** The organisation symmetric key, from the admin's own key state. */
  orgKey: SymmetricCryptoKey;
  /** `encryptedPrivateKey` of the recovery details: the org private key under `orgKey`. */
  encryptedOrgPrivateKey: string;
  /** The member's user key encrypted with the organisation public key (their enrolment). */
  resetPasswordKey: string;
  /** Base64 SPKI public key of the requesting device. */
  devicePublicKey: string;
}

/** Returns the member's user key encrypted to the requesting device's public key. */
export async function rewrapUserKey(
  encryptService: Pick<
    EncryptService,
    "unwrapDecapsulationKey" | "decapsulateKeyUnsigned" | "encapsulateKeyUnsigned"
  >,
  input: RewrapInput,
): Promise<string> {
  const orgPrivateKey = await encryptService.unwrapDecapsulationKey(
    new EncString(input.encryptedOrgPrivateKey),
    input.orgKey,
  );
  const userKey = await encryptService.decapsulateKeyUnsigned(
    new EncString(input.resetPasswordKey),
    orgPrivateKey,
  );
  const wrapped = await encryptService.encapsulateKeyUnsigned(
    userKey,
    Utils.fromB64ToArray(input.devicePublicKey),
  );
  if (!wrapped.encryptedString) {
    throw new Error("Could not encrypt the user key for the device.");
  }
  return wrapped.encryptedString;
}

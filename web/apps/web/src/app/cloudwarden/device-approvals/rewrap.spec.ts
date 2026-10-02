import { rewrapUserKey } from "./rewrap";

describe("rewrapUserKey", () => {
  it("unwraps the org private key, decrypts the user key and encrypts it to the device", async () => {
    const orgKey = { id: "org-key" } as any;
    const calls: string[] = [];
    const encryptService = {
      unwrapDecapsulationKey: jest.fn(async (enc: any, key: any) => {
        calls.push(`unwrap ${enc.encryptedString} with ${key.id}`);
        return new Uint8Array([1, 2, 3]);
      }),
      decapsulateKeyUnsigned: jest.fn(async (enc: any, priv: Uint8Array) => {
        calls.push(`decapsulate ${enc.encryptedString} with ${priv.length}`);
        return { id: "user-key" } as any;
      }),
      encapsulateKeyUnsigned: jest.fn(async (key: any, pub: Uint8Array) => {
        calls.push(`encapsulate ${key.id} to ${Array.from(pub).join(",")}`);
        return { encryptedString: "4.wrapped" } as any;
      }),
    };
    const out = await rewrapUserKey(encryptService, {
      orgKey,
      encryptedOrgPrivateKey: "2.aXY=|Y3Q=|bWFj",
      resetPasswordKey: "4.cmVjb3Zlcnk=", // gitleaks:allow
      devicePublicKey: "AQID",
    });
    expect(out).toBe("4.wrapped");
    expect(calls).toEqual([
      "unwrap 2.aXY=|Y3Q=|bWFj with org-key",
      "decapsulate 4.cmVjb3Zlcnk= with 3",
      "encapsulate user-key to 1,2,3",
    ]);
  });

  it("fails when the device key cannot be encrypted", async () => {
    const encryptService = {
      unwrapDecapsulationKey: jest.fn(async () => new Uint8Array([1])),
      decapsulateKeyUnsigned: jest.fn(async () => ({}) as any),
      encapsulateKeyUnsigned: jest.fn(async () => ({ encryptedString: null }) as any),
    };
    await expect(
      rewrapUserKey(encryptService, {
        orgKey: {} as any,
        encryptedOrgPrivateKey: "2.aXY=|Y3Q=|bWFj",
        resetPasswordKey: "4.cmVjb3Zlcnk=", // gitleaks:allow
        devicePublicKey: "AQID",
      }),
    ).rejects.toThrow();
  });
});

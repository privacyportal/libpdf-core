/**
 * AES-256 security handler for PDF standard encryption.
 *
 * Used for R5-R6 encryption with AESV3 crypt filter (256-bit AES).
 * Unlike R2-R4, uses the file encryption key directly for all objects
 * (no per-object key derivation).
 *
 * Data format: [16-byte IV][ciphertext with PKCS#7 padding]
 *
 * @see PDF 2.0 Specification, Section 7.6.3.3 (AES-256 encryption)
 */

import { sha256 } from "@noble/hashes/sha2.js";

import { aesDecrypt, aesEncrypt } from "../ciphers/aes";
import { AbstractSecurityHandler } from "./abstract";

function makeIVGenerator(seed: Uint8Array) {
  let counter = 0;
  return function nextIV(): Uint8Array {
    const counterBytes = new Uint8Array(4)
    new DataView(counterBytes.buffer).setUint32(0, counter++, false)
    const iv = sha256.create()
      .update(seed)
      .update(counterBytes)
      .digest()
      .subarray(0, 16);
    return iv;
  };
}

export class AES256Handler extends AbstractSecurityHandler {
  readonly algorithm = "AES-256" as const;
  nextIV: undefined | (() => Uint8Array);

  constructor(
    readonly fileKey: Uint8Array,
    ivSeed?: Uint8Array,
  ) {
    super(fileKey);
    if (ivSeed) {
      this.nextIV = makeIVGenerator(ivSeed);
    }
  }

  protected encrypt(data: Uint8Array, _objNum: number, _genNum: number): Uint8Array {
    return aesEncrypt(this.fileKey, data, this.nextIV);
  }

  protected decrypt(data: Uint8Array, _objNum: number, _genNum: number): Uint8Array {
    return aesDecrypt(this.fileKey, data);
  }
}

// Token-name derivation, mirroring `tx.token_name` in the validator:
//
//   token_name(seed) = blake2b_256(cbor.serialise(seed))
//
// Aiken serialises a constructor as tag 121 followed by an INDEFINITE-length
// array (`9f … ff`). Most JS CBOR libraries emit a definite-length array, which
// produces a different hash, which makes minting fail with an error that tells
// you nothing. So the encoding is written out by hand here rather than
// delegated, and pinned by a golden value in goldenTest.js.

import { blake2b } from "@noble/hashes/blake2.js";

/** CBOR unsigned integer, major type 0. */
function cborUint(n) {
  const v = BigInt(n);
  if (v < 0n) throw new Error(`output_index must be non-negative, got ${n}`);
  if (v < 24n) return Uint8Array.from([Number(v)]);
  if (v <= 0xffn) return Uint8Array.from([0x18, Number(v)]);
  if (v <= 0xffffn) return Uint8Array.from([0x19, Number(v >> 8n), Number(v & 0xffn)]);
  if (v <= 0xffffffffn) {
    const b = new Uint8Array(5);
    b[0] = 0x1a;
    new DataView(b.buffer).setUint32(1, Number(v));
    return b;
  }
  const b = new Uint8Array(9);
  b[0] = 0x1b;
  new DataView(b.buffer).setBigUint64(1, v);
  return b;
}

/** CBOR byte string, major type 2. Only the lengths we need (<= 65535). */
function cborBytes(bytes) {
  const n = bytes.length;
  let header;
  if (n < 24) header = Uint8Array.from([0x40 | n]);
  else if (n <= 0xff) header = Uint8Array.from([0x58, n]);
  else if (n <= 0xffff) header = Uint8Array.from([0x59, n >> 8, n & 0xff]);
  else throw new Error(`byte string too long: ${n}`);
  return concat(header, bytes);
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function fromHex(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error(`odd-length hex: ${hex}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * CBOR for `OutputReference { transaction_id: ByteArray, output_index: Int }`,
 * constructor 0 → tag 121 (0xd879), indefinite-length array.
 */
export function serialiseOutputReference(txHashHex, outputIndex) {
  const txId = fromHex(txHashHex);
  if (txId.length !== 32) {
    throw new Error(`transaction_id must be 32 bytes, got ${txId.length}`);
  }
  return concat(
    Uint8Array.from([0xd8, 0x79, 0x9f]), // tag 121, indefinite array start
    cborBytes(txId),
    cborUint(outputIndex),
    Uint8Array.from([0xff]), // break
  );
}

/** The state-token name for an order seeded by this UTxO. Hex, 32 bytes. */
export function tokenName(txHashHex, outputIndex) {
  const cbor = serialiseOutputReference(txHashHex, outputIndex);
  return toHex(blake2b(cbor, { dkLen: 32 }));
}

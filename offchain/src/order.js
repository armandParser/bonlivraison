// Datum and redeemer construction for the order state machine.
//
// Field order and constructor indices are load-bearing and are transcribed
// from lib/bonlivraison/types.ak. A field in the wrong position still encodes
// cleanly and still submits; it fails inside the validator, where the error
// says nothing useful. Treat this file as the mirror of types.ak and change
// the two together.

import { Constr, Data } from "@lucid-evolution/lucid";
import { blake2b } from "@noble/hashes/blake2.js";
import { randomBytes } from "node:crypto";
import { toHex } from "./tokenName.js";

// --- Contractual terms ------------------------------------------------------
// Every total in this protocol is an attested figure in EURO CENTS. The only
// lovelace figure anywhere is the deposit that keeps the UTxO alive.

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

export const DEFAULT_TERMS = {
  acceptanceDeadline: null, // set per order, absolute POSIX ms
  receptionWindow: 2 * DAY,
  disputeWindow: 7 * DAY,
  tolerance: 500, // 5.00 EUR, below which a gap is not worth arbitrating
  abandonGrace: 14 * DAY,
};

/** The deposit: min-ADA so the UTxO can exist, returned to the buyer at close. */
export const DEPOSIT_LOVELACE = 5_000_000n;

// --- Commitments ------------------------------------------------------------

/**
 * blake2b-256 over `salt || canonical-JSON(document)`.
 *
 * The salt is mandatory. Quantities come from a small domain and an unsalted
 * digest is brute-forceable, which would leave a re-identifiable hash — still
 * personal data under GDPR. The salt is returned so it can be stored next to
 * the document; without it the counterparty cannot verify what was sealed.
 */
export function commit(document) {
  const salt = randomBytes(32);
  const body = Buffer.from(canonicalJson(document), "utf8");
  return {
    commitment: toHex(blake2b(Buffer.concat([salt, body]), { dkLen: 32 })),
    salt: salt.toString("hex"),
    document,
  };
}

/** Key-sorted JSON, so one document never yields two digests. */
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.keys(value)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`);
  return `{${entries.join(",")}}`;
}

// --- Datum ------------------------------------------------------------------

/** `Arbitration`, constructor 0: distinct keys, 1 <= threshold <= length. */
function arbitration({ keys, threshold }) {
  return new Constr(0, [keys, BigInt(threshold)]);
}

/** `Terms`, constructor 0, five ints in declaration order. */
function terms(t) {
  return new Constr(0, [
    BigInt(t.acceptanceDeadline),
    BigInt(t.receptionWindow),
    BigInt(t.disputeWindow),
    BigInt(t.tolerance),
    BigInt(t.abandonGrace), // fifth field, appended in commit fadede1
  ]);
}

/** `State::Created`, index 0. */
function created(request) {
  return new Constr(0, [request]);
}

/** `State::Accepted`, index 1. */
function accepted(lines, total) {
  return new Constr(1, [lines, BigInt(total)]);
}

/** `Order`, constructor 0. The datum carried by the order UTxO. */
export function orderDatum({ token, buyer, supplier, panel, contractTerms, state }) {
  return Data.to(
    new Constr(0, [
      token,
      buyer,
      supplier,
      arbitration(panel),
      terms(contractTerms),
      state,
    ]),
  );
}

export { created, accepted };

// --- Redeemers --------------------------------------------------------------

/** `TokenAction::Open`, index 0, carrying the seed `OutputReference`. */
export function openRedeemer(seedTxHash, seedIndex) {
  const outputReference = new Constr(0, [seedTxHash, BigInt(seedIndex)]);
  return Data.to(new Constr(0, [outputReference]));
}

/** `TokenAction::Close`, index 1. */
export function closeRedeemer() {
  return Data.to(new Constr(1, []));
}

/** `Action::Accept`, index 0. */
export function acceptRedeemer(lines, total) {
  return Data.to(new Constr(0, [lines, BigInt(total)]));
}

// The first test to pass, per the deployment brief. If this fails, nothing
// downstream is worth attempting: the token name is recomputed by the minting
// policy from the seed UTxO, so a one-byte disagreement rejects every mint.

import { serialiseOutputReference, tokenName, toHex } from "./tokenName.js";

const SEED_TX = "1111111111111111111111111111111111111111111111111111111111111111";
const SEED_IX = 1;

const EXPECTED_CBOR =
  "d8799f58201111111111111111111111111111111111111111111111111111111111111111" +
  "01ff";
const EXPECTED_NAME =
  "e6b82f9f17464ed2994ea77bb177f40868f65b48bf290ff060e001cd3000a616";

let failed = false;

function check(label, actual, expected) {
  const ok = actual === expected;
  if (!ok) failed = true;
  console.log(`${ok ? "  ok  " : " FAIL "} ${label}`);
  if (!ok) {
    console.log(`         expected  ${expected}`);
    console.log(`         actual    ${actual}`);
  }
}

console.log("token-name derivation");
check("cbor(OutputReference)", toHex(serialiseOutputReference(SEED_TX, SEED_IX)), EXPECTED_CBOR);
check("blake2b_256 → token name", tokenName(SEED_TX, SEED_IX), EXPECTED_NAME);

// Encoding widths for output_index, since real seeds are rarely index 1.
check(
  "index 0 encodes as 0x00",
  toHex(serialiseOutputReference(SEED_TX, 0)).slice(-6),
  "1100ff", // last byte of the txid, then index 0x00, then the break
);
check(
  "index 24 encodes as 0x1818",
  toHex(serialiseOutputReference(SEED_TX, 24)).slice(-6),
  "1818ff",
);

console.log(failed ? "\nFAILED" : "\nall passed");
process.exit(failed ? 1 : 0);

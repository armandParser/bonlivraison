// Three parties, three keys, generated locally and kept out of git.
//
// Preprod only. The buyer and the supplier each hold their own key and pay
// their own fees — the architecture the grant requires rather than a stylistic
// choice, since a fee paid from the operator's wallet does not count as
// adoption. The arbiter never signs in this deployment: its key hash only has
// to exist in the datum for the panel to be well-formed at minting.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  generatePrivateKey,
  makeWalletFromPrivateKey,
  paymentCredentialOf,
} from "@lucid-evolution/lucid";

const here = dirname(fileURLToPath(import.meta.url));
export const KEYS_PATH = join(here, "..", "keys.json");

export const NETWORK = "Preprod";
export const ROLES = ["buyer", "supplier", "arbiter"];

/** Address and payment-key hash for a private key, without touching a provider. */
export async function identityOf(privateKey) {
  const wallet = makeWalletFromPrivateKey(undefined, NETWORK, privateKey);
  const address = await wallet.address();
  return { address, keyHash: paymentCredentialOf(address).hash };
}

export async function generateKeys() {
  const keys = { network: NETWORK, generatedAt: new Date().toISOString() };
  for (const role of ROLES) {
    const privateKey = generatePrivateKey();
    keys[role] = { privateKey, ...(await identityOf(privateKey)) };
  }
  return keys;
}

export function loadKeys() {
  if (!existsSync(KEYS_PATH)) {
    throw new Error(`No keys at ${KEYS_PATH}. Run:  node src/genKeys.js`);
  }
  return JSON.parse(readFileSync(KEYS_PATH, "utf8"));
}

export function saveKeys(keys) {
  writeFileSync(KEYS_PATH, JSON.stringify(keys, null, 2) + "\n", { mode: 0o600 });
}

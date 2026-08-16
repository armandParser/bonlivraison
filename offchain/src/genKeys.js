// Generates the three Preprod keys, once. Refuses to overwrite: rerunning
// after the buyer has been funded would strand the tADA at an address whose
// key no longer exists anywhere.

import { existsSync } from "node:fs";
import { generateKeys, saveKeys, loadKeys, KEYS_PATH, ROLES } from "./keys.js";

const keys = existsSync(KEYS_PATH) ? loadKeys() : await (async () => {
  const fresh = await generateKeys();
  saveKeys(fresh);
  return fresh;
})();

if (existsSync(KEYS_PATH) && process.argv.includes("--force")) {
  console.error("Refusing to regenerate: --force is not implemented on purpose.");
  console.error(`Delete ${KEYS_PATH} by hand if you really mean it.`);
  process.exit(1);
}

console.log(`keys at ${KEYS_PATH} (gitignored, mode 600)\n`);
for (const role of ROLES) {
  console.log(`${role.padEnd(9)} ${keys[role].address}`);
  console.log(`${"".padEnd(9)} keyhash ${keys[role].keyHash}\n`);
}

console.log("Fund the BUYER address from the faucet:");
console.log("  https://docs.cardano.org/cardano-testnets/tools/faucet");
console.log("\nThe supplier is funded from the buyer by:  node src/fundSupplier.js");

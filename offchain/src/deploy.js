// The live Preprod run. Same protocol code as the dry run; only the provider
// and the clock differ.
//
//   node src/deploy.js
//
// Needs BLOCKFROST_PROJECT_ID (a Preprod project key) in the environment or in
// offchain/.env, and a buyer funded from the faucet.

import { existsSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Blockfrost, Koios, Lucid } from "@lucid-evolution/lucid";
import { loadKeys } from "./keys.js";
import { openOrder, acceptOrder, scriptContext } from "./protocol.js";
import { EXPECTED_HASH, loadValidator } from "./blueprint.js";

const here = dirname(fileURLToPath(import.meta.url));
const envPath = join(here, "..", ".env");
if (existsSync(envPath)) process.loadEnvFile(envPath);

const NETWORK = "Preprod";

// Koios needs no account, so the deployment has no signup on its critical path.
// Blockfrost is used instead when a key is present — it is the more reliable of
// the two for submission, which matters more the busier the testnet is.
const PROJECT_ID = process.env.BLOCKFROST_PROJECT_ID;
if (PROJECT_ID && !PROJECT_ID.startsWith("preprod")) {
  console.error(`Refusing to run: project id "${PROJECT_ID.slice(0, 8)}..." is not a Preprod key.`);
  console.error("A mainnet deployment before M1 would make the script undeclarable.");
  process.exit(1);
}

const provider = PROJECT_ID
  ? new Blockfrost("https://cardano-preprod.blockfrost.io/api/v0", PROJECT_ID)
  : new Koios("https://preprod.koios.rest/api/v1");

const SUPPLIER_FLOAT = 200_000_000n; // 200 tADA, so the supplier pays its own way
const explorer = (hash) => `https://preprod.cardanoscan.io/transaction/${hash}`;

const keys = loadKeys();
const compiled = loadValidator();
const lucid = await Lucid(provider, NETWORK);

const { address, policyId } = scriptContext(NETWORK);

console.log(`provider        ${PROJECT_ID ? "Blockfrost" : "Koios (keyless)"}`);
console.log(`compiler        ${compiled.compiler.name} ${compiled.compiler.version}`);
console.log(`script hash     ${compiled.hash}`);
if (compiled.hash !== EXPECTED_HASH) {
  console.error(`\nBlueprint hash changed — expected ${EXPECTED_HASH}.`);
  console.error("The validator was rebuilt since the brief. Re-derive the address before deploying.");
  process.exit(1);
}
console.log(`policy id       ${policyId}`);
console.log(`script address  ${address}\n`);

// --- funding ---------------------------------------------------------------

async function balance(role) {
  const utxos = await lucid.utxosAt(keys[role].address);
  return utxos.reduce((sum, u) => sum + u.assets.lovelace, 0n);
}

const buyerBalance = await balance("buyer");
console.log(`buyer     ${keys.buyer.address}`);
console.log(`          ${buyerBalance / 1_000_000n} tADA`);
if (buyerBalance === 0n) {
  console.error("\nBuyer is empty. Fund it from https://docs.cardano.org/cardano-testnets/tools/faucet");
  process.exit(1);
}

let supplierBalance = await balance("supplier");
console.log(`supplier  ${keys.supplier.address}`);
console.log(`          ${supplierBalance / 1_000_000n} tADA`);

if (supplierBalance < 50_000_000n) {
  console.log("\nFunding the supplier from the buyer, so its own fee comes from its own wallet.");
  lucid.selectWallet.fromPrivateKey(keys.buyer.privateKey);
  const tx = await lucid
    .newTx()
    .pay.ToAddress(keys.supplier.address, { lovelace: SUPPLIER_FLOAT })
    .complete();
  const hash = await (await tx.sign.withWallet().complete()).submit();
  console.log(`  ${hash}`);
  await lucid.awaitTx(hash);
  supplierBalance = await balance("supplier");
  console.log(`  supplier now holds ${supplierBalance / 1_000_000n} tADA`);
}

// --- TX1 -------------------------------------------------------------------

console.log("\nTX1  Open — mint the state token, create the order at the script");
const order = await openOrder(lucid, keys, NETWORK);
console.log(`  hash        ${order.txHash}`);
console.log(`  ${explorer(order.txHash)}`);
console.log(`  token name  ${order.name}`);
console.log("  waiting for confirmation (TX2 spends this output)...");
await lucid.awaitTx(order.txHash);
console.log("  confirmed");

// --- TX2 -------------------------------------------------------------------

console.log("\nTX2  Accept — supplier commits to the lines, signs, pays its own fee");
const accept = await acceptOrder(lucid, keys, NETWORK, order);
console.log(`  hash        ${accept.txHash}`);
console.log(`  ${explorer(accept.txHash)}`);
console.log(`  total       ${accept.total} euro cents`);
await lucid.awaitTx(accept.txHash);
console.log("  confirmed");

// --- receipt ---------------------------------------------------------------

const receipt = {
  network: NETWORK,
  deployedAt: new Date().toISOString(),
  scriptHash: compiled.hash,
  policyId,
  scriptAddress: address,
  compiler: compiled.compiler,
  parties: {
    buyer: { address: keys.buyer.address, keyHash: keys.buyer.keyHash },
    supplier: { address: keys.supplier.address, keyHash: keys.supplier.keyHash },
    arbiter: { keyHash: keys.arbiter.keyHash },
  },
  panel: order.panel,
  terms: order.contractTerms,
  order: { tokenName: order.name, unit: order.unit },
  transactions: [
    { step: "TX1", redeemer: "Open", txHash: order.txHash, explorer: explorer(order.txHash) },
    { step: "TX2", redeemer: "Accept", txHash: accept.txHash, explorer: explorer(accept.txHash) },
  ],
  // Salts belong in the database next to their document: without them the
  // counterparty cannot verify what was committed.
  salts: { request: order.request.salt, lines: accept.lines.salt },
};

const receiptPath = join(here, "..", "deployment.json");
writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + "\n");

console.log(`\nreceipt written to ${receiptPath}`);
console.log("\n--- for the application ---");
console.log(`Preprod script address   ${address}`);
console.log(`TX1 Open                 ${explorer(order.txHash)}`);
console.log(`TX2 Accept               ${explorer(accept.txHash)}`);

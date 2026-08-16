// Runs TX1 and TX2 against the in-process emulator, with the real compiled
// validator from plutus.json.
//
// This is where a datum field in the wrong position or a definite-length CBOR
// array gets caught. On Preprod the same mistakes cost a faucet cooldown and
// an error message that names no field.

import { Emulator, Lucid } from "@lucid-evolution/lucid";
import { loadKeys } from "./keys.js";
import { openOrder, acceptOrder, scriptContext } from "./protocol.js";

const NETWORK = "Custom"; // the emulator's own network id

const keys = loadKeys();
const funded = [keys.buyer, keys.supplier].map((k) => ({
  address: k.address,
  assets: { lovelace: 10_000_000_000n },
}));

const emulator = new Emulator(funded);

// With an emulator provider Lucid ignores SLOT_CONFIG_NETWORK and pins its slot
// config to the emulator's clock at construction: zeroSlot becomes whatever
// emulator.slot reads right now. So build Lucid at slot 0, before advancing.
const lucid = await Lucid(emulator, NETWORK);
const now = () => emulator.now();

// Only then step forward. `Accept` backdates its lower bound five minutes, and
// the evaluator converts a slot below zeroSlot into a negative time — surfacing
// as "validity start or end too far in the past". Twenty blocks is 400 slots,
// comfortably more than the 300 the backdate needs.
emulator.awaitBlock(20);

const { address, policyId } = scriptContext(NETWORK);
console.log(`script address (emulator)  ${address}`);
console.log(`policy id                  ${policyId}\n`);

console.log("TX1  Open — mint the state token, create the order at the script");
const order = await openOrder(lucid, keys, NETWORK, now);
emulator.awaitBlock(1);
console.log(`  hash        ${order.txHash}`);
console.log(`  token name  ${order.name}`);

const atScript = await lucid.utxosAt(address);
console.log(`  script UTxOs ${atScript.length}, holding ${atScript[0]?.assets.lovelace} lovelace\n`);

console.log("TX2  Accept — supplier commits to the lines, signs, pays its own fee");
const accept = await acceptOrder(lucid, keys, NETWORK, order, now);
emulator.awaitBlock(1);
console.log(`  hash        ${accept.txHash}`);
console.log(`  total       ${accept.total} euro cents`);

const after = await lucid.utxosAt(address);
console.log(`  script UTxOs ${after.length}, still holding the token: ${after[0]?.assets[order.unit] === 1n}`);

console.log("\ndry run passed — encoding and both validator branches accept");

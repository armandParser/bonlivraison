// The two transactions of the deployment, written once and run twice: first
// against the emulator, then against Preprod. Same code path both times, so a
// green dry-run means the encoding is right and only the network is left to
// surprise us.

import {
  validatorToAddress,
  paymentCredentialOf,
} from "@lucid-evolution/lucid";
import { loadValidator } from "./blueprint.js";
import { tokenName } from "./tokenName.js";
import {
  orderDatum,
  openRedeemer,
  acceptRedeemer,
  created,
  accepted,
  commit,
  DEFAULT_TERMS,
  DEPOSIT_LOVELACE,
  DAY,
  HOUR,
  MINUTE,
} from "./order.js";

export function scriptContext(network) {
  const compiled = loadValidator();
  const validator = { type: "PlutusV3", script: compiled.script };
  return {
    validator,
    policyId: compiled.hash,
    address: validatorToAddress(network, validator),
  };
}

/**
 * TX1 — Open.
 *
 * Consumes a seed UTxO from the buyer, mints the state token whose name is
 * derived from that seed, and creates the order UTxO at the script in state
 * `Created`. Proves the minting policy executes and the one-shot pattern holds.
 */
export async function openOrder(lucid, keys, network, now = Date.now) {
  const { validator, policyId, address } = scriptContext(network);

  lucid.selectWallet.fromPrivateKey(keys.buyer.privateKey);
  const utxos = await lucid.wallet().getUtxos();
  if (utxos.length === 0) throw new Error("buyer has no UTxOs — fund it first");

  // The seed must be an input of this transaction and is consumed by it, which
  // is what makes the token name unrepeatable. Pick the fattest UTxO so the
  // change and the deposit both fit.
  const seed = utxos.reduce((a, b) => (b.assets.lovelace > a.assets.lovelace ? b : a));
  const name = tokenName(seed.txHash, seed.outputIndex);
  const unit = policyId + name;

  const request = commit({
    kind: "order-request",
    buyer: keys.buyer.keyHash,
    supplier: keys.supplier.keyHash,
    lines: [
      { sku: "TOM-CAT-5KG", label: "Tomates grappe cat.1", qty: 8, unitCents: 1_240 },
      { sku: "COU-VER-3KG", label: "Courgettes vertes", qty: 5, unitCents: 890 },
    ],
    placedAt: new Date(now()).toISOString(),
  });

  const contractTerms = {
    ...DEFAULT_TERMS,
    acceptanceDeadline: now() + 7 * DAY,
  };

  // The panel is [buyer, supplier, independent] at threshold 2: the parties
  // agreeing settles their own dispute, and the third seat only breaks a tie.
  // The platform holds no seat — with one it could always swing a dispute.
  const panel = {
    keys: [keys.buyer.keyHash, keys.supplier.keyHash, keys.arbiter.keyHash],
    threshold: 2,
  };

  const datum = orderDatum({
    token: name,
    buyer: keys.buyer.keyHash,
    supplier: keys.supplier.keyHash,
    panel,
    contractTerms,
    state: created(request.commitment),
  });

  const tx = await lucid
    .newTx()
    .collectFrom([seed])
    .mintAssets({ [unit]: 1n }, openRedeemer(seed.txHash, seed.outputIndex))
    .attach.MintingPolicy(validator)
    .pay.ToContract(
      address,
      { kind: "inline", value: datum },
      { lovelace: DEPOSIT_LOVELACE, [unit]: 1n },
    )
    .complete();

  const signed = await tx.sign.withWallet().complete();
  const txHash = await signed.submit();

  return { txHash, unit, name, datum, request, contractTerms, panel, address };
}

/**
 * TX2 — Accept.
 *
 * The supplier commits to the lines and the amount, signing with its own key
 * and paying its own fee. This is the transaction that matters: TX1 alone only
 * demonstrates minting, while this one runs the spending validator and proves
 * it admits a legitimate transition.
 */
export async function acceptOrder(lucid, keys, network, order, now = Date.now) {
  const { validator, address } = scriptContext(network);

  lucid.selectWallet.fromPrivateKey(keys.supplier.privateKey);

  const [orderUtxo] = await lucid.utxosAt(address).then((all) =>
    all.filter((u) => u.assets[order.unit] === 1n),
  );
  if (!orderUtxo) throw new Error(`order UTxO carrying ${order.unit} not found`);

  const lines = commit({
    kind: "supplier-acceptance",
    order: order.name,
    lines: [
      { sku: "TOM-CAT-5KG", qty: 8, unitCents: 1_240 },
      { sku: "COU-VER-3KG", qty: 5, unitCents: 890 },
    ],
    acceptedAt: new Date(now()).toISOString(),
  });
  const total = 8 * 1_240 + 5 * 890; // euro cents, never lovelace

  const datum = orderDatum({
    token: order.name,
    buyer: keys.buyer.keyHash,
    supplier: keys.supplier.keyHash,
    panel: order.panel,
    contractTerms: order.contractTerms,
    state: accepted(lines.commitment, total),
  });

  // `Accept` requires the range to fall entirely before the acceptance
  // deadline. The upper bound is what the validator reads, so it must be set
  // explicitly — builders leave it open by default and the branch would fail.
  const validFrom = now() - 5 * MINUTE;
  const validTo = now() + HOUR;
  if (validTo >= order.contractTerms.acceptanceDeadline) {
    throw new Error("validity range not entirely before the acceptance deadline");
  }

  const tx = await lucid
    .newTx()
    .collectFrom([orderUtxo], acceptRedeemer(lines.commitment, total))
    .attach.SpendingValidator(validator)
    .pay.ToContract(
      address,
      { kind: "inline", value: datum },
      { lovelace: orderUtxo.assets.lovelace, [order.unit]: 1n },
    )
    // `signed_by` reads extra_signatories, which is the required-signers field
    // and not the witness set. Paying the fee from the supplier's wallet does
    // not populate it; this does.
    .addSignerKey(paymentCredentialOf(keys.supplier.address).hash)
    .validFrom(validFrom)
    .validTo(validTo)
    .complete();

  const signed = await tx.sign.withWallet().complete();
  const txHash = await signed.submit();

  return { txHash, lines, total, datum };
}

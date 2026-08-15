//// Delivery-note validator.
////
//// A single script serves two roles: minting policy for the state token
//// (order uniqueness) and spending validator (state machine). The policy id
//// is therefore equal to the script hash.

use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/fuzz
use aiken/interval.{Interval}
use bonlivraison/reconciliation.{Contested, admissible, reconcile}
use bonlivraison/tx.{
  continuing_output, event_time, paid_to, script_input_count, signed_by,
  token_burned, token_name,
}
use bonlivraison/types.{
  Accept, Accepted, Action, Arbitrate, Cancel, ClaimSilence, Close, CloseDispute,
  Created, Declare, Disputed, Open, Order, Ship, Shipped, State, Terms,
  TokenAction,
}
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{
  PolicyId, from_asset, from_lovelace, lovelace_of, merge, quantity_of, tokens,
}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, find_input,
  placeholder,
}

validator order {
  spend(
    datum: Option<Order>,
    action: Action,
    reference: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum
    expect Some(input) = find_input(self.inputs, reference)

    let address = input.output.address
    expect Script(policy) = address.payment_credential
    let escrow = lovelace_of(input.output.value)

    and {
      // One order per transaction.
      //
      // `paid_to` and `token_burned` read the transaction as a whole, so two
      // orders settled together would each be satisfied by the same outputs:
      // a single payment to the supplier would discharge both, and the buyer
      // would take a full delivery for free. Two orders from the same
      // buyer/supplier pair on the same morning is the normal case in food
      // service, not an edge case.
      //
      // Batching is not a loss here. One order = one UTxO = one state token,
      // so orders never contend for the same UTxO and there is nothing to
      // batch for throughput. Wallet inputs funding the fee are unaffected:
      // only inputs locked by this script are counted.
      (script_input_count(self, policy) == 1)?,
      when action is {
        // --- The supplier commits ----------------------------------------
        Accept { lines, total } -> {
          expect Created { .. } = d.state
          and {
            signed_by(self, d.supplier)?,
            interval.is_entirely_before(
              self.validity_range,
              d.terms.acceptance_deadline,
            )?,
            (total > 0)?,
            // The escrow must cover the commitment, otherwise the buyer could
            // promise without provisioning.
            (escrow >= total)?,
            continues(
              self,
              address,
              policy,
              d,
              Accepted { lines, total },
              escrow,
            )?,
          }
        }

        // --- The buyer withdraws, or the deadline has passed --------------
        Cancel -> {
          expect Created { .. } = d.state
          and {
            or {
              signed_by(self, d.buyer),
              interval.is_entirely_after(
                self.validity_range,
                d.terms.acceptance_deadline,
              ),
            }?,
            token_burned(self, policy, d.token)?,
            // Full escrow back, fee on the canceller. Same reasoning as
            // `settle`.
            (paid_to(self, d.buyer) >= escrow)?,
          }
        }

        // --- The manifest is sealed as the truck departs -------------------
        Ship { manifest, manifest_total } -> {
          expect Accepted { total, .. } = d.state
          and {
            signed_by(self, d.supplier)?,
            (manifest_total > 0)?,
            // No post-agreement inflation: never invoice beyond what was
            // accepted.
            (manifest_total <= total)?,
            continues(
              self,
              address,
              policy,
              d,
              Shipped {
                manifest,
                manifest_total,
                // Upper bound, not lower: see `tx.event_time`. Reading the
                // lower bound here would let the supplier back-date the
                // shipment and expire the buyer's reception window before it
                // ever opened.
                shipped_at: event_time(self.validity_range),
              },
              escrow,
            )?,
          }
        }

        // --- The buyer declares what was actually received -----------------
        Declare { receipt, accepted_total } -> {
          expect Shipped { manifest_total, shipped_at, .. } = d.state
          let declared_at = event_time(self.validity_range)
          let preconditions = and {
              signed_by(self, d.buyer)?,
              admissible(manifest_total, accepted_total)?,
              interval.is_entirely_before(
                self.validity_range,
                shipped_at + d.terms.reception_window,
              )?,
            }

          when reconcile(manifest_total, accepted_total, d.terms.tolerance) is {
            // Significant gap: the undisputed part settles at closing, the
            // delta stays in escrow for the duration of the arbitration.
            Contested -> and {
                preconditions,
                continues(
                  self,
                  address,
                  policy,
                  d,
                  Disputed {
                    manifest_total,
                    accepted_total,
                    receipt,
                    declared_at,
                  },
                  escrow,
                )?,
              }
            // Exact or trivial: immediate settlement, no arbitration.
            _ -> and {
                preconditions,
                settle(self, d, policy, accepted_total, escrow)?,
              }
          }
        }

        // --- The buyer's silence counts as acceptance ----------------------
        ClaimSilence -> {
          expect Shipped { manifest_total, shipped_at, .. } = d.state
          and {
            signed_by(self, d.supplier)?,
            interval.is_entirely_after(
              self.validity_range,
              shipped_at + d.terms.reception_window,
            )?,
            settle(self, d, policy, manifest_total, escrow)?,
          }
        }

        // --- The arbiter rules, within bounds it does not choose -----------
        Arbitrate { final_total } -> {
          expect Disputed { manifest_total, accepted_total, declared_at, .. } =
            d.state
          and {
            signed_by(self, d.arbiter)?,
            (final_total >= accepted_total)?,
            (final_total <= manifest_total)?,
            interval.is_entirely_before(
              self.validity_range,
              declared_at + d.terms.dispute_window,
            )?,
            settle(self, d, policy, final_total, escrow)?,
          }
        }

        // --- The arbiter never ruled: the buyer prevails -------------------
        CloseDispute -> {
          expect Disputed { accepted_total, declared_at, .. } = d.state
          and {
            interval.is_entirely_after(
              self.validity_range,
              declared_at + d.terms.dispute_window,
            )?,
            or {
              signed_by(self, d.buyer),
              signed_by(self, d.supplier),
            }?,
            settle(self, d, policy, accepted_total, escrow)?,
          }
        }
      },
    }
  }

  mint(action: TokenAction, policy: PolicyId, self: Transaction) {
    when action is {
      Open { seed } -> {
        // The seed UTxO is consumed: the token name can never be reproduced.
        expect Some(_) = find_input(self.inputs, seed)
        let expected = token_name(seed)
        expect [Pair(name, 1)] = dict.to_pairs(tokens(self.mint, policy))

        // The token must be born at the script, in state Created, naming
        // itself.
        expect [output] =
          list.filter(
            self.outputs,
            fn(o) {
              o.address.payment_credential == Script(policy) && quantity_of(
                o.value,
                policy,
                expected,
              ) == 1
            },
          )
        expect InlineDatum(raw) = output.datum
        expect d: Order = raw
        expect Created { .. } = d.state

        and {
          (name == expected)?,
          (d.token == expected)?,
        }
      }

      Close ->
        list.all(
          dict.values(tokens(self.mint, policy)),
          fn(quantity) { quantity < 0 },
        )
    }
  }

  else(_) {
    fail
  }
}

/// Carries the order back to the script in a new state, forbidding any
/// mutation of the parties, the token or the contractual terms.
fn continues(
  self: Transaction,
  address: Address,
  policy: PolicyId,
  previous: Order,
  new_state: State,
  escrow: Int,
) -> Bool {
  let output = continuing_output(self, address, policy, previous.token)
  expect InlineDatum(raw) = output.datum
  expect next: Order = raw
  and {
    (next.token == previous.token)?,
    (next.buyer == previous.buyer)?,
    (next.supplier == previous.supplier)?,
    (next.arbiter == previous.arbiter)?,
    (next.terms == previous.terms)?,
    (next.state == new_state)?,
    // The escrow cannot leak along the way.
    (lovelace_of(output.value) >= escrow)?,
  }
}

/// Final closing: token burned, supplier paid, remainder returned in full.
///
/// The escrow is accounted for exactly: the supplier receives what it is
/// owed, the buyer receives the rest, and the transaction fee is paid by
/// whoever submits, out of their own inputs.
///
/// An earlier version allowed `paid_to(buyer) + self.fee`, so the fee could be
/// charged against the buyer's refund. Value conservation caps the supplier's
/// net take at `owed_to_supplier` either way, so that allowance never let the
/// supplier steal outright — but it did let the supplier inflate the fee at
/// zero cost to itself and shrink the buyer's refund by exactly that amount,
/// on every supplier-initiated path. Small per delivery, and levied on every
/// delivery, against the party this product exists to protect.
///
/// Removing it also serves the adoption metric: each party must pay its own
/// fees from its own wallet, and a fee drawn from the buyer's escrow is not
/// that.
fn settle(
  self: Transaction,
  d: Order,
  policy: PolicyId,
  owed_to_supplier: Int,
  escrow: Int,
) -> Bool {
  and {
    token_burned(self, policy, d.token)?,
    (paid_to(self, d.supplier) >= owed_to_supplier)?,
    (paid_to(self, d.buyer) >= escrow - owed_to_supplier)?,
  }
}

// ## Scenarios
//
// End-to-end simulated transactions. Nominal paths matter, attempted abuse
// matters more.

const buyer = #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

const supplier = #"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

const arbiter = #"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"

const policy = #"d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"

const token = #"5eed"

const token_b = #"5eee"

const ref =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: 0,
  }

const ref_b =
  OutputReference {
    transaction_id: #"1111111111111111111111111111111111111111111111111111111111111111",
    output_index: 1,
  }

fn terms() -> Terms {
  Terms {
    acceptance_deadline: 20_000,
    reception_window: 500,
    dispute_window: 1_000,
    tolerance: 1_500_000,
  }
}

fn datum_of(t: ByteArray, state: State) -> Order {
  Order { token: t, buyer, supplier, arbiter, terms: terms(), state }
}

fn dat(state: State) -> Order {
  datum_of(token, state)
}

fn to_script_with(t: ByteArray, escrow: Int, state: State) -> Output {
  Output {
    address: Address {
      payment_credential: Script(policy),
      stake_credential: None,
    },
    value: merge(from_lovelace(escrow), from_asset(policy, t, 1)),
    datum: InlineDatum(datum_of(t, state)),
    reference_script: None,
  }
}

fn to_script(escrow: Int, state: State) -> Output {
  to_script_with(token, escrow, state)
}

fn to_key(who: ByteArray, amount: Int) -> Output {
  Output {
    address: Address {
      payment_credential: VerificationKey(who),
      stake_credential: None,
    },
    value: from_lovelace(amount),
    datum: NoDatum,
    reference_script: None,
  }
}

fn script_input_with(
  r: OutputReference,
  t: ByteArray,
  escrow: Int,
  state: State,
) -> Input {
  Input { output_reference: r, output: to_script_with(t, escrow, state) }
}

fn script_input(escrow: Int, state: State) -> Input {
  script_input_with(ref, token, escrow, state)
}

const shipped =
  Shipped { manifest: #"ee", manifest_total: 80_000_000, shipped_at: 10_000 }

// ### Nominal paths

/// Everything arrived, the supplier is paid, the remainder returns.
test nominal_settles_immediately() {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_key(supplier, 80_000_000), to_key(buyer, 20_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 80_000_000 },
    ref,
    tx,
  )
}

/// Two missing leeks: below the threshold, credited without arbitration.
test trivial_gap_settles_without_dispute() {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_key(supplier, 79_000_000), to_key(buyer, 21_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 79_000_000 },
    ref,
    tx,
  )
}

/// Significant gap: the undisputed part is NOT paid out yet, the order moves
/// to dispute and the escrow stays intact.
test significant_gap_becomes_dispute() {
  let after =
    Disputed {
      manifest_total: 80_000_000,
      accepted_total: 60_000_000,
      receipt: #"ff",
      declared_at: 10_200,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_script(100_000_000, after)],
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 60_000_000 },
    ref,
    tx,
  )
}

/// The buyer's silence counts as acceptance: past the window, the supplier
/// collects its manifest.
test silence_counts_as_acceptance() {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_key(supplier, 80_000_000), to_key(buyer, 20_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_600, 10_700),
      extra_signatories: [supplier],
    }
  order.spend(Some(dat(shipped)), ClaimSilence, ref, tx)
}

/// Silent arbiter: past the delay, the buyer's figure prevails.
test silent_arbiter_lets_the_buyer_win() {
  let dispute =
    Disputed {
      manifest_total: 80_000_000,
      accepted_total: 60_000_000,
      receipt: #"ff",
      declared_at: 10_100,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, dispute)],
      outputs: [to_key(supplier, 60_000_000), to_key(buyer, 40_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(11_200, 11_300),
      extra_signatories: [buyer],
    }
  order.spend(Some(dat(dispute)), CloseDispute, ref, tx)
}

// ### Abuse attempts

/// The supplier cannot claim before the end of the window.
test premature_silence_refused() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_key(supplier, 80_000_000), to_key(buyer, 20_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [supplier],
    }
  order.spend(Some(dat(shipped)), ClaimSilence, ref, tx)
}

/// The supplier cannot declare reception in the buyer's place.
test supplier_cannot_declare_reception() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_key(supplier, 80_000_000), to_key(buyer, 20_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [supplier],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 80_000_000 },
    ref,
    tx,
  )
}

/// The buyer cannot get more back than it is owed by declaring a reception
/// above the manifest.
test declaration_above_manifest_refused() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_key(supplier, 90_000_000), to_key(buyer, 10_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 90_000_000 },
    ref,
    tx,
  )
}

/// The supplier cannot siphon the escrow on the way into dispute.
test escrow_cannot_leak_into_dispute() fail {
  let after =
    Disputed {
      manifest_total: 80_000_000,
      accepted_total: 60_000_000,
      receipt: #"ff",
      declared_at: 10_200,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_script(40_000_000, after), to_key(supplier, 60_000_000)],
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 60_000_000 },
    ref,
    tx,
  )
}

/// The arbiter cannot award the supplier more than its own manifest: its
/// power is bounded on both sides.
test arbiter_cannot_exceed_the_manifest() fail {
  let dispute =
    Disputed {
      manifest_total: 80_000_000,
      accepted_total: 60_000_000,
      receipt: #"ff",
      declared_at: 10_100,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, dispute)],
      outputs: [to_key(supplier, 95_000_000), to_key(buyer, 5_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_200, 10_300),
      extra_signatories: [arbiter],
    }
  order.spend(
    Some(dat(dispute)),
    Arbitrate { final_total: 95_000_000 },
    ref,
    tx,
  )
}

// ### Timestamp forgery (regression tests for the `event_time` fix)
//
// Before the fix, `horodatage` read the LOWER bound of the validity range.
// A transaction with `invalid_before = 0` is valid at any slot, so both
// parties could write an arbitrary past timestamp and expire the deadline
// that protected the other side. The five tests below are the ones that
// previously passed as successful attacks.

const accepted_state = Accepted { lines: #"aa", total: 100_000_000 }

/// The recorded timestamp is the upper bound of the validity range.
test shipment_timestamp_is_the_upper_bound() {
  let after =
    Shipped { manifest: #"ee", manifest_total: 80_000_000, shipped_at: 10_200 }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, accepted_state)],
      outputs: [to_script(100_000_000, after)],
      validity_range: interval.between(10_000, 10_200),
      extra_signatories: [supplier],
    }
  order.spend(
    Some(dat(accepted_state)),
    Ship { manifest: #"ee", manifest_total: 80_000_000 },
    ref,
    tx,
  )
}

/// ATTACK, now blocked: the supplier back-dates its shipment so that the
/// buyer's reception window has already expired, then collects the full
/// manifest through `ClaimSilence` without the buyer ever declaring.
test supplier_cannot_backdate_shipment() fail {
  let after =
    Shipped { manifest: #"ee", manifest_total: 80_000_000, shipped_at: 0 }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, accepted_state)],
      outputs: [to_script(100_000_000, after)],
      validity_range: interval.between(0, 10_200),
      extra_signatories: [supplier],
    }
  order.spend(
    Some(dat(accepted_state)),
    Ship { manifest: #"ee", manifest_total: 80_000_000 },
    ref,
    tx,
  )
}

/// ATTACK, now blocked: the buyer back-dates its declaration so that the
/// arbitration window has already expired, then closes the dispute at its own
/// figure. This one voided the arbiter entirely.
test buyer_cannot_backdate_declaration() fail {
  let after =
    Disputed {
      manifest_total: 80_000_000,
      accepted_total: 10_000_000,
      receipt: #"ff",
      declared_at: 0,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_script(100_000_000, after)],
      validity_range: interval.between(0, 10_400),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 10_000_000 },
    ref,
    tx,
  )
}

/// A timestamp cannot be recorded from an open-ended validity range: there
/// would be no latest slot to pin it to.
test unbounded_validity_range_refused() fail {
  let after =
    Shipped { manifest: #"ee", manifest_total: 80_000_000, shipped_at: 10_200 }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, accepted_state)],
      outputs: [to_script(100_000_000, after)],
      validity_range: interval.after(10_000),
      extra_signatories: [supplier],
    }
  order.spend(
    Some(dat(accepted_state)),
    Ship { manifest: #"ee", manifest_total: 80_000_000 },
    ref,
    tx,
  )
}

/// Nor from an absurdly wide one: forward-dating is the supplier's only
/// remaining freedom, and it would lock the buyer's escrow for as long as it
/// likes. `max_validity_span` caps it.
test oversized_validity_range_refused() fail {
  let after =
    Shipped {
      manifest: #"ee",
      manifest_total: 80_000_000,
      shipped_at: 20_000_000,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, accepted_state)],
      outputs: [to_script(100_000_000, after)],
      validity_range: interval.between(0, 20_000_000),
      extra_signatories: [supplier],
    }
  order.spend(
    Some(dat(accepted_state)),
    Ship { manifest: #"ee", manifest_total: 80_000_000 },
    ref,
    tx,
  )
}

/// The reception window now runs from the sealed upper-bound timestamp, so a
/// claim at 10_600 against a shipment sealed at 10_200 is still premature.
test reception_window_runs_from_the_sealed_timestamp() fail {
  let sealed =
    Shipped { manifest: #"ee", manifest_total: 80_000_000, shipped_at: 10_200 }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, sealed)],
      outputs: [to_key(supplier, 80_000_000), to_key(buyer, 20_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_600, 10_700),
      extra_signatories: [supplier],
    }
  order.spend(Some(dat(sealed)), ClaimSilence, ref, tx)
}

// ### Fee accounting (regression tests for the removed `self.fee` allowance)
//
// Every other test in this file runs on `placeholder`, where `fee` is zero,
// so none of them exercise this. These set a real fee.

/// ATTACK, now blocked: the supplier claims silence with a padded 3 ADA fee
/// and hands the buyer only 17 ADA of the 20 it is owed. The 3 ADA came out
/// of the buyer's refund; the supplier's own net take was unchanged, so it
/// cost the supplier nothing to inflate.
test supplier_cannot_charge_its_fee_to_the_buyer() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped)],
      outputs: [to_key(supplier, 80_000_000), to_key(buyer, 17_000_000)],
      mint: from_asset(policy, token, -1),
      fee: 3_000_000,
      validity_range: interval.between(10_600, 10_700),
      extra_signatories: [supplier],
    }
  order.spend(Some(dat(shipped)), ClaimSilence, ref, tx)
}

/// The correct construction: the supplier brings its own 5 ADA input, pays
/// the 3 ADA fee from it, and the buyer still receives the full 20 ADA.
/// The supplier nets 77 ADA on an 80 ADA claim — it bore its own fee.
test supplier_funds_its_own_fee_on_a_silence_claim() {
  let funding =
    Input { output_reference: ref_b, output: to_key(supplier, 5_000_000) }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped), funding],
      outputs: [to_key(supplier, 82_000_000), to_key(buyer, 20_000_000)],
      mint: from_asset(policy, token, -1),
      fee: 3_000_000,
      validity_range: interval.between(10_600, 10_700),
      extra_signatories: [supplier],
    }
  order.spend(Some(dat(shipped)), ClaimSilence, ref, tx)
}

/// The same allowance existed on `Cancel`: a refund short by the fee amount
/// is no longer a full refund.
test cancellation_refund_is_not_reduced_by_the_fee() fail {
  let created = Created { request: #"aa" }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, created)],
      outputs: [to_key(buyer, 97_000_000)],
      mint: from_asset(policy, token, -1),
      fee: 3_000_000,
      validity_range: interval.between(100, 200),
      extra_signatories: [buyer],
    }
  order.spend(Some(dat(created)), Cancel, ref, tx)
}

// ### Double satisfaction (regression tests for the one-order-per-tx rule)

/// A wallet input funding the fee is not a script input, so ordinary
/// settlement still works. This is the test that proves the fix is not
/// over-restrictive.
test wallet_input_alongside_the_order_is_fine() {
  let funding =
    Input { output_reference: ref_b, output: to_key(buyer, 5_000_000) }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(100_000_000, shipped), funding],
      outputs: [to_key(supplier, 80_000_000), to_key(buyer, 25_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 80_000_000 },
    ref,
    tx,
  )
}

/// ATTACK, now blocked: two orders from the same buyer/supplier pair settled
/// in one transaction. `paid_to` counts OUTPUTS, not per-order flow, so a
/// single 80 ADA payment used to satisfy both validator invocations — the
/// supplier delivered 160 ADA of goods and collected 80.
test double_satisfaction_refused() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [
        script_input_with(ref, token, 100_000_000, shipped),
        script_input_with(ref_b, token_b, 100_000_000, shipped),
      ],
      outputs: [to_key(supplier, 80_000_000), to_key(buyer, 120_000_000)],
      mint: merge(
        from_asset(policy, token, -1),
        from_asset(policy, token_b, -1),
      ),
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  and {
    order.spend(
      Some(datum_of(token, shipped)),
      Declare { receipt: #"ff", accepted_total: 80_000_000 },
      ref,
      tx,
    ),
    order.spend(
      Some(datum_of(token_b, shipped)),
      Declare { receipt: #"ff", accepted_total: 80_000_000 },
      ref_b,
      tx,
    ),
  }
}

// ### The security invariant, as a property
//
// The supplier can never collect more than the manifest it sealed itself,
// whichever path the order takes out of escrow. Everything else in this
// contract is machinery; this is the promise.

/// Builds an order datum with a chosen tolerance, all else fixed.
fn order_with_tolerance(tolerance: Int, state: State) -> Order {
  Order {
    token,
    buyer,
    supplier,
    arbiter,
    terms: Terms {
      acceptance_deadline: 20_000,
      reception_window: 500,
      dispute_window: 1_000,
      tolerance,
    },
    state,
  }
}

/// A settling transaction: order in, token burned, supplier and buyer paid.
fn settlement_tx(
  d: Order,
  escrow: Int,
  payout: Int,
  range: Interval<Int>,
  signers: List<VerificationKeyHash>,
) -> Transaction {
  let locked =
    Output {
      address: Address {
        payment_credential: Script(policy),
        stake_credential: None,
      },
      value: merge(from_lovelace(escrow), from_asset(policy, d.token, 1)),
      datum: InlineDatum(d),
      reference_script: None,
    }
  Transaction {
    ..placeholder,
    inputs: [Input { output_reference: ref, output: locked }],
    outputs: [to_key(supplier, payout), to_key(buyer, escrow - payout)],
    mint: from_asset(policy, token, -1),
    validity_range: range,
    extra_signatories: signers,
  }
}

/// For any of the four paths by which value leaves the escrow, and for any
/// generated totals: if the validator accepts the transaction, the supplier
/// received no more than `manifest_total`.
///
/// The payout is the amount each path actually settles, not a free variable.
/// `settle` pins the payout to the amount owed exactly, so generating it
/// independently means the validator almost never accepts and the implication
/// holds vacuously — which is how the first version of this test passed while
/// catching nothing. The one payout left free is the arbiter's ruling,
/// because bounding that ruling is exactly what is under test.
///
/// The two free totals are folded into [0, 2 * manifest_total] so that about
/// half of all generated cases are ones the validator MUST reject. That is a
/// distribution choice, not a correctness crutch: the assertion still ranges
/// over values well above the manifest.
///
/// Verified by mutation. Weakening `admissible` in `Declare`, or the
/// `final_total <= manifest_total` bound in `Arbitrate`, each make this fail.
test supplier_never_collects_more_than_its_manifest(
  s via fuzz.tuple5(
    fuzz.int_between(1_000_000, 100_000_000),
    fuzz.int_between(0, 200_000_000),
    fuzz.int_between(0, 10_000_000),
    fuzz.int_between(0, 200_000_000),
    fuzz.int_between(0, 3),
  ),
) {
  let (manifest_total, wide_accepted, tolerance, wide_arbitrated, path) = s
  let escrow = 400_000_000
  let span = 2 * manifest_total + 1
  let raw_accepted = wide_accepted % span
  let arbitrated = wide_arbitrated % span

  let sealed = Shipped { manifest: #"ee", manifest_total, shipped_at: 10_000 }

  // A Disputed datum can only ever have been produced by `Declare`, which
  // enforces `admissible`. Generating one where the buyer declared more than
  // the manifest would test a state the ledger cannot reach, and would report
  // a bug that does not exist.
  let reachable_declared =
    if raw_accepted > manifest_total {
      manifest_total
    } else {
      raw_accepted
    }
  let contested =
    Disputed {
      manifest_total,
      accepted_total: reachable_declared,
      receipt: #"ff",
      declared_at: 10_200,
    }

  // Keep `Declare` on its settling branch whatever the generated gap: the
  // dispute branch parks the value at the script rather than paying it out,
  // so it is not a path by which the supplier collects anything.
  let gap = manifest_total - raw_accepted
  let wide_enough =
    if gap > tolerance {
      gap
    } else {
      tolerance
    }

  let (d, action, range, signers, payout) =
    if path == 0 {
      (
        order_with_tolerance(wide_enough, sealed),
        Declare { receipt: #"ff", accepted_total: raw_accepted },
        interval.between(10_100, 10_200),
        [buyer],
        raw_accepted,
      )
    } else if path == 1 {
      (
        order_with_tolerance(tolerance, sealed),
        ClaimSilence,
        interval.between(10_600, 10_700),
        [supplier],
        manifest_total,
      )
    } else if path == 2 {
      (
        order_with_tolerance(tolerance, contested),
        Arbitrate { final_total: arbitrated },
        interval.between(10_300, 10_400),
        [arbiter],
        arbitrated,
      )
    } else {
      (
        order_with_tolerance(tolerance, contested),
        CloseDispute,
        interval.between(11_300, 11_400),
        [buyer],
        reachable_declared,
      )
    }

  let tx = settlement_tx(d, escrow, payout, range, signers)
  let validator_accepts = order.spend(Some(d), action, ref, tx)

  !validator_accepts || payout <= manifest_total
}

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
  continuing_output, event_time, paid_to, script_input_count, signature_count,
  signed_by, token_burned, token_name, well_formed_panel,
}
use bonlivraison/types.{
  Accept, Accepted, Action, Arbitrate, Arbitration, Cancel, ClaimSilence, Close,
  CloseDispute, Created, Declare, Disputed, Open, Order, Ship, Shipped, State,
  Terms, TokenAction,
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
    // Not an escrow: only the min-ADA that lets this UTxO exist. It returns
    // to the buyer when the order closes.
    let deposit = lovelace_of(input.output.value)

    and {
      // One order per transaction. Three reasons, in order of weight.
      //
      // 1. `paid_to` reads the transaction as a whole, not a flow attributable
      //    to one order. Two orders closed together would both be discharged
      //    by a single deposit refund, and whoever built the transaction would
      //    pocket the other. That is only ~2 ADA per order rather than a whole
      //    delivery, but two orders from the same buyer/supplier pair on the
      //    same morning is the normal case in food service, not an edge case.
      //
      // 2. One transition, one transaction, one attestation. CIP-0170 counts
      //    signed attestations carrying a declared identifier, so a batched
      //    transaction would collapse several attestations into one counted
      //    event.
      //
      // 3. Nothing is lost. One order = one UTxO = one state token, so orders
      //    never contend for the same UTxO and there is no throughput reason
      //    to batch. Wallet inputs funding the fee are unaffected: only inputs
      //    locked by this script are counted.
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
            continues(
              self,
              address,
              policy,
              d,
              Accepted { lines, total },
              deposit,
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
            // Deposit back in full, fee on the canceller. Same reasoning as
            // `close_order`.
            (paid_to(self, d.buyer) >= deposit)?,
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
              deposit,
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
            // Significant gap: the order stays open and the two opposing
            // figures stay on the record until the panel rules or the window
            // expires.
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
                  deposit,
                )?,
              }
            // Exact or trivial: close the record now, no arbitration.
            _ -> and {
                preconditions,
                close_order(self, d, policy, deposit)?,
              }
          }
        }

        // --- The buyer's silence counts as acceptance ----------------------
        ClaimSilence -> {
          // The attested figure on this path is the sealed manifest itself.
          // It is on the record in the datum; nothing needs to move.
          expect Shipped { shipped_at, .. } = d.state
          and {
            signed_by(self, d.supplier)?,
            interval.is_entirely_after(
              self.validity_range,
              shipped_at + d.terms.reception_window,
            )?,
            close_order(self, d, policy, deposit)?,
          }
        }

        // --- The arbiter rules, within bounds it does not choose -----------
        Arbitrate { final_total } -> {
          expect Disputed { manifest_total, accepted_total, declared_at, .. } =
            d.state
          and {
            (signature_count(self, d.arbitration.keys) >= d.arbitration.threshold)?,
            (final_total >= accepted_total)?,
            (final_total <= manifest_total)?,
            interval.is_entirely_before(
              self.validity_range,
              declared_at + d.terms.dispute_window,
            )?,
            close_order(self, d, policy, deposit)?,
          }
        }

        // --- The arbiter never ruled: the buyer prevails -------------------
        CloseDispute -> {
          // The attested figure on this path is the buyer's declaration,
          // already on the record in the datum.
          expect Disputed { declared_at, .. } = d.state
          and {
            interval.is_entirely_after(
              self.validity_range,
              declared_at + d.terms.dispute_window,
            )?,
            or {
              signed_by(self, d.buyer),
              signed_by(self, d.supplier),
            }?,
            close_order(self, d, policy, deposit)?,
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
          // The only point where this datum is created rather than carried
          // forward by `continues`, so the only place a malformed arbitration
          // panel can be caught.
          well_formed_panel(d.arbitration.keys, d.arbitration.threshold)?,
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
  deposit: Int,
) -> Bool {
  let output = continuing_output(self, address, policy, previous.token)
  expect InlineDatum(raw) = output.datum
  expect next: Order = raw
  and {
    (next.token == previous.token)?,
    (next.buyer == previous.buyer)?,
    (next.supplier == previous.supplier)?,
    (next.arbitration == previous.arbitration)?,
    (next.terms == previous.terms)?,
    (next.state == new_state)?,
    // The deposit cannot leak along the way. It is only min-ADA, but it is
    // the buyer's, and it must survive to be returned at closing.
    (lovelace_of(output.value) >= deposit)?,
  }
}

/// Final closing: the state token is burned and the deposit returns to the
/// buyer.
///
/// No money changes hands here, and none ever did. The figure each path put
/// on the record — the buyer's declaration, the sealed manifest, the panel's
/// ruling — is an attested amount in euro cents. Payment follows by SEPA
/// transfer, off-chain. What this transaction leaves behind is the record.
///
/// The amount owed is therefore not a parameter: the bounds that matter are
/// enforced where each figure is written (`admissible` in `Declare`, the two
/// bounds in `Arbitrate`), not here.
///
/// The deposit returns in full, with the fee on whoever submits. An earlier
/// version allowed `paid_to(buyer) + self.fee`, letting a supplier inflate the
/// fee at zero cost to itself and take the difference out of the buyer's
/// refund. Small per delivery, levied on every delivery, against the party
/// this product exists to protect. It also broke the adoption metric: each
/// party must pay its own fees from its own wallet, and a fee drawn from the
/// buyer's deposit is not that.
fn close_order(
  self: Transaction,
  d: Order,
  policy: PolicyId,
  deposit: Int,
) -> Bool {
  and {
    token_burned(self, policy, d.token)?,
    (paid_to(self, d.buyer) >= deposit)?,
  }
}

// ## Scenarios
//
// End-to-end simulated transactions. Nominal paths matter, attempted abuse
// matters more.
//
// Every total below is an ATTESTED FIGURE IN EURO CENTS. The only lovelace
// figure is `min_ada`: the deposit that keeps the order UTxO alive and returns
// to the buyer at closing.

const buyer = #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

const supplier = #"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

/// The independent seat on the arbitration panel.
///
/// The other two seats are the buyer and the supplier themselves. Two
/// signatures rule, so the parties agreeing settles their own dispute, and
/// this key only breaks a tie. The platform holds no seat at all — with a
/// seat it could always swing a dispute by siding with one party, which is
/// the neutrality problem the whole design exists to remove.
const third_party = #"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"

const outsider = #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

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

/// Min-ADA on the order UTxO. Not an escrow: the buyer gets it back.
const min_ada: Int = 2_000_000

fn panel() -> Arbitration {
  Arbitration { keys: [buyer, supplier, third_party], threshold: 2 }
}

fn terms() -> Terms {
  Terms {
    acceptance_deadline: 20_000,
    reception_window: 500,
    dispute_window: 1_000,
    // 15 EUR
    tolerance: 1_500,
  }
}

fn datum_of(t: ByteArray, state: State) -> Order {
  Order {
    token: t,
    buyer,
    supplier,
    arbitration: panel(),
    terms: terms(),
    state,
  }
}

fn dat(state: State) -> Order {
  datum_of(token, state)
}

fn to_script_with(t: ByteArray, lovelace: Int, state: State) -> Output {
  Output {
    address: Address {
      payment_credential: Script(policy),
      stake_credential: None,
    },
    value: merge(from_lovelace(lovelace), from_asset(policy, t, 1)),
    datum: InlineDatum(datum_of(t, state)),
    reference_script: None,
  }
}

fn to_script(lovelace: Int, state: State) -> Output {
  to_script_with(token, lovelace, state)
}

fn to_key(who: ByteArray, lovelace: Int) -> Output {
  Output {
    address: Address {
      payment_credential: VerificationKey(who),
      stake_credential: None,
    },
    value: from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

fn script_input_with(
  r: OutputReference,
  t: ByteArray,
  lovelace: Int,
  state: State,
) -> Input {
  Input { output_reference: r, output: to_script_with(t, lovelace, state) }
}

fn script_input(lovelace: Int, state: State) -> Input {
  script_input_with(ref, token, lovelace, state)
}

/// 800 EUR sealed against a 1000 EUR order.
const shipped =
  Shipped { manifest: #"ee", manifest_total: 80_000, shipped_at: 10_000 }

const accepted_state = Accepted { lines: #"aa", total: 100_000 }

/// A closing transaction: token burned, deposit back to the buyer.
fn closing_tx(
  state: State,
  range: Interval<Int>,
  signers: List<VerificationKeyHash>,
) -> Transaction {
  Transaction {
    ..placeholder,
    inputs: [script_input(min_ada, state)],
    outputs: [to_key(buyer, min_ada)],
    mint: from_asset(policy, token, -1),
    validity_range: range,
    extra_signatories: signers,
  }
}

// ### Nominal paths

/// Everything arrived: the buyer attests the full manifest and the record
/// closes. No value moves — the 800 EUR is paid by SEPA, off-chain.
test nominal_closes_immediately() {
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 80_000 },
    ref,
    closing_tx(shipped, interval.between(10_100, 10_200), [buyer]),
  )
}

/// Two missing leeks: 10 EUR short, below the 15 EUR threshold, credited
/// without arbitration.
test trivial_gap_closes_without_dispute() {
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 79_000 },
    ref,
    closing_tx(shipped, interval.between(10_100, 10_200), [buyer]),
  )
}

/// A 200 EUR gap: the order stays open, both figures stay on the record, and
/// the deposit stays put.
test significant_gap_becomes_dispute() {
  let after =
    Disputed {
      manifest_total: 80_000,
      accepted_total: 60_000,
      receipt: #"ff",
      declared_at: 10_200,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, shipped)],
      outputs: [to_script(min_ada, after)],
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 60_000 },
    ref,
    tx,
  )
}

/// Past the window, the buyer's silence puts the sealed manifest on the
/// record as the agreed figure.
test silence_counts_as_acceptance() {
  order.spend(
    Some(dat(shipped)),
    ClaimSilence,
    ref,
    closing_tx(shipped, interval.between(10_600, 10_700), [supplier]),
  )
}

const dispute_case =
  Disputed {
    manifest_total: 80_000,
    accepted_total: 60_000,
    receipt: #"ff",
    declared_at: 10_100,
  }

/// Nobody ruled in time: the buyer's figure stands.
test silent_panel_lets_the_buyer_win() {
  order.spend(
    Some(dat(dispute_case)),
    CloseDispute,
    ref,
    closing_tx(dispute_case, interval.between(11_200, 11_300), [buyer]),
  )
}

/// The buyer opens, then withdraws before the supplier accepts. Deposit back.
test buyer_can_cancel_before_acceptance() {
  let created = Created { request: #"aa" }
  order.spend(
    Some(dat(created)),
    Cancel,
    ref,
    closing_tx(created, interval.between(100, 200), [buyer]),
  )
}

// ### Abuse attempts

/// The supplier cannot claim before the end of the window.
test premature_silence_refused() fail {
  order.spend(
    Some(dat(shipped)),
    ClaimSilence,
    ref,
    closing_tx(shipped, interval.between(10_100, 10_200), [supplier]),
  )
}

/// The supplier cannot declare reception in the buyer's place.
test supplier_cannot_declare_reception() fail {
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 80_000 },
    ref,
    closing_tx(shipped, interval.between(10_100, 10_200), [supplier]),
  )
}

/// The buyer cannot attest receiving more than the supplier sealed. This is
/// the min() rule, and it is the one arithmetic bound the chain enforces.
test declaration_above_manifest_refused() fail {
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 90_000 },
    ref,
    closing_tx(shipped, interval.between(10_100, 10_200), [buyer]),
  )
}

/// The deposit cannot be siphoned on the way into dispute.
test deposit_cannot_leak_into_dispute() fail {
  let after =
    Disputed {
      manifest_total: 80_000,
      accepted_total: 60_000,
      receipt: #"ff",
      declared_at: 10_200,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, shipped)],
      outputs: [to_script(500_000, after), to_key(supplier, 1_500_000)],
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 60_000 },
    ref,
    tx,
  )
}

/// The panel cannot record a figure above the supplier's own manifest.
test panel_cannot_exceed_the_manifest() fail {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 95_000 },
    ref,
    closing_tx(
      dispute_case,
      interval.between(10_200, 10_300),
      [buyer, supplier],
    ),
  )
}

/// Nor below what the buyer already conceded.
test panel_cannot_go_below_the_declaration() fail {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 50_000 },
    ref,
    closing_tx(
      dispute_case,
      interval.between(10_200, 10_300),
      [buyer, supplier],
    ),
  )
}

// ### Timestamp forgery (regression tests for the `event_time` fix)
//
// Before the fix, the recorded timestamp read the LOWER bound of the validity
// range. A transaction with `invalid_before = 0` is valid at any slot, so
// either party could write an arbitrary past timestamp and expire the deadline
// that protected the other side. With no money on the chain, this sequencing
// is the entire product — these are the most important tests in the file.

/// The recorded timestamp is the upper bound of the validity range.
test shipment_timestamp_is_the_upper_bound() {
  let after =
    Shipped { manifest: #"ee", manifest_total: 80_000, shipped_at: 10_200 }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, accepted_state)],
      outputs: [to_script(min_ada, after)],
      validity_range: interval.between(10_000, 10_200),
      extra_signatories: [supplier],
    }
  order.spend(
    Some(dat(accepted_state)),
    Ship { manifest: #"ee", manifest_total: 80_000 },
    ref,
    tx,
  )
}

/// ATTACK, now blocked: the supplier back-dates its shipment so the buyer's
/// reception window has already expired, then puts the full manifest on the
/// record through `ClaimSilence` without the buyer ever declaring.
test supplier_cannot_backdate_shipment() fail {
  let after = Shipped { manifest: #"ee", manifest_total: 80_000, shipped_at: 0 }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, accepted_state)],
      outputs: [to_script(min_ada, after)],
      validity_range: interval.between(0, 10_200),
      extra_signatories: [supplier],
    }
  order.spend(
    Some(dat(accepted_state)),
    Ship { manifest: #"ee", manifest_total: 80_000 },
    ref,
    tx,
  )
}

/// ATTACK, now blocked: the buyer back-dates its declaration so the dispute
/// window has already expired, then closes at its own figure. This one voided
/// the panel entirely.
test buyer_cannot_backdate_declaration() fail {
  let after =
    Disputed {
      manifest_total: 80_000,
      accepted_total: 10_000,
      receipt: #"ff",
      declared_at: 0,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, shipped)],
      outputs: [to_script(min_ada, after)],
      validity_range: interval.between(0, 10_400),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 10_000 },
    ref,
    tx,
  )
}

/// A timestamp cannot be recorded from an open-ended validity range.
test unbounded_validity_range_refused() fail {
  let after =
    Shipped { manifest: #"ee", manifest_total: 80_000, shipped_at: 10_200 }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, accepted_state)],
      outputs: [to_script(min_ada, after)],
      validity_range: interval.after(10_000),
      extra_signatories: [supplier],
    }
  order.spend(
    Some(dat(accepted_state)),
    Ship { manifest: #"ee", manifest_total: 80_000 },
    ref,
    tx,
  )
}

/// Nor from an absurdly wide one: forward-dating is the supplier's only
/// remaining freedom, and it would hold the order open as long as it likes.
test oversized_validity_range_refused() fail {
  let after =
    Shipped { manifest: #"ee", manifest_total: 80_000, shipped_at: 20_000_000 }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, accepted_state)],
      outputs: [to_script(min_ada, after)],
      validity_range: interval.between(0, 20_000_000),
      extra_signatories: [supplier],
    }
  order.spend(
    Some(dat(accepted_state)),
    Ship { manifest: #"ee", manifest_total: 80_000 },
    ref,
    tx,
  )
}

/// The reception window runs from the sealed upper-bound timestamp.
test reception_window_runs_from_the_sealed_timestamp() fail {
  let sealed =
    Shipped { manifest: #"ee", manifest_total: 80_000, shipped_at: 10_200 }
  order.spend(
    Some(dat(sealed)),
    ClaimSilence,
    ref,
    closing_tx(sealed, interval.between(10_600, 10_700), [supplier]),
  )
}

// ### Fee accounting (regression tests for the removed `self.fee` allowance)
//
// Every other test runs on `placeholder`, where `fee` is zero, so none of them
// exercise this. These set a real fee. The amount at stake is now the min-ADA
// deposit rather than an escrow — but at ~2 ADA per order it is larger than
// the fee being griefed, and it comes out of the restaurant's pocket.

/// ATTACK, now blocked: the supplier claims silence with a padded fee and
/// returns only part of the deposit. The shortfall came out of the buyer's
/// refund; the supplier's own position was unchanged, so inflating cost it
/// nothing.
test supplier_cannot_charge_its_fee_to_the_buyer() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, shipped)],
      outputs: [to_key(buyer, 1_500_000)],
      mint: from_asset(policy, token, -1),
      fee: 500_000,
      validity_range: interval.between(10_600, 10_700),
      extra_signatories: [supplier],
    }
  order.spend(Some(dat(shipped)), ClaimSilence, ref, tx)
}

/// The correct construction: the supplier brings its own input and pays the
/// fee from it. The buyer's deposit comes back whole.
test supplier_funds_its_own_fee_on_a_silence_claim() {
  let funding =
    Input { output_reference: ref_b, output: to_key(supplier, 5_000_000) }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, shipped), funding],
      outputs: [to_key(buyer, min_ada), to_key(supplier, 4_500_000)],
      mint: from_asset(policy, token, -1),
      fee: 500_000,
      validity_range: interval.between(10_600, 10_700),
      extra_signatories: [supplier],
    }
  order.spend(Some(dat(shipped)), ClaimSilence, ref, tx)
}

/// The same allowance existed on `Cancel`.
test cancellation_refund_is_not_reduced_by_the_fee() fail {
  let created = Created { request: #"aa" }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, created)],
      outputs: [to_key(buyer, 1_500_000)],
      mint: from_asset(policy, token, -1),
      fee: 500_000,
      validity_range: interval.between(100, 200),
      extra_signatories: [buyer],
    }
  order.spend(Some(dat(created)), Cancel, ref, tx)
}

// ### One order per transaction

/// A wallet input funding the fee is not a script input, so ordinary closing
/// still works. This proves the rule is not over-restrictive.
test wallet_input_alongside_the_order_is_fine() {
  let funding =
    Input { output_reference: ref_b, output: to_key(buyer, 5_000_000) }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, shipped), funding],
      outputs: [to_key(buyer, 7_000_000)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 80_000 },
    ref,
    tx,
  )
}

/// ATTACK, now blocked: two orders closed in one transaction, both discharged
/// by a single deposit refund. Whoever built it pockets the other deposit —
/// and two attestations collapse into one counted transaction.
test double_satisfaction_refused() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [
        script_input_with(ref, token, min_ada, shipped),
        script_input_with(ref_b, token_b, min_ada, shipped),
      ],
      outputs: [to_key(buyer, min_ada)],
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
      Declare { receipt: #"ff", accepted_total: 80_000 },
      ref,
      tx,
    ),
    order.spend(
      Some(datum_of(token_b, shipped)),
      Declare { receipt: #"ff", accepted_total: 80_000 },
      ref_b,
      tx,
    ),
  }
}

// ### Arbitration panel (2-of-3: buyer, supplier, independent third party)

/// The two parties agree. No third party needed, and none involved.
test the_two_parties_can_settle_their_own_dispute() {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 70_000 },
    ref,
    closing_tx(
      dispute_case,
      interval.between(10_200, 10_300),
      [buyer, supplier],
    ),
  )
}

/// They disagree, so the independent seat breaks the tie with the supplier.
test the_third_party_can_break_a_tie() {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 75_000 },
    ref,
    closing_tx(
      dispute_case,
      interval.between(10_200, 10_300),
      [supplier, third_party],
    ),
  )
}

/// No single seat can rule alone. This is the whole point: with the platform
/// holding no key, and neither party able to act unilaterally, nobody can
/// decide a dispute on their own.
test one_seat_alone_cannot_rule() fail {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 70_000 },
    ref,
    closing_tx(dispute_case, interval.between(10_200, 10_300), [supplier]),
  )
}

/// Padding the signature list with keys outside the panel reaches nothing.
test signatures_outside_the_panel_do_not_count() fail {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 70_000 },
    ref,
    closing_tx(
      dispute_case,
      interval.between(10_200, 10_300),
      [supplier, outsider, third_party_impostor()],
    ),
  )
}

fn third_party_impostor() -> VerificationKeyHash {
  #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
}

// ### Panel well-formedness, checked at minting
//
// Also the first tests of the `Open` handler, which previously had none.

fn open_tx(arbitration: Arbitration) -> Transaction {
  let seed = ref_b
  let name = token_name(seed)
  let born =
    Output {
      address: Address {
        payment_credential: Script(policy),
        stake_credential: None,
      },
      value: merge(from_lovelace(min_ada), from_asset(policy, name, 1)),
      datum: InlineDatum(
        Order {
          token: name,
          buyer,
          supplier,
          arbitration,
          terms: terms(),
          state: Created { request: #"aa" },
        },
      ),
      reference_script: None,
    }
  Transaction {
    ..placeholder,
    inputs: [
      Input { output_reference: seed, output: to_key(buyer, 10_000_000) },
    ],
    outputs: [born],
    mint: from_asset(policy, name, 1),
  }
}

/// Nominal opening: seed consumed, token derived from it, panel well formed.
test order_opens_with_a_well_formed_panel() {
  order.mint(
    Open { seed: ref_b },
    policy,
    open_tx(Arbitration { keys: [buyer, supplier, third_party], threshold: 2 }),
  )
}

/// A zero threshold would let anyone rule on a dispute.
test zero_threshold_panel_refused() fail {
  order.mint(
    Open { seed: ref_b },
    policy,
    open_tx(Arbitration { keys: [buyer, supplier, third_party], threshold: 0 }),
  )
}

/// A threshold above the panel size makes ruling impossible, stranding every
/// dispute on the timeout path where the buyer's figure wins by default.
test threshold_above_panel_size_refused() fail {
  order.mint(
    Open { seed: ref_b },
    policy,
    open_tx(Arbitration { keys: [buyer, supplier], threshold: 3 }),
  )
}

/// Duplicate keys would let one seat's signature count twice, turning a
/// nominal 2-of-3 into a seat that rules alone.
test duplicate_panel_keys_refused() fail {
  order.mint(
    Open { seed: ref_b },
    policy,
    open_tx(Arbitration { keys: [buyer, buyer, third_party], threshold: 2 }),
  )
}

// ### The security invariant, as a property
//
// The record can never carry a figure against the supplier larger than the
// manifest the supplier sealed itself, whichever path the order takes. With
// no money on the chain, this is the promise in full.

fn order_with_tolerance(tolerance: Int, state: State) -> Order {
  Order {
    token,
    buyer,
    supplier,
    arbitration: panel(),
    terms: Terms {
      acceptance_deadline: 20_000,
      reception_window: 500,
      dispute_window: 1_000,
      tolerance,
    },
    state,
  }
}

/// For any of the four paths that close an order, and for any generated
/// totals: if the validator accepts, the figure that path puts on the record
/// is no greater than `manifest_total`.
///
/// The attested figure is the amount each path actually records, not a free
/// variable — generating it independently would mean the validator almost
/// never accepts and the implication would hold vacuously, which is how the
/// first version of this test passed while catching nothing. The one figure
/// left free is the panel's ruling, because bounding that ruling is exactly
/// what is under test.
///
/// Verified by mutation. Weakening `admissible` in `Declare`, or the
/// `final_total <= manifest_total` bound in `Arbitrate`, each make this fail.
test attested_total_never_exceeds_the_manifest(
  s via fuzz.tuple5(
    fuzz.int_between(1_000, 10_000_000),
    fuzz.int_between(0, 20_000_000),
    fuzz.int_between(0, 5_000),
    fuzz.int_between(0, 20_000_000),
    fuzz.int_between(0, 3),
  ),
) {
  let (manifest_total, wide_accepted, tolerance, wide_ruling, path) = s
  let span = 2 * manifest_total + 1
  let raw_accepted = wide_accepted % span
  let ruling = wide_ruling % span

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

  // Keep `Declare` on its closing branch whatever the generated gap: the
  // dispute branch leaves the order open rather than recording a final
  // figure, so it is not a path that closes anything.
  let gap = manifest_total - raw_accepted
  let wide_enough =
    if gap > tolerance {
      gap
    } else {
      tolerance
    }

  let (d, action, range, signers, attested) =
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
        Arbitrate { final_total: ruling },
        interval.between(10_300, 10_400),
        [buyer, supplier],
        ruling,
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

  let tx =
    Transaction {
      ..placeholder,
      inputs: [
        Input {
          output_reference: ref,
          output: Output {
            address: Address {
              payment_credential: Script(policy),
              stake_credential: None,
            },
            value: merge(from_lovelace(min_ada), from_asset(policy, token, 1)),
            datum: InlineDatum(d),
            reference_script: None,
          },
        },
      ],
      outputs: [to_key(buyer, min_ada)],
      mint: from_asset(policy, token, -1),
      validity_range: range,
      extra_signatories: signers,
    }
  let validator_accepts = order.spend(Some(d), action, ref, tx)

  !validator_accepts || attested <= manifest_total
}

// ### Boundary tests
//
// A property test ranges widely but lands on exact boundaries only by luck.
// Once totals are euro cents, `tolerance` (15 EUR) is tiny next to
// `manifest_total` (800 EUR), so a bound widened by exactly the tolerance sits
// in a window the fuzzer will essentially never hit. These pin the boundaries
// directly.

/// One cent above the sealed manifest is already too much.
test panel_cannot_exceed_the_manifest_by_one_cent() fail {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 80_001 },
    ref,
    closing_tx(
      dispute_case,
      interval.between(10_200, 10_300),
      [buyer, supplier],
    ),
  )
}

/// Exactly the manifest is fine: the panel may side entirely with the supplier.
test panel_may_rule_exactly_the_manifest() {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 80_000 },
    ref,
    closing_tx(
      dispute_case,
      interval.between(10_200, 10_300),
      [buyer, supplier],
    ),
  )
}

/// One cent below what the buyer already conceded is too little.
test panel_cannot_go_below_the_declaration_by_one_cent() fail {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 59_999 },
    ref,
    closing_tx(
      dispute_case,
      interval.between(10_200, 10_300),
      [buyer, supplier],
    ),
  )
}

/// Exactly the declaration is fine: the panel may side entirely with the buyer.
test panel_may_rule_exactly_the_declaration() {
  order.spend(
    Some(dat(dispute_case)),
    Arbitrate { final_total: 60_000 },
    ref,
    closing_tx(
      dispute_case,
      interval.between(10_200, 10_300),
      [buyer, supplier],
    ),
  )
}

/// One cent above the manifest is refused on the buyer's own declaration too.
test declaration_one_cent_above_the_manifest_refused() fail {
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 80_001 },
    ref,
    closing_tx(shipped, interval.between(10_100, 10_200), [buyer]),
  )
}

/// The deposit belongs to the buyer. Closing an order without returning it —
/// here, handing it to the supplier instead — is refused.
test deposit_must_be_returned_at_closing() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [script_input(min_ada, shipped)],
      outputs: [to_key(supplier, min_ada)],
      mint: from_asset(policy, token, -1),
      validity_range: interval.between(10_100, 10_200),
      extra_signatories: [buyer],
    }
  order.spend(
    Some(dat(shipped)),
    Declare { receipt: #"ff", accepted_total: 80_000 },
    ref,
    tx,
  )
}

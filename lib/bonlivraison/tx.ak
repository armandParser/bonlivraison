//// Helpers for reading the transaction context.

use aiken/cbor
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash, blake2b_256}
use aiken/interval.{Finite, Interval}
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{AssetName, PolicyId, quantity_of}
use cardano/transaction.{Output, OutputReference, Transaction}

/// Widest validity range (ms) accepted on a transaction that records a
/// timestamp. See `event_time`.
///
/// Three hours is generous for a dock operation and still far too narrow to
/// be abused: it bounds how far a party can push a deadline that runs against
/// its counterparty.
pub const max_validity_span: Int = 3 * 60 * 60 * 1000

/// Does the transaction carry this key's signature?
pub fn signed_by(self: Transaction, who: VerificationKeyHash) -> Bool {
  list.has(self.extra_signatories, who)
}

/// Number of inputs in this transaction locked by the given script.
///
/// Used to enforce one order per transaction. See `paid_to` for why that
/// matters.
pub fn script_input_count(self: Transaction, policy: PolicyId) -> Int {
  list.count(
    self.inputs,
    fn(i) { i.output.address.payment_credential == Script(policy) },
  )
}

/// Total lovelace paid to a payment key by this transaction.
///
/// CAUTION: this measures a total over the whole transaction, not a flow
/// attributable to one order. Two orders settled together would each see the
/// same outputs and could both be satisfied by a single payment — the classic
/// double-satisfaction bug. Every caller therefore relies on the transaction
/// carrying exactly one input from this script, enforced once in the spend
/// handler via `script_input_count`.
pub fn paid_to(self: Transaction, who: VerificationKeyHash) -> Int {
  list.reduce(
    self.outputs,
    0,
    fn(acc, output) {
      when output.address.payment_credential is {
        VerificationKey(k) ->
          if k == who {
            acc + assets.lovelace_of(output.value)
          } else {
            acc
          }
        _ -> acc
      }
    },
  )
}

/// Timestamp recorded on-chain for an event that starts a deadline running
/// against the counterparty.
///
/// Returns the UPPER bound of the validity range: the latest slot at which
/// this transaction could possibly have been accepted by the ledger.
///
/// Why not the lower bound. A transaction with `invalid_before = 0` is valid
/// at any slot — the ledger never checks that the lower bound is anywhere
/// near "now". Reading the lower bound therefore lets the party building the
/// transaction write any past timestamp it likes, and both recorded
/// timestamps in this protocol start a countdown against the other side:
///
///   - the supplier back-dating `shipped_at` expires the buyer's reception
///     window before the buyer ever sees the goods, then collects the full
///     manifest via `ClaimSilence`;
///   - the buyer back-dating `declared_at` expires the arbitration window
///     immediately, then closes the dispute at its own figure via
///     `CloseDispute`, so the arbiter never gets to rule.
///
/// The upper bound is the pessimistic choice for whoever writes it: it can
/// only be pushed forward, which delays that party's own claim.
///
/// Pushing it forward still locks the escrow for longer, so the range is also
/// required to be finite on both ends and no wider than `max_validity_span`.
/// Between the two, a recorded timestamp is provably within
/// `max_validity_span` of the real inclusion slot.
///
/// Bound inclusivity is ignored: it shifts the result by at most one slot,
/// which is immaterial against windows measured in hours.
pub fn event_time(range: Interval<Int>) -> Int {
  expect Finite(lower) = range.lower_bound.bound_type
  expect Finite(upper) = range.upper_bound.bound_type
  expect upper >= lower
  expect upper - lower <= max_validity_span
  upper
}

/// The single output that carries the order back to the script, identified by
/// its state token. Fails if there is zero or more than one.
pub fn continuing_output(
  self: Transaction,
  address: Address,
  policy: PolicyId,
  token: AssetName,
) -> Output {
  expect [output] =
    list.filter(
      self.outputs,
      fn(o) { o.address == address && quantity_of(o.value, policy, token) == 1 },
    )
  output
}

/// Is the state token destroyed by this transaction?
pub fn token_burned(
  self: Transaction,
  policy: PolicyId,
  token: AssetName,
) -> Bool {
  quantity_of(self.mint, policy, token) == -1
}

/// Token name derived from a seed UTxO: guarantees an order can only ever
/// exist in a single copy.
pub fn token_name(seed: OutputReference) -> AssetName {
  blake2b_256(cbor.serialise(seed))
}

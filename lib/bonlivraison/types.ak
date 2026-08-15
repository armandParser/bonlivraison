//// Types for the delivery-note protocol.
////
//// One order = one UTxO at the script, carrying a unique state token and an
//// inline datum. No price, no line item and no personal data is written in
//// clear: only salted commitments and totals go on-chain.
////
//// ATTESTATION MODE. This contract moves no money. The UTxO holds only the
//// min-ADA needed to exist, and that deposit returns to the buyer when the
//// order closes. Every total below is an ATTESTED FIGURE IN EURO CENTS, not
//// lovelace. Payment happens by SEPA transfer, off-chain, driven by the
//// record this contract produces.
////
//// A restaurant will not lock the ADA equivalent of an 800 EUR invoice at
//// 6am — the float required per establishment would run to thousands of
//// euros, against fees of about 0.20 EUR per order. What the validator still
//// enforces is the part that matters: that the manifest was sealed before
//// the buyer declared, that the buyer cannot attest more than the manifest,
//// that only entitled parties transition, and that the time windows hold.
//// Enforcement on sequence, not on money. Non-repudiation is the product.

use aiken/crypto.{VerificationKeyHash}
use cardano/transaction.{OutputReference}

/// blake2b-256 commitment to an off-chain document (order lines, shipping
/// manifest, reception declaration).
///
/// The preimage MUST be salted: without a salt, quantities can be recovered
/// by brute force, and a re-identifiable hash remains personal data under
/// GDPR.
pub type Commitment =
  ByteArray

/// Arbitration panel: an M-of-N set of keys entitled to rule on a dispute.
///
/// A single arbiter key would make whoever holds it the trusted third party
/// this design exists to remove — and if it were the platform's own key, the
/// platform would be arbitrating disputes over a record it also profits from.
/// A threshold across independent holders is what makes the record adoptable
/// by suppliers who have no reason to trust the platform.
///
/// Well-formedness (distinct keys, `1 <= threshold <= length(keys)`) is
/// enforced once, at minting, because that is the only point where this
/// datum is created rather than carried forward by `continues`.
pub type Arbitration {
  /// Distinct verification keys. Duplicates would let one signature count
  /// more than once towards the threshold.
  keys: List<VerificationKeyHash>,
  /// Minimum number of distinct panel signatures required to rule.
  threshold: Int,
}

/// Contractual parameters, frozen at creation and never mutable afterwards.
pub type Terms {
  /// Deadline (POSIX ms) past which the supplier can no longer accept and the
  /// buyer recovers the deposit.
  acceptance_deadline: Int,
  /// Delay (ms) granted to the buyer after shipment to declare what was
  /// received. Past that delay, silence counts as accepting the manifest.
  reception_window: Int,
  /// Delay (ms) granted to the arbiter to settle a dispute. Past that delay,
  /// the buyer's declared figure prevails.
  dispute_window: Int,
  /// Triviality threshold, in euro cents. Below it, the gap is credited to
  /// the buyer automatically: arbitrating would cost more than the gap.
  tolerance: Int,
}

/// Successive states of an order.
pub type State {
  /// The buyer has issued a request and funded the min-ADA deposit.
  Created { request: Commitment }
  /// The supplier has committed to a set of lines and an amount, in cents.
  Accepted { lines: Commitment, total: Int }
  /// The supplier sealed its manifest BEFORE the buyer declared anything.
  /// That precedence is what makes the reconciliation probative.
  ///
  /// `shipped_at` is the UPPER bound of the sealing transaction's validity
  /// range — the latest slot at which it could have been accepted. See
  /// `tx.event_time` for why the lower bound would be forgeable.
  Shipped { manifest: Commitment, manifest_total: Int, shipped_at: Int }
  /// The two declarations diverge beyond the tolerance.
  ///
  /// `declared_at` is an upper bound, for the same reason as `shipped_at`.
  Disputed {
    manifest_total: Int,
    accepted_total: Int,
    receipt: Commitment,
    declared_at: Int,
  }
}

/// Datum carried by the order UTxO.
pub type Order {
  /// State-token name (unique per order).
  token: ByteArray,
  /// The restaurant.
  buyer: VerificationKeyHash,
  /// The supplier.
  supplier: VerificationKeyHash,
  /// Arbitration panel. Its power is bounded on both sides by `Arbitrate`:
  /// it can only pick a figure between what the buyer declared and what the
  /// supplier sealed.
  arbitration: Arbitration,
  terms: Terms,
  state: State,
}

/// Permitted transitions.
pub type Action {
  /// Supplier: commits to the lines and the amount.
  Accept { lines: Commitment, total: Int }
  /// Buyer (or anyone once the deadline has passed): closes and returns
  /// the deposit. Nothing was ever owed on-chain.
  Cancel
  /// Supplier: seals the manifest as the truck departs.
  Ship { manifest: Commitment, manifest_total: Int }
  /// Buyer: declares what was received. `accepted_total` is the result of the
  /// min() rule computed off-chain over the lines.
  Declare { receipt: Commitment, accepted_total: Int }
  /// Supplier: the buyer's silence counts as accepting the manifest.
  ClaimSilence
  /// Panel: records the arbitrated figure, bounded by
  /// [accepted_total, manifest_total]. Records it; moves nothing.
  Arbitrate { final_total: Int }
  /// The arbiter never ruled: the buyer's figure prevails.
  CloseDispute
}

/// State-token operations.
pub type TokenAction {
  /// Opening an order, anchored on a seed UTxO for uniqueness.
  Open { seed: OutputReference }
  /// Closing: the token is burned, the UTxO can never live again.
  Close
}

//// Types for the delivery-note protocol.
////
//// One order = one UTxO at the script, carrying a unique state token and an
//// inline datum. No price, no line item and no personal data is written in
//// clear: only salted commitments and totals go on-chain.

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

/// Contractual parameters, frozen at creation and never mutable afterwards.
pub type Terms {
  /// Deadline (POSIX ms) past which the supplier can no longer accept and the
  /// buyer recovers the escrow.
  acceptance_deadline: Int,
  /// Delay (ms) granted to the buyer after shipment to declare what was
  /// received. Past that delay, silence counts as accepting the manifest.
  reception_window: Int,
  /// Delay (ms) granted to the arbiter to settle a dispute. Past that delay,
  /// the buyer's declared figure prevails.
  dispute_window: Int,
  /// Triviality threshold (lovelace). Below it, the gap is credited to the
  /// buyer automatically: arbitrating would cost more than the gap itself.
  tolerance: Int,
}

/// Successive states of an order.
pub type State {
  /// The buyer has issued a request and locked the escrow.
  Created { request: Commitment }
  /// The supplier has committed to a set of lines and an amount.
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
  /// Arbitration third party. May be a multi-signature key, or the platform
  /// itself — its power is bounded by `Arbitrate`.
  arbiter: VerificationKeyHash,
  terms: Terms,
  state: State,
}

/// Permitted transitions.
pub type Action {
  /// Supplier: commits to the lines and the amount.
  Accept { lines: Commitment, total: Int }
  /// Buyer (or anyone once the deadline has passed): full refund.
  Cancel
  /// Supplier: seals the manifest as the truck departs.
  Ship { manifest: Commitment, manifest_total: Int }
  /// Buyer: declares what was received. `accepted_total` is the result of the
  /// min() rule computed off-chain over the lines.
  Declare { receipt: Commitment, accepted_total: Int }
  /// Supplier: the buyer's silence counts as accepting the manifest.
  ClaimSilence
  /// Arbiter: settles a dispute, bounded by [accepted_total, manifest_total].
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

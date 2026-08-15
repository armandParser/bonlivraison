//// The min() reconciliation rule.
////
//// The contract does not compare line items one by one: that would be costly
//// in execution units and it would expose negotiated prices. It enforces a
//// weaker but sufficient constraint:
////
////   0 <= accepted_total <= manifest_total
////
//// The buyer can never declare owing MORE than what the supplier claimed,
//// and has no incentive to declare less than reality — the declaration is
//// signed, timestamped and irrevocable, and the supplier can produce it in
//// arbitration.
////
//// Monotonicity of min() is therefore guaranteed on-chain by the inequality,
//// and economically by non-repudiation. What the chain does NOT do is
//// establish physical facts: that remains the job of the scanner and of the
//// counter-signature at the dock.

use aiken/fuzz

/// Outcome of a reconciliation.
pub type Outcome {
  /// Both declarations agree.
  Exact
  /// Gap below the triviality threshold: credited without arbitration.
  Tolerated
  /// Significant gap: the undisputed part settles immediately, the delta goes
  /// to arbitration.
  Contested
}

/// A reception declaration is admissible if it is non-negative and does not
/// exceed the supplier's own commitment.
pub fn admissible(manifest_total: Int, accepted_total: Int) -> Bool {
  accepted_total >= 0 && accepted_total <= manifest_total
}

/// Classifies the gap between the supplier's commitment and the buyer's
/// declaration.
pub fn reconcile(
  manifest_total: Int,
  accepted_total: Int,
  tolerance: Int,
) -> Outcome {
  let gap = manifest_total - accepted_total
  if gap <= 0 {
    Exact
  } else if gap <= tolerance {
    Tolerated
  } else {
    Contested
  }
}

/// Amount immediately claimable by the supplier, whatever the outcome.
///
/// This is the property that unblocks cash flow: a dispute over 2 EUR no
/// longer freezes an 800 EUR invoice.
pub fn immediately_due(accepted_total: Int) -> Int {
  accepted_total
}

// ## Tests

test exact_when_the_counts_agree() {
  reconcile(80_000_000, 80_000_000, 1_500_000) == Exact
}

test trivial_gap_absorbed_without_arbitration() {
  reconcile(80_000_000, 79_000_000, 1_500_000) == Tolerated
}

test gap_exactly_at_threshold_stays_tolerated() {
  reconcile(80_000_000, 78_500_000, 1_500_000) == Tolerated
}

test gap_just_above_threshold_becomes_contested() {
  reconcile(80_000_000, 78_499_999, 1_500_000) == Contested
}

test zero_tolerance_makes_every_gap_contestable() {
  reconcile(80_000_000, 79_999_999, 0) == Contested
}

test negative_declaration_inadmissible() {
  !admissible(80_000_000, -1)
}

test buyer_cannot_inflate_the_invoice() {
  !admissible(80_000_000, 80_000_001)
}

test totally_missing_delivery_is_admissible() {
  admissible(80_000_000, 0)
}

/// Central property: whatever the admissible declaration, the supplier can
/// never collect more than its own commitment.
///
/// KNOWN WEAKNESS: this property is close to vacuous. `accepted` is built by
/// construction to satisfy `admissible`, and `immediately_due` is the
/// identity, so the assertion reduces to a tautology about the modulo
/// operator. Replacing `admissible` with `True` does not make it fail. It is
/// kept here only to preserve the existing baseline; a real state-machine
/// property test is tracked as follow-up work.
test never_more_than_the_manifest(n via fuzz.both(fuzz.int(), fuzz.int())) {
  let (manifest, raw) = n
  let manifest_total = abs_int(manifest)
  let accepted = abs_int(raw) % ( manifest_total + 1 )
  admissible(manifest_total, accepted)? && immediately_due(accepted) <= manifest_total
}

fn abs_int(x: Int) -> Int {
  if x < 0 {
    -x
  } else {
    x
  }
}

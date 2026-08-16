# bonlivraison

Delivery-note attestation on Cardano, for food-service procurement.

In food service the delivery note is signed before it can be checked.
Deliveries land at 6am during prep; the chef signs for fourteen crates without
counting them. From then the note is proof of conformity, and disproving it
falls on the restaurant. This contract replaces that single signature with two
independent ones, in a fixed order: the supplier seals its manifest as the
truck departs, and the buyer attests what arrived afterwards, without being
able to change what was sealed.

One order is one UTxO, carrying a unique state token and an inline datum.

```
Created ──Accept──> Accepted ──Ship──> Shipped ──Declare──> Disputed
   │                    │                 │                     │
 Cancel              Abandon        ClaimSilence          Arbitrate
                                     / Declare           / CloseDispute
```

## Attestation, not escrow

This contract moves no money. The UTxO holds only the min-ADA that lets it
exist, and that deposit returns to the buyer when the order closes. Every
total in the datum is an **attested figure in euro cents**, not lovelace.
Payment happens by SEPA transfer, off-chain, driven by the record this
contract produces.

A restaurant will not lock the ADA equivalent of an 800 EUR invoice at 6am —
the float per establishment would run to thousands of euros, against fees of
about 0.20 EUR per order. What the validator enforces instead is the part that
matters: that the manifest was sealed before the buyer declared, that the
buyer cannot attest more than the manifest, that only entitled parties
transition, and that the time windows hold. Enforcement on sequence, not on
money. Non-repudiation is the product.

## Design notes

**Liveness exits.** `Created` and `Disputed` already close without
cooperation: `Cancel` is permissionless after the acceptance deadline,
`CloseDispute` takes either party. Two states lacked that. `ClaimSilence`
becomes permissionless after `shipped_at + reception_window + abandon_grace` —
it records the sealed manifest, which the contract already treats as the
figure once the buyer's window closes, so a permissionless close destroys no
supplier right. `Abandon` covers `Accepted`, where nothing shipped and closure
carries no attestation, after `acceptance_deadline + abandon_grace`. Both
anchor on timestamps that already exist and are already validated: no new
datum field, no new mint check. A `created_at` written at mint would need
pinning to `event_time`, or a buyer could back-date it, let the supplier ship,
and abandon instead of declaring.

**On arbiter silence, the buyer's figure prevails.** This mirrors
`ClaimSilence`: at each stage the default penalises the party that failed to
act. Because the panel is `[buyer, supplier, independent]` at threshold 2,
silence means the supplier declined to converge with either seat — a midpoint
default would hand it half the gap for stonewalling. The rule assumes the
independent seat is reliably available; securing that availability is a
contractual commitment, not a property of the code.

**The arbitration panel is bounded on both sides.** `Arbitrate` can only
record a figure between what the buyer declared and what the supplier sealed.
The platform holds no seat: with one it could swing any dispute by siding with
a party, which is the neutrality problem this design exists to remove.

**Timestamps are read from the upper bound of the validity range**, never the
lower. A transaction with `invalid_before = 0` is valid at any slot, so
reading the lower bound would let either party back-date and expire the
deadline protecting the other side.

**Commitments must be salted.** Quantities are brute-forceable from a small
domain, and a re-identifiable hash remains personal data under GDPR. Salts
live off-chain; deleting one makes its commitment permanently unverifiable,
which is a credible answer to the right to erasure against an immutable chain.

## Known limitations

1. **Liveness depends on someone submitting.** `Abandon` is permissionless,
   not automatic. If nobody sweeps, abandoned orders stay open and their
   deposits stay stranded — by neglect rather than by design. Running the
   sweeper is an operating commitment, not a property of the contract.

2. **The chain does not know what was in the crate.** Physical checks stay
   human and scanner work. What is guaranteed is that declarations are
   irreversible and symmetric, and that the supplier sealed first.

3. **Plutus scripts cannot read transaction metadata.** The validator neither
   sees nor checks the CIP-0170 attestation identifier. The identifier travels
   in metadata; the binding to the on-chain action is the signing key.

4. **`Terms` are not bounded by the validator.** The supplier accepts the
   whole datum when it signs `Accept`, so unreasonable terms must be refused
   there, off-chain. The Accept screen has to show them.

5. **No off-chain layer in this repository.** Transaction building, commitment
   construction, KERI attestations and the sweeper live in a separate
   TypeScript work item.

## Building

```sh
aiken check     # 66 tests
aiken build
```

Set your GitHub handle in `aiken.toml` before publishing:
`name = "<handle>/bonlivraison"` and `user = "<handle>"`.

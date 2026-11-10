# Gas report

Measured with Foundry 1.5.1, solc 0.8.28, optimizer 2000 runs, EVM `cancun`.
Regenerate with `forge test --match-path test/Gas.t.sol -vv` and `forge test --gas-report`.

## Per-vote cost (the number that matters for a public election)

Execution gas of `Election.castVote` with a real Groth16 proof, measured inside the EVM. A full transaction
adds the 21,000 base cost and calldata (≈ 1.06 KB for K=4, ≈ 1.57 KB for K=8).

| Ballot circuit | First vote | Re-vote | Budget enforced by `test/Gas.t.sol` |
|---|---:|---:|---:|
| K = 4 slots (23 public signals) | 375,527 | 353,101 | < 400,000 |
| K = 8 slots (39 public signals) | 487,790 | — | < 600,000 |

Where the gas goes (K = 4): Groth16 pairing check ≈ 210k (4 pairings + 23 scalar multiplications for the
public inputs), one cold storage slot for the nullifier record (22.1k), the `BallotCast` event carrying the
16 ciphertext words, and the public-input checks against the election snapshot.

## Election lifecycle (one K = 4 election, 5 trustees, threshold 3)

| Operation | Who | Gas | Count per election |
|---|---|---:|---:|
| `createElection` | admin | ≈ 985,000 | 1 |
| `publishRoot` (batch of 4 leaves) | registrar | 74,878 – 90,976 | per batch |
| `registerKey` (subgroup check) | each trustee | 370,563 | n |
| `deal` (t Pedersen commitments, subgroup-checked) | each trustee | 1,135,373 | n |
| `reveal` (t Feldman commitments) | each trustee | 1,094,043 | n |
| `TrusteeCoordinator.finalize` | anyone | 349,544 | 1 |
| `Tally.aggregate` (8 ballots, 3 slots) | anyone | 621,564 | per batch (≈ 78k per ballot) |
| `Tally.normalize` | anyone | 281,356 – 671,135 | 1 |
| `submitPartialDecryption` (3 slots / 5 slots) | each trustee | 3,552,971 / 5,851,511 | ≥ t |
| `finalizeSlot` | anyone | 442,782 – 549,861 | per candidate |

## Optimisations applied

* Scalar multiplication on Baby Jubjub rewritten as a single stack-only assembly loop
  (projective coordinates, one modular inversion at the end): 487,956 → 310,862 gas per 251-bit
  multiplication. Chaum–Pedersen verification uses Straus' trick (shared doublings) on top of that.
* Nullifier record packed into one slot (`uint224` ballot hash + `uint32` count); phase, flags and
  timestamps packed into one slot.
* Ciphertexts are not stored: they are emitted once and committed to by the 224-bit hash, which the
  aggregator must reproduce.
* Custom errors throughout; all external inputs are `calldata`.
* Gas forwarded to the verifier is capped at 600,000 so a malformed proof cannot burn the caller's
  whole gas limit (before the fix a malformed point consumed ~1,000,000,000 gas in tests).

## Notes for operators

Trustee decryption is the most expensive step (≈ 650k gas per Chaum–Pedersen verification). On Ethereum L1
this is a few transactions per trustee per election; on an L2 such as Base or Arbitrum the cost is negligible.
Voters never pay it.

# VeriVote Smart Contract Security Review

| | |
|---|---|
| Scope | `contracts/src/**` at the commit that adds this report (Election, VeriVoteFactory, VoterRegistry, TrusteeCoordinator, Tally, BabyJubJub, ChaumPedersen, Lagrange). Generated Groth16 verifiers reviewed for integration only. |
| Out of scope | Circom circuits (covered by `circuits/test`), off-chain services, OpenZeppelin dependencies (v5.4.0) |
| Method | Manual line-by-line review, adversarial test writing, stateful fuzzing, symbolic execution (Halmos), static analysis (Slither 0.11.6) |
| Nature | **Internal review by the project author.** It is written in the format of a professional audit so that findings are traceable, but it is not an independent third-party audit and must not be presented as one. An external audit is a launch prerequisite (see §6). |

## 1. Summary

| Severity | Found | Fixed | Acknowledged |
|---|---:|---:|---:|
| Critical | 0 | 0 | 0 |
| High | 1 | 0 | 1 (operational, deployment blocker) |
| Medium | 3 | 2 | 1 |
| Low | 5 | 3 | 2 |
| Informational / Gas | 6 | 4 | 2 |

The protocol-level guarantees the contracts enforce were each turned into a test that fails if the guarantee
breaks: one ballot per roll entry, last ballot counts, aggregation of exactly the final ballots, verified
partial decryptions, `Σ counts == ballots`, time-locked monotonic phases, a pause that cannot change results
or shorten voting, and upgrades blocked while an election is live.

## 2. System overview (as reviewed)

`VeriVoteFactory` deploys one UUPS `Election` proxy per election and registers it with three singletons:
`VoterRegistry` (Merkle roots of identity commitments), `TrusteeCoordinator` (Pedersen-VSS DKG with Feldman
reveal) and `Tally` (homomorphic aggregation and threshold decryption). Ballots are accepted only with a Groth16
proof of roll membership, nullifier derivation and well-formed one-hot ElGamal encryption. Upgrade authority is
a `TimelockController` controlled by a Safe; a separate pauser role can only pause.

## 3. Findings

### VV-01 — High — Development proving keys are not from a ceremony (Acknowledged, deployment blocker)

The committed verifiers (`src/verifiers/Groth16VerifierK4.sol`, `Groth16VerifierK8.sol`) are generated from
`circuits/scripts/dev-keys.sh`, which runs one deterministic phase-2 contribution on a locally generated
phase-1 file. Anyone who knows that entropy can forge proofs, which would break eligibility and ballot
validity.

**Resolution.** Acceptable for tests and local demos only. Before any real deployment the verifiers MUST be
regenerated from a multi-party phase-2 ceremony (`circuits/scripts/ceremony.sh`) on top of the Perpetual
Powers of Tau (procedure in `docs/RUNBOOK.md` §4). CI regenerates the verifier from the final zkey and fails
if it differs from the committed file.

### VV-02 — Medium — Unbounded gas forwarded to the verifier (Fixed)

`Election._verifyProof` forwarded all remaining gas to the verifier. A proof containing a point that is not on
BN254 makes the pairing precompile fail by consuming all gas it receives. In tests a single malformed
submission consumed about 1,000,000,000 gas.

**Impact.** A relayer that submits an unvalidated proof loses its whole gas limit; a contract integrating with
`castVote` could be griefed.

**Fix.** The call is capped at `VERIFIER_GAS_LIMIT = 600_000` (`contracts/src/Election.sol:76`, used at
`contracts/src/Election.sol:366`). Test `test_publicInputMismatchesRejected` now completes in about 14M gas
including the full election setup.

### VV-03 — Medium — Registrar can publish a root that does not match the published leaves (Acknowledged)

`VoterRegistry.publishRoot` (`contracts/src/VoterRegistry.sol:84`) stores the root supplied by the registrar
and emits the leaves, but does not recompute the root on-chain. A malicious registrar could publish a root
that commits to extra, unpublished identity commitments and vote with them.

**Why not fixed on-chain.** An on-chain Poseidon tree costs about 20 Poseidon hashes per insertion
(roughly 0.5–0.6M gas per voter), which is prohibitive for large rolls. A batched insertion proof (as in MACI)
is the scalable fix and is listed as future work.

**Mitigation in place.** The mismatch is always detectable: `verivote-audit` rebuilds the tree from the
`LeavesAppended` stream and compares every published root. A voter whose own leaf is missing cannot build a
valid path and notices immediately. The threat is documented as V-5 in `docs/THREAT_MODEL.md`.

### VV-04 — Medium — A qualified dealer that withholds its reveal aborts the DKG (Acknowledged)

In `TrusteeCoordinator.finalize` (`contracts/src/TrusteeCoordinator.sol:266`) a qualified dealer that does not
reveal its Feldman commitments fails the DKG; a dealer that reveals inconsistent commitments can be exposed
and also fails it (`exposeReveal`, line 248). Full GJKR instead reconstructs the dealer's secret publicly.

**Rationale.** Aborting is simpler and cannot bias the key; the failure is publicly attributable to one
trustee, who is removed before re-running the DKG. Liveness cost: one restart per misbehaving trustee.
Documented as V-11 in the threat model.

### VV-05 — Medium — Ballot ciphertext points are not subgroup-checked on-chain (Acknowledged, by construction)

`Tally.aggregate` adds ciphertext points without checking they lie in the prime-order subgroup.

**Analysis.** The points are outputs of the ballot circuit: `c1 = r·G` with `G` in the subgroup, and
`c2 = m·G + r·PK` where `PK` is a sum of subgroup-checked Feldman commitments. They are bound to the
`BallotCast` record by a 224-bit hash, so no other points can be aggregated. A subgroup check per point would
cost about 300k gas per ballot slot. No change.

### VV-06 — Low — Return-data bomb on the verifier call (Fixed)

`_verifyProof` decoded the full return data into memory, so a malicious verifier could force expensive memory
expansion. The verifier is admin-configured, but the call now copies exactly one word in assembly and requires
`returndatasize() == 32` (`contracts/src/Election.sol:366`).

### VV-07 — Low — Redundant checks hid unreachable branches (Fixed)

Two checks could never fail: a trustee-count check in `Election.advance` (the coordinator already enforces
`2 ≤ t ≤ n`) and a field-range check in `Tally._accumulate` (the words already passed the Groth16 verifier,
which rejects values ≥ p, and are bound by the stored hash). Both were removed with an explanatory comment.

### VV-08 — Low — Ambiguous abort rule (Fixed)

The abort condition in `Election.abort` was a single compound `if/else if` expression that was easy to misread.
It is now `_abortAllowed` (`contracts/src/Election.sol:261`) with one rule per phase, and every rule has a
dedicated test (`test_adminAbortBeforeVoting`, `test_anyoneAbortsWhenDkgMissedDeadline`,
`test_strangerCannotAbortWhenDkgSucceeded`, `test_votingCannotBeAborted`, `test_anyoneAbortsStalledTally`).

### VV-09 — Low — Timestamp dependence (Acknowledged)

Phase transitions and DKG windows use `block.timestamp` (16 Slither notes). All windows are at least ten
minutes (`MIN_*_WINDOW` in `VeriVoteFactory`), so the few seconds of proposer influence are irrelevant.

### VV-10 — Low — External call per ballot in aggregation (Acknowledged)

`Tally._checkBallot` (`contracts/src/Tally.sol:141`) calls `Election.ballotRecord` for each ballot. The callee is
the election proxy registered by the factory, and batches are capped at `MAX_BATCH = 256`.

### VV-11 — Informational — Over-vote defence in depth (Verified)

If the verifier or circuit were ever broken and accepted a ballot voting for two candidates, `_finalizeElection`
(`contracts/src/Tally.sol:278`) still refuses to finalize because the counts would not sum to the number of
ballots. Test `DefenseInDepthTest.test_overVoteCaughtByTallySumCheck` uses a deliberately broken verifier to
show this.

### VV-12 — Informational — Shadowing and uninitialised-local lints (Fixed)

Parameters that shadowed state variables were renamed and default-zero locals are initialised explicitly so the
Slither gate (`fail_on: medium`) runs without suppressions for these classes.

### VV-13 — Informational — 224-bit ballot commitment

Ballot hashes are truncated to 224 bits to pack the nullifier record into one slot. Second-preimage resistance
remains about 2^224 and collision resistance about 2^112, which is adequate here.

### VV-14 — Gas — Curve arithmetic (Fixed)

The first implementation kept projective coordinates in memory structs. Rewriting the loops as stack-only
assembly reduced a 251-bit scalar multiplication from 487,956 to 310,862 gas and Chaum–Pedersen verification
to about 650k gas. Numbers are in `contracts/GAS_REPORT.md`.

### VV-15 — Gas — Ciphertexts emitted, not stored (Design)

Storing 16–32 words per ballot would cost at least 320k extra gas per vote. Ballots are emitted once and
committed to by hash; `Tally.aggregate` re-supplies them as calldata.

### VV-16 — Informational — Slither suppressions

Three `incorrect-equality` reports on enum comparisons (a known false positive when a function also reads
the timestamp) and the benign reentrancy note on `createElection` (the only call is the constructor of our own
proxy) are suppressed inline with a justification.

## 4. Verification performed

| Technique | Result |
|---|---|
| Unit and integration tests (Foundry) | 102 tests, all passing; full elections run with real Groth16 proofs, a real DKG transcript and real Chaum–Pedersen proofs |
| Stateful invariant fuzzing | 4 invariants × 48 runs × 24 calls locally (256 × 32 in the `ci` profile): tally equals distinct nullifiers, no nullifier reuse, monotonic phases, pause cannot change results |
| Property fuzzing | 256 runs each: any tampered signal or proof word is rejected; any pause extends voting exactly; random time travel never skips or reverses a phase |
| Cross-implementation vectors | Solidity curve, Chaum–Pedersen and Lagrange code checked against the TypeScript reference (`contracts/test/vectors/TestVectors.sol`) |
| Symbolic execution (Halmos 0.3.3) | 5 specifications, all PASS for every symbolic input: pause cannot mutate results, pause never shortens voting, re-vote counting, pauser has no other powers, monotonic Voting→Tallying (`contracts/test/formal/RESULTS.md`) |
| Static analysis (Slither 0.11.6) | 0 High, 0 Medium after fixes; 17 Low (timestamp, calls-loop) acknowledged; 6 Informational (assembly) |
| Mythril, Aderyn | Configured in CI (`.github/workflows/ci.yml`); not run on the author's machine, so no local results are claimed |
| Coverage (`forge coverage --ir-minimum`) | 98.9% branches and 100% functions across the reviewed contracts; see §5 for what the remaining lines are |

## 5. Coverage and formal results

Line coverage excluding generated verifiers is reported by `forge coverage --ir-minimum`. The lines it reports
as unexecuted are constructor and initializer bodies (creation code is not attributed by the tool), the inline
assembly in `BabyJubJub` (executed by every curve test but not attributed), and one `return false` the IR
pipeline folds into the preceding branch. Every Solidity-level branch outside inline assembly is exercised.

Halmos results (5/5 PASS, 3.5 s) are recorded in `contracts/test/formal/RESULTS.md`.

## 6. Recommendations before mainnet

1. Run the phase-2 ceremony with independent contributors and replace the verifiers (VV-01).
2. Commission an independent audit of contracts **and circuits**.
3. Consider a batched Merkle-insertion proof so the registry verifies roots on-chain (VV-03).
4. Deploy on an L2 to keep trustee decryption costs low (VV-14).

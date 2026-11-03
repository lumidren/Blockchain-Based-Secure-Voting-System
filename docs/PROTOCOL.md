# VeriVote Protocol Specification

Version 1.0 — normative. Every implementation detail in this document is enforced by code in this
repository; where a value is measured rather than designed (constraint counts, gas) the measurement
lives in `ARCHITECTURE.md` and the technical paper.

## 1. Primitives and parameters

| Symbol | Value / definition |
|---|---|
| `p` | BN254 scalar field modulus `21888242871839275222246405745257275088548364400416034343698204186575808495617` (all Circom arithmetic, Poseidon, Baby Jubjub coordinates) |
| Curve `E` | Baby Jubjub, twisted Edwards `a·x² + y² = 1 + d·x²·y²` over `F_p`, `a = 168700`, `d = 168696` |
| `l` | Prime subgroup order `2736030358979909402780800718157159386076813972158567259200215660948447373041` (251 bits); cofactor `8` |
| `G` | circomlib `Base8` = `(5299619240641551281634865583518297030282874472190772894086521144482721001553, 16950150798460657717958625567821834550301663161624707787222815936182638968203)` |
| `H` | Second generator with unknown discrete log: `8 · hashToCurve("VeriVote/H/v1")` (derivation in `packages/crypto-core/src/babyjub.ts#deriveH`, constant checked by test) |
| `Poseidon_n` | circomlib Poseidon with `n` inputs (t = n+1). Different arities use different round constants, which gives domain separation between `Poseidon_1` and `Poseidon_2` |
| `Hs(·)` | `keccak256(abi.encode(·))` interpreted as a `uint256` and reduced mod `l` (Fiat–Shamir challenges verified on-chain) |
| Proof system | Groth16 over BN254, Circom 2.2 + snarkjs |
| Merkle depth `D` | 20 (capacity 1,048,576 commitments) |
| Ballot slots `K` | compile-time; circuits shipped for `K ∈ {4, 8}` |

Because `a` is a quadratic residue and `d` is a non-residue in `F_p`, the twisted Edwards addition law
is complete: the on-chain formulas have no exceptional inputs (verified in `contracts/test/BabyJubJub.t.sol`).

Scalars for the curve (`r`, shares, DKG coefficients, challenges) live in `Z_l`. Scalars for the circuit
(secrets, Poseidon inputs) live in `F_p`.

## 2. Identities and the voter roll

1. A voter samples `sk ←$ F_p` client-side (CSPRNG, 31 random bytes reduced mod `p` is not used; 32 bytes are rejection-sampled below `p`).
2. Identity commitment: `idc = Poseidon_1(sk)`.
3. The registrar verifies eligibility through an adapter (`services/registrar/src/eligibility/`), then appends `idc` to the election's Merkle tree and to its hash-chained audit log.
4. Merkle tree: binary, depth `D`, node hash `Poseidon_2(left, right)`, zero leaf `0`, zero hashes `Z_0 = 0`, `Z_{i+1} = Poseidon_2(Z_i, Z_i)`; leaves appended left to right.
5. The registrar publishes `root` on-chain with the appended leaves as calldata; `VoterRegistry` stores the full root history `(root, leafCount, blockNumber)` and emits `LeavesAppended(electionId, startIndex, leaves)`. Anyone can rebuild the tree from events and check the root.
6. When the election enters `Voting`, the `Election` contract snapshots the current root; later root changes do not affect the election.

## 3. Ballot encryption (exponential ElGamal on Baby Jubjub)

Election public key `PK = x·G` where `x` is never known to anyone (Section 5).

For slot `i ∈ [0, K)` with choice `m_i ∈ {0,1}` and randomness `r_i ←$ [1, l)`:

```
C1_i = r_i · G
C2_i = m_i · G + r_i · PK
```

Homomorphism: `(C1, C2) + (C1', C2') = (C1 + C1', C2 + C2')` encrypts `m + m'`.
Decryption: `M = C2 − x·C1 = m·G`; `m` is recovered by baby-step giant-step (`packages/crypto-core/src/elgamal.ts#discreteLog`) with `m ≤ ballotCount`.

Each slot uses independent randomness. Reusing `r` across slots would reveal `(m_i − m_j)·G`.

## 4. Ballot circuit `Ballot(K, D)`

Private inputs: `sk`, `pathElements[D]`, `pathIndices[D]`, `m[K]`, `r[K]`.
Public inputs (in declaration order): `root`, `electionId`, `pk[2]`, `numCandidates`, `voteIndex`.
Outputs: `c1[K][2]`, `c2[K][2]`, `nullifier`.

Constraints:

1. `idc = Poseidon_1(sk)`; Merkle inclusion of `idc` at the path under `root` (`pathIndices` boolean-constrained).
2. `nullifier = Poseidon_2(sk, electionId)`.
3. `m_i · (m_i − 1) = 0` for all `i`; `Σ m_i = 1`.
4. `m_i · (1 − lt(i, numCandidates)) = 0`: no vote in an inactive slot (`lt` via `LessThan(8)`; `numCandidates ≤ K` enforced by the contract).
5. `r_i` decomposed to 253 bits; `c1_i = EscalarMulFix(r_i, G)`; `c2_i = BabyAdd(m_i·G, EscalarMulAny(r_i, pk))` with `m_i·G` realised as a boolean point selection between the identity `(0,1)` and `G`.
6. `pk` is constrained to lie on the curve (`BabyCheck`); `voteIndex` is bound by a dummy quadratic constraint so the optimizer keeps it as a public input.

Public signal vector (what the contract receives), length `4K + 7`:

```
[ c1[0].x, c1[0].y, …, c1[K-1].x, c1[K-1].y,
  c2[0].x, c2[0].y, …, c2[K-1].x, c2[K-1].y,
  nullifier, root, electionId, pk.x, pk.y, numCandidates, voteIndex ]
```

Soundness argument: a valid proof shows the prover knows a secret whose commitment is in the snapshotted
roll, that the nullifier is the deterministic function of that secret and this election, and that the
published ciphertext encrypts a well-formed one-hot ballot under the election key. The ciphertext and
`voteIndex` are bound through the public inputs, so a relayer or a mempool observer cannot replace or
replay them.

## 5. Distributed key generation (Pedersen VSS with Feldman reveal)

Trustees `T_1 … T_n`, threshold `t` (`2 ≤ t ≤ n ≤ 32`). Each trustee holds an Ethereum account (for
authorisation) and a Baby Jubjub encryption key `EK_j = ek_j·G` registered on-chain.

Phases are time-boxed by the coordinator (`dealDeadline < complaintDeadline < revealDeadline < revealComplaintDeadline`).

**Deal.** Trustee `i` samples `a_{i,0..t-1}, b_{i,0..t-1} ←$ Z_l`, defines `f_i(z) = Σ a_{i,k} z^k`, `f'_i(z) = Σ b_{i,k} z^k`,
publishes Pedersen commitments `C_{i,k} = a_{i,k}·G + b_{i,k}·H` and, for every `j`, the pair
`(s_{i,j}, s'_{i,j}) = (f_i(j), f'_i(j))` encrypted to `EK_j`:

```
e ←$ Z_l; R = e·G; Z = e·EK_j
key = HKDF-SHA256(ikm = Z.x (32 bytes BE), salt = "VeriVote/DKG/v1", info = electionId ‖ i ‖ j)
ct  = AES-256-GCM(key, iv ←$ 12 bytes, aad = electionId ‖ i ‖ j, plaintext = s ‖ s')
```

The contract stores `C_{i,*}` and emits the ciphertexts (`SharesDelivered`). Commitments must be on the curve
and in the prime-order subgroup (`l·C = O`), checked on-chain.

**Complaint.** Trustee `j` decrypts and checks `s_{i,j}·G + s'_{i,j}·H = Σ_k C_{i,k}·j^k`. On failure it files
`complain(i)`. Dealer `i` must answer with `justify(j, s, s')`; the contract verifies the same equation. A dealer
that fails to justify, or justifies with an invalid pair, is **disqualified**. `QUAL` = dealers that dealt and were
not disqualified. The protocol requires `|QUAL| ≥ t`.

**Reveal.** Every `i ∈ QUAL` publishes Feldman commitments `A_{i,k} = a_{i,k}·G` (subgroup-checked). Trustee `j` checks
`s_{i,j}·G = Σ_k A_{i,k}·j^k`. On failure, `j` publishes `exposeReveal(i, s_{i,j}, s'_{i,j})`; the contract
verifies the pair against the Pedersen commitments (proving `j` holds the genuine share) and that the Feldman
equation fails. If so the DKG is marked `Failed` and `i` is recorded as malicious; the election cannot
proceed and must be re-run without `i`. (Full GJKR would instead reconstruct `a_{i,0}` publicly; we deliberately
abort, see THREAT_MODEL §T-DKG-2.)

**Finalize.** After `revealComplaintDeadline` with no failure:

```
PK      = Σ_{i∈QUAL} A_{i,0}
Ck_k    = Σ_{i∈QUAL} A_{i,k}                 (combined Feldman commitments)
S_j     = Σ_k Ck_k · j^k = s_j·G              (trustee verification keys, computed on-chain lazily)
s_j     = Σ_{i∈QUAL} s_{i,j} mod l            (trustee j's share, computed locally)
```

Any `t` trustees can reconstruct `x = Σ a_{i,0}`; no coalition of fewer than `t` learns anything about `x`
beyond `PK` (information-theoretically for the Pedersen phase, computationally for the Feldman reveal under DL).

## 6. Casting

`Election.castVote(proof, publicSignals)`:

1. phase is `Voting`, not paused, `block.timestamp < votingEnd` (as extended by pauses);
2. `publicSignals[root] == snapshotRoot`, `[electionId] == this election`, `[pk] == snapshot PK`, `[numCandidates] == numCandidates`;
3. `voteIndex == record[nullifier].count` (0 on first vote; re-voting requires `allowRevote`);
4. `Verifier.verifyProof` succeeds;
5. store `record[nullifier] = (keccak256(c1‖c2)[:224] , count + 1)`; emit `BallotCast(nullifier, voteIndex, ballotHash, c1, c2)`.

Only the latest ballot per nullifier counts (last-vote-counts). The contract never stores ciphertexts; the
event is the canonical ballot box and the `record` is the commitment used at aggregation.

The voter's receipt is `(electionId, nullifier, voteIndex, ballotHash, txHash)`.

**Benaloh challenge.** Before proving, the client displays `ballotHash` of a *candidate* encryption. The voter
may *audit*: the client reveals `(m, r)` and the voter re-encrypts with an independent tool
(`verivote-audit challenge` or the explorer) and checks equality; the audited ciphertext is discarded. Or *cast*:
the client proves and submits. A client that lies about the encryption is caught with probability `1 − 2^{-a}`
after `a` audits.

## 7. Aggregation and tally

**Aggregation** (phase `Tallying`, permissionless): `Tally.aggregate(electionId, ballots[])` where each ballot is
`(nullifier, c1[K], c2[K])`. The contract requires nullifiers strictly increasing across the whole
aggregation (so each is processed at most once), `keccak256(c1‖c2)[:224] == record[nullifier].hash`, and adds the
ciphertexts to the running tally `(ΣC1_i, ΣC2_i)` kept in projective coordinates. Decryption cannot start until
`aggregatedCount == ballotCount` (number of distinct nullifiers), so no ballot can be omitted and only the
latest ballot of each voter can be included.

**Partial decryption.** Trustee `j` (`S_j` known on-chain) submits for every active slot `i`:

```
D_{j,i} = s_j · C1_i
proof:  w ←$ Z_l, A = w·G, B = w·C1_i,
        e = Hs("VeriVote/CP/v1", electionId, i, S_j, C1_i, D_{j,i}, A, B),
        z = w + e·s_j mod l
verify: z·G = A + e·S_j   and   z·C1_i = B + e·D_{j,i}
```

**Finalisation** (permissionless, once `≥ t` trustees submitted): for subset `T` (`|T| = t`):

```
λ_j = Π_{m∈T, m≠j} m · (m − j)^{-1} mod l
X_i = Σ_{j∈T} λ_j · D_{j,i}
M_i = C2_i − X_i
require count_i · G == M_i      (count_i supplied by the caller, found off-chain by BSGS)
```

When all active slots are finalised the contract requires `Σ count_i == ballotCount` and moves to `Finalized`,
emitting `TallyFinalized(counts)`. Every quantity used is on-chain, so `verivote-audit` recomputes the whole
chain from events without trusting any party.

## 8. Phases and time locks

`Setup → Registration → Voting → Tallying → Finalized`, plus terminal `Aborted`. Phase indices are strictly
increasing. Transitions are permissionless once the scheduled timestamp is reached and the preconditions hold:

| Transition | Precondition |
|---|---|
| Setup → Registration | `now ≥ registrationStart`; ≥ 2 candidates; trustees configured |
| Registration → Voting | `now ≥ votingStart`; DKG finalised; roll non-empty; snapshots root, PK, candidate count |
| Voting → Tallying | `now ≥ votingEnd + pausedTime` |
| Tallying → Finalized | all active slots finalised and `Σ counts == ballotCount` |
| Setup/Registration → Aborted | admin, or anyone if `now ≥ votingStart` and DKG not finalised |
| Tallying → Aborted | anyone if `now ≥ tallyDeadline` and not finalised |

Pausing (global pauser role) blocks `castVote`, root publication and DKG submissions. Time spent paused during
`Voting` extends `votingEnd` by the same amount, so a pause cannot shorten the voting window. Pausing cannot
touch ballot records, nullifiers, tallies or results (invariant-tested).

Upgrades: `Election` proxies accept an upgrade only in `Setup`. Singletons accept one only when no election is
between `Registration` and `Tallying`. All upgrade authority sits behind a `TimelockController` whose proposer
is a Safe multisig.

## 9. Encoding conventions

* Points on-chain: `(uint256 x, uint256 y)` affine; projective `(X, Y, Z)`; identity `(0, 1)`.
* Scalars mod `l` as `uint256`; the contract rejects scalars `≥ l`.
* `electionId = uint256(keccak256(abi.encode(chainId, factory, index))) >> 8` (fits in `F_p`).
* Ballot hash: `bytes28(keccak256(abi.encodePacked(c1[0].x, c1[0].y, …, c2[K-1].y)))`.
* Trustee indices are 1-based in all polynomial evaluations.

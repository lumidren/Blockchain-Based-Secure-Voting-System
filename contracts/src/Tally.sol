// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardTransientUpgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardTransientUpgradeable.sol";
import {BabyJubJub} from "./libraries/BabyJubJub.sol";
import {ChaumPedersen} from "./libraries/ChaumPedersen.sol";
import {Lagrange} from "./libraries/Lagrange.sol";
import {IElection, IVeriVoteFactory, ITally, ITrusteeCoordinator} from "./interfaces/IVeriVote.sol";

/**
 * @title Tally
 * @notice Homomorphic aggregation of the final ballots, verified threshold decryption and finalisation.
 *
 *  aggregate()               anyone — adds ballots (sorted by nullifier, checked against Election records)
 *  normalize()               anyone — once every ballot is aggregated, converts the sums to affine form
 *  submitPartialDecryption() trustee — D_j = s_j·C1 with Chaum–Pedersen proofs for every active slot
 *  finalizeSlot()            anyone — Lagrange-combines t partials and checks count·G + X == C2
 *
 * Every input is public, so `verivote-audit` can replay this contract's checks off-chain.
 */
contract Tally is ITally, Initializable, UUPSUpgradeable, ReentrancyGuardTransientUpgradeable {
    using BabyJubJub for BabyJubJub.Point;

    struct ElectionTally {
        address election;
        uint8 slots;
        uint8 numCandidates;
        bool normalized;
        bool finalized;
        uint8 partialCount;
        uint8 finalizedSlots;
        uint32 aggregatedCount;
        uint256 lastNullifier;
        BabyJubJub.ProjectivePoint[] acc1;
        BabyJubJub.ProjectivePoint[] acc2;
        BabyJubJub.Point[] c1;
        BabyJubJub.Point[] c2;
        uint32[] counts;
        bool[] slotFinalized;
    }

    error NotFactory();
    error NotTrustee();
    error NotUpgradeAuthority();
    error ElectionsActive();
    error AlreadyRegistered();
    error UnknownElection();
    error WrongPhase();
    error ElectionPaused();
    error NullifierOrder();
    error UnknownBallot(uint256 nullifier);
    error BallotHashMismatch(uint256 nullifier);
    error WrongCiphertextLength();
    error CoordinateOutOfField();
    error NotAllAggregated(uint32 aggregated, uint32 expected);
    error AlreadyNormalized();
    error NotNormalized();
    error AlreadySubmitted();
    error WrongPartialCount();
    error InvalidPartialDecryption(uint8 slot);
    error SlotOutOfRange();
    error SlotAlreadyFinalized();
    error WrongSubsetSize(uint8 expected, uint256 actual);
    error TrusteeNotSubmitted(uint8 trustee);
    error WrongCount();
    error CountSumMismatch(uint256 sum, uint32 ballots);
    error EmptyBatch();

    uint256 public constant MAX_BATCH = 256;

    IVeriVoteFactory public factory;
    mapping(uint256 electionId => ElectionTally) private _tallies;
    mapping(uint256 electionId => mapping(uint8 trustee => BabyJubJub.Point[])) private _partials;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address factory_) external initializer {
        __UUPSUpgradeable_init();
        __ReentrancyGuardTransient_init();
        factory = IVeriVoteFactory(factory_);
    }

    function initElection(uint256 electionId, address election, uint8 slots) external {
        if (msg.sender != address(factory)) revert NotFactory();
        ElectionTally storage t = _tallies[electionId];
        if (t.election != address(0)) revert AlreadyRegistered();
        t.election = election;
        t.slots = slots;
        emit ElectionRegistered(electionId, election, slots);
    }

    // ------------------------------------------------------------------------------------------
    // Aggregation
    // ------------------------------------------------------------------------------------------

    /// @notice Adds a batch of final ballots. Nullifiers must be strictly increasing across all batches.
    function aggregate(uint256 electionId, Ballot[] calldata ballots) external nonReentrant {
        ElectionTally storage t = _requireTallying(electionId);
        if (t.normalized) revert AlreadyNormalized();
        if (ballots.length == 0 || ballots.length > MAX_BATCH) revert EmptyBatch();
        IElection election = IElection(t.election);
        uint8 slots = t.slots;
        uint8 nc = t.numCandidates;
        if (nc == 0) {
            nc = election.numCandidates();
            t.numCandidates = nc;
            for (uint8 i = 0; i < nc; i++) {
                t.acc1.push(BabyJubJub.projIdentity());
                t.acc2.push(BabyJubJub.projIdentity());
            }
        }
        // load accumulators into memory once
        BabyJubJub.ProjectivePoint[] memory acc1 = new BabyJubJub.ProjectivePoint[](nc);
        BabyJubJub.ProjectivePoint[] memory acc2 = new BabyJubJub.ProjectivePoint[](nc);
        for (uint8 i = 0; i < nc; i++) {
            acc1[i] = t.acc1[i];
            acc2[i] = t.acc2[i];
        }
        uint256 last = t.lastNullifier;
        for (uint256 b = 0; b < ballots.length; b++) {
            if (ballots[b].nullifier <= last) revert NullifierOrder();
            _checkBallot(election, ballots[b], uint256(slots) * 4);
            _accumulate(acc1, acc2, ballots[b].ciphertext, slots, nc);
            last = ballots[b].nullifier;
        }
        for (uint8 i = 0; i < nc; i++) {
            t.acc1[i] = acc1[i];
            t.acc2[i] = acc2[i];
        }
        t.lastNullifier = last;
        t.aggregatedCount += uint32(ballots.length);
        emit BallotsAggregated(electionId, uint32(ballots.length), t.aggregatedCount, last);
    }

    /// @dev The ballot must be the latest one recorded for its nullifier (hash commitment match).
    function _checkBallot(IElection election, Ballot calldata ballot, uint256 words) internal view {
        if (ballot.ciphertext.length != words) revert WrongCiphertextLength();
        (uint224 storedHash, uint32 count) = election.ballotRecord(ballot.nullifier);
        if (count == 0) revert UnknownBallot(ballot.nullifier);
        uint224 h = uint224(uint256(keccak256(abi.encodePacked(ballot.ciphertext))) >> 32);
        if (h != storedHash) revert BallotHashMismatch(ballot.nullifier);
    }

    /// @dev Adds the active slots of one ciphertext vector to the accumulators (projective mixed addition).
    function _accumulate(
        BabyJubJub.ProjectivePoint[] memory acc1,
        BabyJubJub.ProjectivePoint[] memory acc2,
        uint256[] calldata ct,
        uint8 slots,
        uint8 nc
    ) internal pure {
        uint256 off = uint256(slots) * 2;
        for (uint256 i = 0; i < nc; i++) {
            uint256 x1 = ct[2 * i];
            uint256 y1 = ct[2 * i + 1];
            uint256 x2 = ct[off + 2 * i];
            uint256 y2 = ct[off + 2 * i + 1];
            if (x1 >= BabyJubJub.P || y1 >= BabyJubJub.P || x2 >= BabyJubJub.P || y2 >= BabyJubJub.P) revert CoordinateOutOfField();
            BabyJubJub.addAffineInPlace(acc1[i], x1, y1);
            BabyJubJub.addAffineInPlace(acc2[i], x2, y2);
        }
    }

    /// @notice Converts the accumulated sums to affine coordinates once every distinct nullifier is included.
    function normalize(uint256 electionId) external nonReentrant {
        ElectionTally storage t = _requireTallying(electionId);
        if (t.normalized) revert AlreadyNormalized();
        IElection election = IElection(t.election);
        uint32 expected = election.ballotCount();
        if (t.aggregatedCount != expected) revert NotAllAggregated(t.aggregatedCount, expected);
        uint8 nc = t.numCandidates;
        if (nc == 0) {
            // zero ballots: tally is the identity for every active slot
            nc = election.numCandidates();
            t.numCandidates = nc;
        }
        uint256[] memory c1Flat = new uint256[](2 * nc);
        uint256[] memory c2Flat = new uint256[](2 * nc);
        for (uint8 i = 0; i < nc; i++) {
            BabyJubJub.Point memory p1 = t.acc1.length == 0 ? BabyJubJub.identity() : BabyJubJub.toAffine(t.acc1[i]);
            BabyJubJub.Point memory p2 = t.acc2.length == 0 ? BabyJubJub.identity() : BabyJubJub.toAffine(t.acc2[i]);
            t.c1.push(p1);
            t.c2.push(p2);
            t.counts.push(0);
            t.slotFinalized.push(false);
            c1Flat[2 * i] = p1.x;
            c1Flat[2 * i + 1] = p1.y;
            c2Flat[2 * i] = p2.x;
            c2Flat[2 * i + 1] = p2.y;
        }
        t.normalized = true;
        emit TallyNormalized(electionId, c1Flat, c2Flat);
    }

    // ------------------------------------------------------------------------------------------
    // Decryption
    // ------------------------------------------------------------------------------------------

    /// @param partials D_j for every active slot; @param proofs Chaum–Pedersen proofs, one per slot
    function submitPartialDecryption(uint256 electionId, BabyJubJub.Point[] calldata partials, ChaumPedersen.Proof[] calldata proofs)
        external
        nonReentrant
    {
        ElectionTally storage t = _requireTallying(electionId);
        if (!t.normalized) revert NotNormalized();
        ITrusteeCoordinator coord = ITrusteeCoordinator(factory.coordinator());
        uint8 j = coord.trusteeIndex(electionId, msg.sender);
        if (j == 0) revert NotTrustee();
        if (_partials[electionId][j].length != 0) revert AlreadySubmitted();
        uint8 nc = t.numCandidates;
        if (partials.length != nc || proofs.length != nc) revert WrongPartialCount();
        BabyJubJub.Point memory s = coord.verificationKey(electionId, j);
        uint256[] memory flat = new uint256[](2 * nc);
        for (uint8 i = 0; i < nc; i++) {
            _verifyAndStorePartial(electionId, j, s, t.c1[i], partials[i], proofs[i], i);
            flat[2 * i] = partials[i].x;
            flat[2 * i + 1] = partials[i].y;
        }
        t.partialCount += 1;
        emit PartialDecryptionSubmitted(electionId, j, flat);
    }

    function _verifyAndStorePartial(
        uint256 electionId,
        uint8 j,
        BabyJubJub.Point memory s,
        BabyJubJub.Point memory c1,
        BabyJubJub.Point calldata d,
        ChaumPedersen.Proof calldata proof,
        uint8 slot
    ) internal {
        if (!ChaumPedersen.verify(s, c1, d, proof, electionId, slot)) revert InvalidPartialDecryption(slot);
        _partials[electionId][j].push(d);
    }

    /**
     * @notice Finalises one slot from `t` partial decryptions: X = Σ λ_j D_j, check count·G + X == C2.
     * @param trusteeSubset exactly `threshold` distinct trustee indices that have submitted
     */
    function finalizeSlot(uint256 electionId, uint8 slot, uint32 count, uint8[] calldata trusteeSubset) external nonReentrant {
        ElectionTally storage t = _requireTallying(electionId);
        if (!t.normalized) revert NotNormalized();
        if (slot >= t.numCandidates) revert SlotOutOfRange();
        if (t.slotFinalized[slot]) revert SlotAlreadyFinalized();
        ITrusteeCoordinator coord = ITrusteeCoordinator(factory.coordinator());
        uint8 th = coord.threshold(electionId);
        if (trusteeSubset.length != th) revert WrongSubsetSize(th, trusteeSubset.length);
        uint256[] memory idx = new uint256[](th);
        for (uint256 i = 0; i < th; i++) {
            uint8 j = trusteeSubset[i];
            if (_partials[electionId][j].length == 0) revert TrusteeNotSubmitted(j);
            idx[i] = j;
        }
        uint256[] memory lambda = Lagrange.coefficients(idx); // reverts on duplicates
        BabyJubJub.ProjectivePoint memory x = BabyJubJub.projIdentity();
        for (uint256 i = 0; i < th; i++) {
            BabyJubJub.Point memory dj = _partials[electionId][trusteeSubset[i]][slot];
            BabyJubJub.ProjectivePoint memory term = BabyJubJub.projMul(dj, lambda[i]);
            BabyJubJub.addInPlace(x, term);
        }
        // count·G + X == C2  ⟺  C2 − X == count·G
        BabyJubJub.ProjectivePoint memory cg = BabyJubJub.projMul(BabyJubJub.generator(), count);
        BabyJubJub.addInPlace(x, cg);
        if (!BabyJubJub.projEqualsAffine(x, t.c2[slot])) revert WrongCount();
        t.counts[slot] = count;
        t.slotFinalized[slot] = true;
        t.finalizedSlots += 1;
        emit SlotFinalized(electionId, slot, count, trusteeSubset);
        if (t.finalizedSlots == t.numCandidates) _finalizeElection(electionId, t);
    }

    function _finalizeElection(uint256 electionId, ElectionTally storage t) internal {
        IElection election = IElection(t.election);
        uint32 ballots = election.ballotCount();
        uint256 sum;
        for (uint256 i = 0; i < t.counts.length; i++) sum += t.counts[i];
        if (sum != ballots) revert CountSumMismatch(sum, ballots);
        t.finalized = true;
        emit TallyFinalized(electionId, t.counts, ballots);
        election.markFinalized(t.counts);
    }

    // ------------------------------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------------------------------

    function status(uint256 electionId)
        external
        view
        returns (uint8 numCandidates, bool normalized, bool finalized, uint8 partialCount, uint8 finalizedSlots, uint32 aggregatedCount, uint256 lastNullifier)
    {
        ElectionTally storage t = _tallies[electionId];
        return (t.numCandidates, t.normalized, t.finalized, t.partialCount, t.finalizedSlots, t.aggregatedCount, t.lastNullifier);
    }

    function encryptedTally(uint256 electionId) external view returns (BabyJubJub.Point[] memory c1, BabyJubJub.Point[] memory c2) {
        ElectionTally storage t = _tallies[electionId];
        return (t.c1, t.c2);
    }

    function partialDecryptions(uint256 electionId, uint8 trustee) external view returns (BabyJubJub.Point[] memory) {
        return _partials[electionId][trustee];
    }

    function counts(uint256 electionId) external view returns (uint32[] memory) {
        return _tallies[electionId].counts;
    }

    function slotFinalized(uint256 electionId, uint8 slot) external view returns (bool) {
        return _tallies[electionId].slotFinalized[slot];
    }

    function _requireTallying(uint256 electionId) internal view returns (ElectionTally storage t) {
        t = _tallies[electionId];
        if (t.election == address(0)) revert UnknownElection();
        IElection e = IElection(t.election);
        if (e.phase() != IElection.Phase.Tallying) revert WrongPhase();
        if (e.paused()) revert ElectionPaused();
    }

    function _authorizeUpgrade(address) internal view override {
        if (!factory.isUpgradeAuthority(msg.sender)) revert NotUpgradeAuthority();
        if (factory.activeElections() != 0) revert ElectionsActive();
    }
}

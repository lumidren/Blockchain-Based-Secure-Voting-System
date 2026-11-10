// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardTransientUpgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardTransientUpgradeable.sol";
import {BabyJubJub} from "./libraries/BabyJubJub.sol";
import {IElection, IVeriVoteFactory, IVoterRegistry, ITrusteeCoordinator} from "./interfaces/IVeriVote.sol";

/**
 * @title Election
 * @notice One UUPS proxy per election. Owns the phase machine, the candidate list, the schedule, the
 *         ballot box (nullifier → latest ballot commitment) and the emergency pause.
 * @dev Invariants (see test/invariant):
 *      - phase index never decreases;
 *      - a nullifier's ballot count only increases, by one per accepted castVote;
 *      - pause cannot modify records, ballotCount or results and never shortens the voting window;
 *      - upgrades are only possible while phase == Setup.
 */
contract Election is IElection, Initializable, UUPSUpgradeable, ReentrancyGuardTransientUpgradeable {
    using BabyJubJub for BabyJubJub.Point;

    /// @dev packed into one storage slot
    struct Status {
        Phase phase;
        bool allowRevote;
        bool paused;
        uint8 slots;
        uint8 numCandidates;
        uint64 registrationStart;
        uint64 votingStart;
        uint64 votingEnd;
    }

    struct Timing {
        uint64 tallyDeadline;
        uint64 pausedAt;
        uint32 ballotCount;
        uint32 leafCount;
    }

    struct Record {
        uint224 ballotHash;
        uint32 count;
    }

    error NotAdmin();
    error NotFactory();
    error NotTally();
    error NotPauser();
    error NotUpgradeAuthority();
    error WrongPhase(Phase expected, Phase actual);
    error UpgradeOnlyInSetup();
    error IsPaused();
    error NotPaused();
    error TooEarly(uint64 until);
    error InvalidSchedule();
    error InvalidCandidates();
    error DkgNotFinalized();
    error EmptyRoll();
    error VotingClosed();
    error WrongSignalCount(uint256 expected, uint256 actual);
    error WrongRoot();
    error WrongElectionId();
    error WrongPublicKey();
    error WrongCandidateCount();
    error WrongVoteIndex(uint32 expected, uint256 actual);
    error RevoteNotAllowed();
    error InvalidProof();
    error CannotAbort();
    error WrongResultsLength();
    error SignalOutOfField();

    /// @dev Groth16 verification costs ≈ 210k (K=4) / 310k (K=8) gas; 600k leaves ample headroom.
    uint256 public constant VERIFIER_GAS_LIMIT = 600_000;

    uint256 public electionId;
    IVeriVoteFactory public factory;
    IVoterRegistry public registry;
    ITrusteeCoordinator public coordinator;
    address public tally;
    address public verifier;
    bytes4 public verifierSelector;
    uint16 public numSignals;
    address public admin;
    string public title;
    string public metadataURI;
    string[] private _candidates;
    Status private _status;
    Timing private _timing;
    uint256 public snapshotRoot;
    BabyJubJub.Point private _snapshotKey;
    mapping(uint256 nullifier => Record) private _records;
    uint32[] private _results;
    bytes32 public resultsHash;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    struct InitArgs {
        uint256 electionId;
        address admin;
        string title;
        string metadataURI;
        string[] candidates;
        uint8 slots;
        bool allowRevote;
        uint64 registrationStart;
        uint64 votingStart;
        uint64 votingEnd;
        uint64 tallyDeadline;
        address verifier;
        bytes4 verifierSelector;
        uint16 numSignals;
    }

    function initialize(InitArgs calldata a) external initializer {
        __UUPSUpgradeable_init();
        __ReentrancyGuardTransient_init();
        factory = IVeriVoteFactory(msg.sender);
        registry = IVoterRegistry(factory.registry());
        coordinator = ITrusteeCoordinator(factory.coordinator());
        tally = factory.tally();
        electionId = a.electionId;
        admin = a.admin;
        title = a.title;
        metadataURI = a.metadataURI;
        verifier = a.verifier;
        verifierSelector = a.verifierSelector;
        numSignals = a.numSignals;
        _status.slots = a.slots;
        _status.allowRevote = a.allowRevote;
        _setCandidates(a.candidates);
        _setSchedule(a.registrationStart, a.votingStart, a.votingEnd, a.tallyDeadline);
        emit MetadataSet(a.title, a.metadataURI);
    }

    // ------------------------------------------------------------------------------------------
    // Modifiers
    // ------------------------------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier inPhase(Phase p) {
        if (_status.phase != p) revert WrongPhase(p, _status.phase);
        _;
    }

    modifier whenNotPaused() {
        if (_status.paused) revert IsPaused();
        _;
    }

    // ------------------------------------------------------------------------------------------
    // Setup-phase configuration (admin only, immutable afterwards)
    // ------------------------------------------------------------------------------------------

    function setCandidates(string[] calldata candidates) external onlyAdmin inPhase(Phase.Setup) {
        _setCandidates(candidates);
    }

    function setSchedule(uint64 registrationStart, uint64 votingStart, uint64 votingEnd, uint64 tallyDeadline)
        external
        onlyAdmin
        inPhase(Phase.Setup)
    {
        _setSchedule(registrationStart, votingStart, votingEnd, tallyDeadline);
    }

    function setMetadata(string calldata newTitle, string calldata newMetadataURI) external onlyAdmin inPhase(Phase.Setup) {
        title = newTitle;
        metadataURI = newMetadataURI;
        emit MetadataSet(newTitle, newMetadataURI);
    }

    function _setCandidates(string[] calldata candidates) internal {
        if (candidates.length < 2 || candidates.length > _status.slots) revert InvalidCandidates();
        delete _candidates;
        for (uint256 i = 0; i < candidates.length; i++) {
            if (bytes(candidates[i]).length == 0) revert InvalidCandidates();
            _candidates.push(candidates[i]);
        }
        _status.numCandidates = uint8(candidates.length);
        emit CandidatesSet(candidates);
    }

    function _setSchedule(uint64 registrationStart, uint64 votingStart, uint64 votingEnd, uint64 tallyDeadline) internal {
        if (!(registrationStart < votingStart && votingStart < votingEnd && votingEnd < tallyDeadline)) revert InvalidSchedule();
        _status.registrationStart = registrationStart;
        _status.votingStart = votingStart;
        _status.votingEnd = votingEnd;
        _timing.tallyDeadline = tallyDeadline;
        emit ScheduleSet(registrationStart, votingStart, votingEnd, tallyDeadline);
    }

    // ------------------------------------------------------------------------------------------
    // Phase machine (permissionless, time-locked)
    // ------------------------------------------------------------------------------------------

    /// @notice Advances to the next phase once its scheduled time and preconditions are met.
    function advance() external whenNotPaused nonReentrant {
        Status memory s = _status;
        if (s.phase == Phase.Setup) {
            if (block.timestamp < s.registrationStart) revert TooEarly(s.registrationStart);
            _status.phase = Phase.Registration;
            emit PhaseAdvanced(Phase.Setup, Phase.Registration, block.timestamp);
            factory.onElectionActivated(electionId);
        } else if (s.phase == Phase.Registration) {
            if (block.timestamp < s.votingStart) revert TooEarly(s.votingStart);
            if (!coordinator.isFinalized(electionId)) revert DkgNotFinalized();
            (uint256 root, uint32 leafCount) = registry.currentRoot(electionId);
            if (leafCount == 0) revert EmptyRoll();
            BabyJubJub.Point memory pk = coordinator.publicKey(electionId);
            snapshotRoot = root;
            _snapshotKey = pk;
            _timing.leafCount = leafCount;
            _status.phase = Phase.Voting;
            emit VotingSnapshot(root, leafCount, pk.x, pk.y);
            emit PhaseAdvanced(Phase.Registration, Phase.Voting, block.timestamp);
        } else if (s.phase == Phase.Voting) {
            if (block.timestamp < s.votingEnd) revert TooEarly(s.votingEnd);
            _status.phase = Phase.Tallying;
            emit PhaseAdvanced(Phase.Voting, Phase.Tallying, block.timestamp);
        } else {
            revert WrongPhase(Phase.Voting, s.phase);
        }
    }

    /// @notice Records the decrypted result. Only the Tally contract can call this, only from Tallying.
    function markFinalized(uint32[] calldata counts) external inPhase(Phase.Tallying) {
        if (msg.sender != tally) revert NotTally();
        if (counts.length != _status.numCandidates) revert WrongResultsLength();
        _results = counts;
        resultsHash = keccak256(abi.encodePacked(counts));
        _status.phase = Phase.Finalized;
        emit ResultsRecorded(counts, resultsHash);
        emit PhaseAdvanced(Phase.Tallying, Phase.Finalized, block.timestamp);
        factory.onElectionClosed(electionId);
    }

    /**
     * @notice Aborts the election. Allowed for the admin before voting starts, or for anyone under
     *         objective failure conditions: the DKG did not finalize by votingStart, or the tally was not
     *         finalized by tallyDeadline. Voting can never be aborted by anyone.
     */
    function abort(string calldata reason) external nonReentrant {
        Phase from = _status.phase;
        if (!_abortAllowed(from)) revert CannotAbort();
        _status.phase = Phase.Aborted;
        emit ElectionAborted(msg.sender, from, reason);
        emit PhaseAdvanced(from, Phase.Aborted, block.timestamp);
        if (from != Phase.Setup) factory.onElectionClosed(electionId);
    }

    function _abortAllowed(Phase from) internal view returns (bool) {
        if (from == Phase.Setup) return msg.sender == admin;
        if (from == Phase.Registration) {
            if (msg.sender == admin) return true;
            return block.timestamp >= _status.votingStart && !coordinator.isFinalized(electionId);
        }
        if (from == Phase.Tallying) return block.timestamp >= _timing.tallyDeadline;
        return false;
    }

    // ------------------------------------------------------------------------------------------
    // Emergency pause: blocks casting, roll updates, DKG and tally submissions; cannot touch state.
    // ------------------------------------------------------------------------------------------

    function pause() external {
        if (!factory.isPauser(msg.sender)) revert NotPauser();
        if (_status.paused) revert IsPaused();
        Phase p = _status.phase;
        if (p == Phase.Finalized || p == Phase.Aborted) revert WrongPhase(Phase.Voting, p);
        _status.paused = true;
        _timing.pausedAt = uint64(block.timestamp);
        emit Paused(msg.sender, uint64(block.timestamp));
    }

    /// @dev Time spent paused extends the voting window (and the tally deadline) by the same amount.
    function unpause() external {
        if (!factory.isPauser(msg.sender)) revert NotPauser();
        if (!_status.paused) revert NotPaused();
        uint64 now_ = uint64(block.timestamp);
        uint64 pausedAt = _timing.pausedAt;
        uint64 votingExtension;
        uint64 tallyExtension;
        Phase p = _status.phase;
        if (p == Phase.Registration || p == Phase.Voting) {
            uint64 overlapStart = pausedAt > _status.votingStart ? pausedAt : _status.votingStart;
            if (now_ > overlapStart) votingExtension = now_ - overlapStart;
            _status.votingEnd += votingExtension;
            _timing.tallyDeadline += votingExtension;
        } else if (p == Phase.Tallying) {
            tallyExtension = now_ - pausedAt;
            _timing.tallyDeadline += tallyExtension;
        }
        _status.paused = false;
        _timing.pausedAt = 0;
        emit Unpaused(msg.sender, now_, votingExtension, tallyExtension);
    }

    // ------------------------------------------------------------------------------------------
    // Voting
    // ------------------------------------------------------------------------------------------

    /**
     * @notice Casts (or re-casts) a ballot. Permissionless: the Groth16 proof is the authorisation.
     * @param signals public signals in circuit order: c1[K].xy, c2[K].xy, nullifier, root, electionId, pk.x, pk.y, numCandidates, voteIndex
     */
    function castVote(uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c, uint256[] calldata signals)
        external
        inPhase(Phase.Voting)
        whenNotPaused
        nonReentrant
    {
        Status memory s = _status;
        if (block.timestamp >= s.votingEnd) revert VotingClosed();
        if (signals.length != numSignals) revert WrongSignalCount(numSignals, signals.length);
        uint256 base = uint256(s.slots) * 4;
        uint256 nullifier = signals[base];
        if (signals[base + 1] != snapshotRoot) revert WrongRoot();
        if (signals[base + 2] != electionId) revert WrongElectionId();
        if (signals[base + 3] != _snapshotKey.x || signals[base + 4] != _snapshotKey.y) revert WrongPublicKey();
        if (signals[base + 5] != s.numCandidates) revert WrongCandidateCount();
        uint256 voteIndex = signals[base + 6];

        Record memory rec = _records[nullifier];
        if (rec.count != 0 && !s.allowRevote) revert RevoteNotAllowed();
        if (voteIndex != rec.count) revert WrongVoteIndex(rec.count, voteIndex);

        if (!_verifyProof(a, b, c, signals)) revert InvalidProof();

        // effects
        uint224 ballotHash = uint224(uint256(keccak256(abi.encodePacked(signals[:base]))) >> 32);
        if (rec.count == 0) _timing.ballotCount += 1;
        _records[nullifier] = Record({ballotHash: ballotHash, count: rec.count + 1});
        emit BallotCast(nullifier, rec.count, ballotHash, signals[:base]);
    }

    /// @dev Calls the generated Groth16 verifier through a static call with a fixed-size signal array,
    ///      which lets one Election implementation serve circuits with different public-input counts.
    function _verifyProof(uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c, uint256[] calldata signals)
        internal
        view
        returns (bool)
    {
        bytes memory data =
            abi.encodePacked(verifierSelector, a[0], a[1], b[0][0], b[0][1], b[1][0], b[1][1], c[0], c[1], signals);
        // Gas is capped: a malformed point makes the pairing precompile fail and consume all gas it is given.
        (bool ok, bytes memory ret) = verifier.staticcall{gas: VERIFIER_GAS_LIMIT}(data);
        return ok && ret.length == 32 && abi.decode(ret, (bool));
    }

    // ------------------------------------------------------------------------------------------
    // Upgrades: only the timelock, only before anything is at stake.
    // ------------------------------------------------------------------------------------------

    function _authorizeUpgrade(address) internal view override {
        if (!factory.isUpgradeAuthority(msg.sender)) revert NotUpgradeAuthority();
        if (_status.phase != Phase.Setup) revert UpgradeOnlyInSetup();
    }

    // ------------------------------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------------------------------

    function phase() external view returns (Phase) {
        return _status.phase;
    }

    function paused() external view returns (bool) {
        return _status.paused;
    }

    function allowRevote() external view returns (bool) {
        return _status.allowRevote;
    }

    function slots() external view returns (uint8) {
        return _status.slots;
    }

    function numCandidates() external view returns (uint8) {
        return _status.numCandidates;
    }

    function candidates() external view returns (string[] memory) {
        return _candidates;
    }

    function schedule() external view returns (uint64 registrationStart, uint64 votingStart, uint64 votingEnd, uint64 tallyDeadline) {
        return (_status.registrationStart, _status.votingStart, _status.votingEnd, _timing.tallyDeadline);
    }

    function ballotCount() external view returns (uint32) {
        return _timing.ballotCount;
    }

    function leafCount() external view returns (uint32) {
        return _timing.leafCount;
    }

    function pausedAt() external view returns (uint64) {
        return _timing.pausedAt;
    }

    function snapshotKey() external view returns (uint256 x, uint256 y) {
        return (_snapshotKey.x, _snapshotKey.y);
    }

    function ballotRecord(uint256 nullifier) external view returns (uint224 ballotHash, uint32 count) {
        Record memory r = _records[nullifier];
        return (r.ballotHash, r.count);
    }

    function results() external view returns (uint32[] memory) {
        return _results;
    }
}

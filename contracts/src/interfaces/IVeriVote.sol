// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BabyJubJub} from "../libraries/BabyJubJub.sol";
import {ChaumPedersen} from "../libraries/ChaumPedersen.sol";

/// @notice Parameters supplied to VeriVoteFactory.createElection.
struct ElectionParams {
    address admin;
    address registrar;
    string title;
    string metadataURI;
    string[] candidates;
    /// @dev ballot slots K of the circuit to use (4 or 8)
    uint8 slots;
    bool allowRevote;
    uint64 registrationStart;
    uint64 votingStart;
    uint64 votingEnd;
    uint64 tallyDeadline;
    address[] trustees;
    uint8 threshold;
    /// @dev keyDeadline, dealDeadline, complaintDeadline, justifyDeadline, revealDeadline, revealComplaintDeadline
    uint64[6] dkgSchedule;
}

interface IVeriVoteFactory {
    event ElectionCreated(uint256 indexed electionId, address indexed election, address indexed admin, uint8 slots);
    event VerifierSet(uint8 indexed slots, address verifier, uint16 numSignals);
    event ElectionImplementationSet(address indexed implementation);
    event ElectionActivated(uint256 indexed electionId, uint256 activeElections);
    event ElectionClosed(uint256 indexed electionId, uint256 activeElections);

    function isUpgradeAuthority(address account) external view returns (bool);
    function isPauser(address account) external view returns (bool);
    function activeElections() external view returns (uint256);
    function onElectionActivated(uint256 electionId) external;
    function onElectionClosed(uint256 electionId) external;
    function registry() external view returns (address);
    function coordinator() external view returns (address);
    function tally() external view returns (address);
    function electionAddress(uint256 electionId) external view returns (address);
}

interface IElection {
    enum Phase {
        Setup,
        Registration,
        Voting,
        Tallying,
        Finalized,
        Aborted
    }

    event CandidatesSet(string[] candidates);
    event ScheduleSet(uint64 registrationStart, uint64 votingStart, uint64 votingEnd, uint64 tallyDeadline);
    event MetadataSet(string title, string metadataURI);
    event PhaseAdvanced(Phase indexed from, Phase indexed to, uint256 timestamp);
    event VotingSnapshot(uint256 merkleRoot, uint32 leafCount, uint256 pkX, uint256 pkY);
    event BallotCast(uint256 indexed nullifier, uint32 voteIndex, uint224 ballotHash, uint256[] ciphertext);
    event Paused(address indexed by, uint64 at);
    event Unpaused(address indexed by, uint64 at, uint64 votingExtension, uint64 tallyExtension);
    event ElectionAborted(address indexed by, Phase fromPhase, string reason);
    event ResultsRecorded(uint32[] counts, bytes32 resultsHash);

    function electionId() external view returns (uint256);
    function phase() external view returns (Phase);
    function admin() external view returns (address);
    function paused() external view returns (bool);
    function ballotCount() external view returns (uint32);
    function numCandidates() external view returns (uint8);
    function slots() external view returns (uint8);
    function ballotRecord(uint256 nullifier) external view returns (uint224 ballotHash, uint32 count);
    function markFinalized(uint32[] calldata counts) external;
}

interface IVoterRegistry {
    event ElectionRegistered(uint256 indexed electionId, address election, address registrar);
    event RegistrarSet(uint256 indexed electionId, address registrar);
    event RootPublished(uint256 indexed electionId, uint256 indexed root, uint32 leafCount, uint256 rootIndex);
    event LeavesAppended(uint256 indexed electionId, uint32 startIndex, uint256[] leaves);

    function initElection(uint256 electionId, address election, address registrar) external;
    function currentRoot(uint256 electionId) external view returns (uint256 root, uint32 leafCount);
}

interface ITrusteeCoordinator {
    event ElectionRegistered(uint256 indexed electionId, address election, address[] trustees, uint8 threshold);
    event EncryptionKeyRegistered(uint256 indexed electionId, uint8 indexed trustee, uint256 x, uint256 y);
    event Dealt(uint256 indexed electionId, uint8 indexed dealer);
    event SharesDelivered(uint256 indexed electionId, uint8 indexed dealer, bytes[] encryptedShares);
    event ComplaintFiled(uint256 indexed electionId, uint8 indexed dealer, uint8 indexed complainant);
    event ComplaintJustified(uint256 indexed electionId, uint8 indexed dealer, uint8 indexed complainant, uint256 s, uint256 sPrime);
    event DealerDisqualified(uint256 indexed electionId, uint8 indexed dealer, string reason);
    event Revealed(uint256 indexed electionId, uint8 indexed dealer);
    event DkgFailed(uint256 indexed electionId, uint8 indexed dealer, string reason);
    event DkgFinalized(uint256 indexed electionId, uint256 pkX, uint256 pkY, uint8 qualified);

    function initElection(
        uint256 electionId,
        address election,
        address[] calldata trusteeList,
        uint8 quorum,
        uint64[6] calldata timeline
    ) external;
    function publicKey(uint256 electionId) external view returns (BabyJubJub.Point memory);
    function isFinalized(uint256 electionId) external view returns (bool);
    function trusteeIndex(uint256 electionId, address trustee) external view returns (uint8);
    function trusteeCount(uint256 electionId) external view returns (uint8);
    function threshold(uint256 electionId) external view returns (uint8);
    function verificationKey(uint256 electionId, uint8 trustee) external view returns (BabyJubJub.Point memory);
}

interface ITally {
    struct Ballot {
        uint256 nullifier;
        /// @dev 4K words: c1[0].x, c1[0].y, …, c2[K-1].x, c2[K-1].y — exactly the circuit output order
        uint256[] ciphertext;
    }

    event ElectionRegistered(uint256 indexed electionId, address election, uint8 slots);
    event BallotsAggregated(uint256 indexed electionId, uint32 count, uint32 aggregatedTotal, uint256 lastNullifier);
    event TallyNormalized(uint256 indexed electionId, uint256[] c1, uint256[] c2);
    event PartialDecryptionSubmitted(uint256 indexed electionId, uint8 indexed trustee, uint256[] partials);
    event SlotFinalized(uint256 indexed electionId, uint8 indexed slot, uint32 count, uint8[] trustees);
    event TallyFinalized(uint256 indexed electionId, uint32[] counts, uint32 ballotCount);

    function initElection(uint256 electionId, address election, uint8 slots) external;
}

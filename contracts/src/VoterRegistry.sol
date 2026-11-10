// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IElection, IVeriVoteFactory, IVoterRegistry} from "./interfaces/IVeriVote.sol";

/**
 * @title VoterRegistry
 * @notice Per-election Merkle root history of identity commitments. The registrar publishes new roots
 *         together with the appended leaves (as calldata, emitted in events) so anyone can rebuild the
 *         tree and check the root. Roots can only change during the Registration phase; the Election
 *         snapshots the root when Voting starts.
 */
contract VoterRegistry is IVoterRegistry, Initializable, UUPSUpgradeable {
    struct RootEntry {
        uint256 root;
        uint32 leafCount;
        uint64 blockNumber;
        uint64 timestamp;
    }

    struct ElectionRoll {
        address election;
        address registrar;
        RootEntry[] roots;
    }

    error NotFactory();
    error NotRegistrar();
    error NotElectionAdmin();
    error NotUpgradeAuthority();
    error ElectionsActive();
    error UnknownElection();
    error AlreadyRegistered();
    error WrongPhase();
    error ElectionPaused();
    error LeafCountMismatch(uint32 expected, uint32 actual);
    error LeafOutOfField();
    error ZeroRoot();
    error TooManyLeaves();

    uint256 internal constant FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant MAX_LEAVES_PER_BATCH = 2048;
    uint32 public constant MAX_LEAVES = 1_048_576; // depth-20 tree

    IVeriVoteFactory public factory;
    mapping(uint256 electionId => ElectionRoll) private _rolls;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address factory_) external initializer {
        __UUPSUpgradeable_init();
        factory = IVeriVoteFactory(factory_);
    }

    function initElection(uint256 electionId, address election, address registrar) external {
        if (msg.sender != address(factory)) revert NotFactory();
        ElectionRoll storage roll = _rolls[electionId];
        if (roll.election != address(0)) revert AlreadyRegistered();
        roll.election = election;
        roll.registrar = registrar;
        emit ElectionRegistered(electionId, election, registrar);
    }

    /// @notice The election admin may rotate the registrar while the election is still in Setup.
    function setRegistrar(uint256 electionId, address registrar) external {
        ElectionRoll storage roll = _rolls[electionId];
        if (roll.election == address(0)) revert UnknownElection();
        IElection e = IElection(roll.election);
        if (msg.sender != e.admin()) revert NotElectionAdmin();
        if (e.phase() != IElection.Phase.Setup) revert WrongPhase();
        roll.registrar = registrar;
        emit RegistrarSet(electionId, registrar);
    }

    /**
     * @notice Publishes a new root after appending `leaves`. `newLeafCount` must equal the previous count
     *         plus `leaves.length`, which makes the on-chain leaf stream gap-free and replayable.
     */
    function publishRoot(uint256 electionId, uint256 newRoot, uint256[] calldata leaves, uint32 newLeafCount) external {
        ElectionRoll storage roll = _rolls[electionId];
        if (roll.election == address(0)) revert UnknownElection();
        if (msg.sender != roll.registrar) revert NotRegistrar();
        IElection e = IElection(roll.election);
        if (e.phase() != IElection.Phase.Registration) revert WrongPhase();
        if (e.paused()) revert ElectionPaused();
        if (newRoot == 0) revert ZeroRoot();
        if (leaves.length > MAX_LEAVES_PER_BATCH) revert TooManyLeaves();
        uint32 prev = roll.roots.length == 0 ? 0 : roll.roots[roll.roots.length - 1].leafCount;
        uint32 expected = prev + uint32(leaves.length);
        if (expected != newLeafCount || newLeafCount > MAX_LEAVES) revert LeafCountMismatch(expected, newLeafCount);
        for (uint256 i = 0; i < leaves.length; i++) {
            if (leaves[i] >= FIELD) revert LeafOutOfField();
        }
        roll.roots.push(RootEntry({root: newRoot, leafCount: newLeafCount, blockNumber: uint64(block.number), timestamp: uint64(block.timestamp)}));
        emit LeavesAppended(electionId, prev, leaves);
        emit RootPublished(electionId, newRoot, newLeafCount, roll.roots.length - 1);
    }

    function currentRoot(uint256 electionId) external view returns (uint256 root, uint32 leafCount) {
        RootEntry[] storage roots = _rolls[electionId].roots;
        if (roots.length == 0) return (0, 0);
        RootEntry storage last = roots[roots.length - 1];
        return (last.root, last.leafCount);
    }

    function rootCount(uint256 electionId) external view returns (uint256) {
        return _rolls[electionId].roots.length;
    }

    function rootAt(uint256 electionId, uint256 index) external view returns (RootEntry memory) {
        return _rolls[electionId].roots[index];
    }

    function isKnownRoot(uint256 electionId, uint256 root) external view returns (bool) {
        RootEntry[] storage roots = _rolls[electionId].roots;
        for (uint256 i = 0; i < roots.length; i++) {
            if (roots[i].root == root) return true;
        }
        return false;
    }

    function registrarOf(uint256 electionId) external view returns (address) {
        return _rolls[electionId].registrar;
    }

    function electionOf(uint256 electionId) external view returns (address) {
        return _rolls[electionId].election;
    }

    function _authorizeUpgrade(address) internal view override {
        if (!factory.isUpgradeAuthority(msg.sender)) revert NotUpgradeAuthority();
        if (factory.activeElections() != 0) revert ElectionsActive();
    }
}

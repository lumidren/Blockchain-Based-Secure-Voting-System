// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Election} from "./Election.sol";
import {ElectionParams, IElection, IVeriVoteFactory, IVoterRegistry, ITrusteeCoordinator, ITally} from "./interfaces/IVeriVote.sol";

/**
 * @title VeriVoteFactory
 * @notice Creates elections (as UUPS proxies), wires them into the registry / coordinator / tally
 *         singletons, holds the verifier registry and the roles for pausing and upgrading.
 * @dev DEFAULT_ADMIN_ROLE is meant to be a TimelockController controlled by a Safe multisig.
 *      No singleton (including this one) can be upgraded while any election is active.
 */
contract VeriVoteFactory is IVeriVoteFactory, Initializable, UUPSUpgradeable, AccessControlUpgradeable {
    struct VerifierInfo {
        address verifier;
        uint16 numSignals;
        bytes4 selector;
    }

    error ZeroAddress();
    error NoVerifierForSlots(uint8 slots);
    error InvalidCandidates();
    error InvalidSchedule();
    error UnknownElection();
    error NotElection();
    error ElectionsActive();
    error TooShort();

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    uint64 public constant MIN_REGISTRATION_WINDOW = 10 minutes;
    uint64 public constant MIN_VOTING_WINDOW = 10 minutes;
    uint64 public constant MIN_TALLY_WINDOW = 10 minutes;

    address public electionImplementation;
    address public registry;
    address public coordinator;
    address public tally;
    uint256 public electionCount;
    uint256 public activeElections;
    mapping(uint8 slots => VerifierInfo) private _verifiers;
    mapping(uint256 index => uint256 electionId) public electionIdAt;
    mapping(uint256 electionId => address) private _elections;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address pauser, address electionImplementation_) external initializer {
        if (timelock == address(0) || pauser == address(0) || electionImplementation_ == address(0)) revert ZeroAddress();
        __UUPSUpgradeable_init();
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(PAUSER_ROLE, pauser);
        electionImplementation = electionImplementation_;
        emit ElectionImplementationSet(electionImplementation_);
    }

    /// @dev Singletons are deployed after the factory (they need its address); wired once by the deployer-admin.
    function setModules(address registry_, address coordinator_, address tally_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (registry_ == address(0) || coordinator_ == address(0) || tally_ == address(0)) revert ZeroAddress();
        if (registry != address(0)) revert ElectionsActive(); // modules are immutable once set
        registry = registry_;
        coordinator = coordinator_;
        tally = tally_;
    }

    function setVerifier(uint8 slots, address verifier, uint16 numSignals) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        bytes4 selector = bytes4(
            keccak256(abi.encodePacked("verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[", Strings.toString(numSignals), "])"))
        );
        _verifiers[slots] = VerifierInfo({verifier: verifier, numSignals: numSignals, selector: selector});
        emit VerifierSet(slots, verifier, numSignals);
    }

    function setElectionImplementation(address impl) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (impl == address(0)) revert ZeroAddress();
        electionImplementation = impl;
        emit ElectionImplementationSet(impl);
    }

    /// @notice Creates an election proxy and registers it with every module.
    function createElection(ElectionParams calldata p) external returns (uint256 electionId, address election) {
        VerifierInfo memory v = _validate(p);
        uint256 index = ++electionCount;
        electionId = uint256(keccak256(abi.encode(block.chainid, address(this), index))) >> 8;
        election = _deployElection(p, v, electionId);
        _elections[electionId] = election;
        electionIdAt[index] = electionId;
        _registerModules(p, electionId, election);
        emit ElectionCreated(electionId, election, p.admin, p.slots);
    }

    function _validate(ElectionParams calldata p) internal view returns (VerifierInfo memory v) {
        v = _verifiers[p.slots];
        if (v.verifier == address(0)) revert NoVerifierForSlots(p.slots);
        if (v.numSignals != uint16(p.slots) * 4 + 7) revert NoVerifierForSlots(p.slots);
        if (p.candidates.length < 2 || p.candidates.length > p.slots) revert InvalidCandidates();
        if (p.admin == address(0) || p.registrar == address(0)) revert ZeroAddress();
        if (!(p.registrationStart < p.votingStart && p.votingStart < p.votingEnd && p.votingEnd < p.tallyDeadline)) {
            revert InvalidSchedule();
        }
        if (p.votingStart - p.registrationStart < MIN_REGISTRATION_WINDOW) revert TooShort();
        if (p.votingEnd - p.votingStart < MIN_VOTING_WINDOW) revert TooShort();
        if (p.tallyDeadline - p.votingEnd < MIN_TALLY_WINDOW) revert TooShort();
        if (p.dkgSchedule[5] > p.votingStart) revert InvalidSchedule();
    }

    function _deployElection(ElectionParams calldata p, VerifierInfo memory v, uint256 electionId) internal returns (address) {
        Election.InitArgs memory args;
        args.electionId = electionId;
        args.admin = p.admin;
        args.title = p.title;
        args.metadataURI = p.metadataURI;
        args.candidates = p.candidates;
        args.slots = p.slots;
        args.allowRevote = p.allowRevote;
        args.registrationStart = p.registrationStart;
        args.votingStart = p.votingStart;
        args.votingEnd = p.votingEnd;
        args.tallyDeadline = p.tallyDeadline;
        args.verifier = v.verifier;
        args.verifierSelector = v.selector;
        args.numSignals = v.numSignals;
        return address(new ERC1967Proxy(electionImplementation, abi.encodeCall(Election.initialize, (args))));
    }

    function _registerModules(ElectionParams calldata p, uint256 electionId, address election) internal {
        IVoterRegistry(registry).initElection(electionId, election, p.registrar);
        ITrusteeCoordinator(coordinator).initElection(electionId, election, p.trustees, p.threshold, p.dkgSchedule);
        ITally(tally).initElection(electionId, election, p.slots);
    }

    // ------------------------------------------------------------------------------------------
    // Callbacks from elections
    // ------------------------------------------------------------------------------------------

    function onElectionActivated(uint256 electionId) external {
        if (_elections[electionId] != msg.sender) revert NotElection();
        activeElections += 1;
        emit ElectionActivated(electionId, activeElections);
    }

    function onElectionClosed(uint256 electionId) external {
        if (_elections[electionId] != msg.sender) revert NotElection();
        activeElections -= 1;
        emit ElectionClosed(electionId, activeElections);
    }

    // ------------------------------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------------------------------

    function isUpgradeAuthority(address account) external view returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, account);
    }

    function isPauser(address account) external view returns (bool) {
        return hasRole(PAUSER_ROLE, account);
    }

    function electionAddress(uint256 electionId) external view returns (address) {
        return _elections[electionId];
    }

    function verifierFor(uint8 slots) external view returns (VerifierInfo memory) {
        return _verifiers[slots];
    }

    function _authorizeUpgrade(address) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (activeElections != 0) revert ElectionsActive();
    }
}

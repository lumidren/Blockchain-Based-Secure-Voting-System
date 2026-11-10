// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Election} from "../../src/Election.sol";
import {VeriVoteFactory} from "../../src/VeriVoteFactory.sol";
import {VoterRegistry} from "../../src/VoterRegistry.sol";
import {TrusteeCoordinator} from "../../src/TrusteeCoordinator.sol";
import {Tally} from "../../src/Tally.sol";
import {Groth16VerifierK4} from "../../src/verifiers/Groth16VerifierK4.sol";
import {Groth16VerifierK8} from "../../src/verifiers/Groth16VerifierK8.sol";
import {ElectionParams, IElection} from "../../src/interfaces/IVeriVote.sol";
import {BabyJubJub} from "../../src/libraries/BabyJubJub.sol";
import {ChaumPedersen} from "../../src/libraries/ChaumPedersen.sol";
import {Fixtures} from "../fixtures/Fixtures.sol";

/**
 * @dev Deploys the full system exactly like script/Deploy.s.sol (implementations, UUPS proxies, verifiers,
 *      module wiring, hand-over to a TimelockController) and drives elections through every phase using the
 *      pre-generated fixtures (real Groth16 proofs bound to the deterministic election IDs below).
 *      The deployment order MUST stay fixed: the fixture generator derives the factory address from it.
 */
abstract contract Base is Test {
    uint64 internal constant T0 = 1_000_000;
    uint256 internal constant TIMELOCK_DELAY = 2 days;

    address internal deployer = address(this);
    address internal safe = makeAddr("safe");
    address internal pauser = makeAddr("pauser");
    address internal admin = makeAddr("admin");
    address internal registrar = makeAddr("registrar");
    address internal relayer = makeAddr("relayer");
    address internal stranger = makeAddr("stranger");

    TimelockController internal timelock;
    VeriVoteFactory internal factory;
    VoterRegistry internal registry;
    TrusteeCoordinator internal coordinator;
    Tally internal tally;
    Groth16VerifierK4 internal verifier4;
    Groth16VerifierK8 internal verifier8;
    address internal electionImpl;

    address[] internal trustees;

    function setUp() public virtual {
        vm.warp(T0);
        electionImpl = address(new Election());
        VeriVoteFactory factoryImpl = new VeriVoteFactory();
        factory = VeriVoteFactory(
            address(new ERC1967Proxy(address(factoryImpl), abi.encodeCall(VeriVoteFactory.initialize, (deployer, pauser, electionImpl))))
        );
        registry = VoterRegistry(
            address(new ERC1967Proxy(address(new VoterRegistry()), abi.encodeCall(VoterRegistry.initialize, (address(factory)))))
        );
        coordinator = TrusteeCoordinator(
            address(
                new ERC1967Proxy(address(new TrusteeCoordinator()), abi.encodeCall(TrusteeCoordinator.initialize, (address(factory))))
            )
        );
        tally = Tally(address(new ERC1967Proxy(address(new Tally()), abi.encodeCall(Tally.initialize, (address(factory))))));
        verifier4 = new Groth16VerifierK4();
        verifier8 = new Groth16VerifierK8();
        factory.setModules(address(registry), address(coordinator), address(tally));
        factory.setVerifier(4, address(verifier4), 23);
        factory.setVerifier(8, address(verifier8), 39);

        address[] memory proposers = new address[](1);
        proposers[0] = safe;
        address[] memory executors = new address[](1);
        executors[0] = safe;
        timelock = new TimelockController(TIMELOCK_DELAY, proposers, executors, address(0));
        factory.grantRole(factory.DEFAULT_ADMIN_ROLE(), address(timelock));
        factory.renounceRole(factory.DEFAULT_ADMIN_ROLE(), deployer);

        for (uint256 i = 0; i < Fixtures.N; i++) {
            trustees.push(makeAddr(string.concat("trustee", vm.toString(i + 1))));
        }
    }

    // ------------------------------------------------------------------------------------------
    // Election lifecycle helpers
    // ------------------------------------------------------------------------------------------

    function _schedule() internal pure returns (uint64[6] memory s) {
        s[0] = T0 + 1 hours; // keys
        s[1] = T0 + 2 hours; // deal
        s[2] = T0 + 3 hours; // complain
        s[3] = T0 + 4 hours; // justify
        s[4] = T0 + 5 hours; // reveal
        s[5] = T0 + 6 hours; // reveal complaints
    }

    function _params(uint8 slots, uint256 numCandidates, bool allowRevote) internal view returns (ElectionParams memory p) {
        string[] memory names = new string[](numCandidates);
        for (uint256 i = 0; i < numCandidates; i++) names[i] = string.concat("Candidate ", vm.toString(i + 1));
        p = ElectionParams({
            admin: admin,
            registrar: registrar,
            title: "Board election",
            metadataURI: "ipfs://metadata",
            candidates: names,
            slots: slots,
            allowRevote: allowRevote,
            registrationStart: T0 + 30 minutes,
            votingStart: T0 + 7 hours,
            votingEnd: T0 + 9 hours,
            tallyDeadline: T0 + 12 hours,
            trustees: trustees,
            threshold: Fixtures.T,
            dkgSchedule: _schedule()
        });
    }

    function _create(uint8 slots, uint256 numCandidates, bool allowRevote) internal returns (uint256 id, Election e) {
        (uint256 electionId, address addr) = factory.createElection(_params(slots, numCandidates, allowRevote));
        return (electionId, Election(addr));
    }

    /// @dev Runs the whole DKG with the fixture's honest trustees.
    function _runDkg(uint256 id) internal {
        for (uint8 j = 1; j <= Fixtures.N; j++) {
            vm.prank(trustees[j - 1]);
            coordinator.registerKey(id, Fixtures.encryptionKey(j));
        }
        vm.warp(_schedule()[0] + 1);
        for (uint8 i = 1; i <= Fixtures.N; i++) {
            vm.prank(trustees[i - 1]);
            coordinator.deal(id, Fixtures.pedersen(i), Fixtures.shareBlobs(i));
        }
        vm.warp(_schedule()[3] + 1);
        for (uint8 i = 1; i <= Fixtures.N; i++) {
            vm.prank(trustees[i - 1]);
            coordinator.reveal(id, Fixtures.feldman(i));
        }
        vm.warp(_schedule()[5] + 1);
        coordinator.finalize(id);
    }

    function _publishRoll(uint256 id) internal {
        vm.prank(registrar);
        registry.publishRoot(id, Fixtures.rootAfter(4), Fixtures.leavesRange(0, 4), 4);
        vm.prank(registrar);
        registry.publishRoot(id, Fixtures.root(), Fixtures.leavesRange(4, Fixtures.VOTERS), uint32(Fixtures.VOTERS));
    }

    /// @dev Setup → Registration (+roll, DKG) → Voting.
    function _toVoting(uint256 id, Election e) internal {
        vm.warp(T0 + 30 minutes);
        e.advance();
        _publishRoll(id);
        _runDkg(id);
        vm.warp(T0 + 7 hours);
        e.advance();
    }

    function _cast(Election e, Fixtures.BallotProof memory b) internal {
        e.castVote(b.a, b.b, b.c, b.signals);
    }

    function _toTallying(Election e) internal {
        (,, uint64 votingEnd,) = e.schedule();
        vm.warp(votingEnd);
        e.advance();
    }

    // ------------------------------------------------------------------------------------------
    // Trustee-side decryption done in Solidity with the fixture shares (tests only)
    // ------------------------------------------------------------------------------------------

    function _partials(uint256 id, uint8 j, uint256 seed)
        internal
        view
        returns (BabyJubJub.Point[] memory ds, ChaumPedersen.Proof[] memory proofs)
    {
        (BabyJubJub.Point[] memory c1,) = tally.encryptedTally(id);
        uint256 share = Fixtures.share(j);
        BabyJubJub.Point memory s = BabyJubJub.mul(BabyJubJub.generator(), share);
        ds = new BabyJubJub.Point[](c1.length);
        proofs = new ChaumPedersen.Proof[](c1.length);
        for (uint256 i = 0; i < c1.length; i++) {
            uint256 w = uint256(keccak256(abi.encode(seed, j, i))) % (BabyJubJub.L - 1) + 1;
            ds[i] = BabyJubJub.mul(c1[i], share);
            BabyJubJub.Point memory a = BabyJubJub.mul(BabyJubJub.generator(), w);
            BabyJubJub.Point memory b = BabyJubJub.mul(c1[i], w);
            uint256 ch = ChaumPedersen.challenge(id, i, s, c1[i], ds[i], a, b);
            uint256 z = addmod(w, mulmod(ch, share, BabyJubJub.L), BabyJubJub.L);
            proofs[i] = ChaumPedersen.Proof(a, b, z);
        }
    }

    function _submitPartial(uint256 id, uint8 j) internal {
        (BabyJubJub.Point[] memory ds, ChaumPedersen.Proof[] memory proofs) = _partials(id, j, 42);
        vm.prank(trustees[j - 1]);
        tally.submitPartialDecryption(id, ds, proofs);
    }

    /// @dev Aggregates the final ballot of every nullifier (sorted), normalises, decrypts with trustees 1..t and finalises.
    function _aggregateAll(uint256 id, Fixtures.BallotProof[] memory finals) internal {
        Fixtures.sortByNullifier(finals);
        Tally.Ballot[] memory batch = new Tally.Ballot[](finals.length);
        for (uint256 i = 0; i < finals.length; i++) batch[i] = Fixtures.toTallyBallot(finals[i]);
        tally.aggregate(id, batch);
        tally.normalize(id);
    }

    function _decryptAndFinalize(uint256 id, uint32[] memory expected) internal {
        for (uint8 j = 1; j <= Fixtures.T; j++) _submitPartial(id, j);
        uint8[] memory subset = new uint8[](Fixtures.T);
        for (uint8 j = 0; j < Fixtures.T; j++) subset[j] = j + 1;
        for (uint8 i = 0; i < expected.length; i++) tally.finalizeSlot(id, i, expected[i], subset);
    }

    function _logAddresses() internal view {
        console2.log("factory", address(factory));
    }
}

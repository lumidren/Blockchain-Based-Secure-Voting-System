// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Base} from "./utils/Base.t.sol";
import {Fixtures} from "./fixtures/Fixtures.sol";
import {Election} from "../src/Election.sol";
import {VoterRegistry} from "../src/VoterRegistry.sol";
import {TrusteeCoordinator} from "../src/TrusteeCoordinator.sol";
import {Tally} from "../src/Tally.sol";
import {VeriVoteFactory} from "../src/VeriVoteFactory.sol";
import {ElectionParams, IElection, ITally} from "../src/interfaces/IVeriVote.sol";
import {BabyJubJub} from "../src/libraries/BabyJubJub.sol";
import {ChaumPedersen} from "../src/libraries/ChaumPedersen.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

// ============================================================================================
// VoterRegistry
// ============================================================================================

contract VoterRegistryTest is Base {
    uint256 internal id;
    Election internal e;

    function setUp() public override {
        super.setUp();
        (id, e) = _create(4, 3, true);
    }

    function test_publishOnlyInRegistrationByRegistrar() public {
        uint256[] memory leaves = Fixtures.leavesRange(0, 4);
        vm.prank(registrar);
        vm.expectRevert(VoterRegistry.WrongPhase.selector);
        registry.publishRoot(id, 1, leaves, 4);
        vm.warp(T0 + 30 minutes);
        e.advance();
        vm.expectRevert(VoterRegistry.NotRegistrar.selector);
        registry.publishRoot(id, 1, leaves, 4);
        vm.prank(registrar);
        vm.expectRevert(VoterRegistry.UnknownElection.selector);
        registry.publishRoot(id + 1, 1, leaves, 4);
        _publishRoll(id);
        (uint256 root, uint32 count) = registry.currentRoot(id);
        assertEq(root, Fixtures.root());
        assertEq(count, 8);
        assertEq(registry.rootCount(id), 2);
        assertEq(registry.rootAt(id, 0).root, Fixtures.rootAfter(4));
        assertTrue(registry.isKnownRoot(id, Fixtures.rootAfter(4)));
        assertFalse(registry.isKnownRoot(id, 123));
        assertEq(registry.registrarOf(id), registrar);
        assertEq(registry.electionOf(id), address(e));
    }

    function test_leafStreamMustBeGapFree() public {
        vm.warp(T0 + 30 minutes);
        e.advance();
        uint256[] memory leaves = Fixtures.leavesRange(0, 4);
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(VoterRegistry.LeafCountMismatch.selector, uint32(4), uint32(5)));
        registry.publishRoot(id, 1, leaves, 5);
        vm.prank(registrar);
        vm.expectRevert(VoterRegistry.ZeroRoot.selector);
        registry.publishRoot(id, 0, leaves, 4);
        leaves[2] = BabyJubJub.P;
        vm.prank(registrar);
        vm.expectRevert(VoterRegistry.LeafOutOfField.selector);
        registry.publishRoot(id, 1, leaves, 4);
        uint256[] memory huge = new uint256[](2049);
        vm.prank(registrar);
        vm.expectRevert(VoterRegistry.TooManyLeaves.selector);
        registry.publishRoot(id, 1, huge, 2049);
    }

    function test_publishBlockedWhilePaused() public {
        vm.warp(T0 + 30 minutes);
        e.advance();
        vm.prank(pauser);
        e.pause();
        vm.prank(registrar);
        vm.expectRevert(VoterRegistry.ElectionPaused.selector);
        registry.publishRoot(id, 1, Fixtures.leavesRange(0, 4), 4);
    }

    function test_rollFrozenOnceVotingStarts() public {
        _toVoting(id, e);
        vm.prank(registrar);
        vm.expectRevert(VoterRegistry.WrongPhase.selector);
        registry.publishRoot(id, 5, new uint256[](0), 8);
    }

    function test_registrarRotationOnlyByAdminInSetup() public {
        address newRegistrar = makeAddr("newRegistrar");
        vm.expectRevert(VoterRegistry.NotElectionAdmin.selector);
        registry.setRegistrar(id, newRegistrar);
        vm.prank(admin);
        registry.setRegistrar(id, newRegistrar);
        assertEq(registry.registrarOf(id), newRegistrar);
        vm.prank(admin);
        vm.expectRevert(VoterRegistry.UnknownElection.selector);
        registry.setRegistrar(id + 1, newRegistrar);
        vm.warp(T0 + 30 minutes);
        e.advance();
        vm.prank(admin);
        vm.expectRevert(VoterRegistry.WrongPhase.selector);
        registry.setRegistrar(id, registrar);
    }

    function test_initOnlyByFactoryOnce() public {
        vm.expectRevert(VoterRegistry.NotFactory.selector);
        registry.initElection(1, address(1), address(2));
        vm.prank(address(factory));
        vm.expectRevert(VoterRegistry.AlreadyRegistered.selector);
        registry.initElection(id, address(1), address(2));
    }

    function test_emptyRollViews() public view {
        (uint256 root, uint32 count) = registry.currentRoot(12345);
        assertEq(root, 0);
        assertEq(count, 0);
    }
}

// ============================================================================================
// TrusteeCoordinator (DKG)
// ============================================================================================

contract TrusteeCoordinatorTest is Base {
    uint256 internal id;
    Election internal e;

    function setUp() public override {
        super.setUp();
        (id, e) = _create(4, 3, true);
    }

    function _registerAll() internal {
        for (uint8 j = 1; j <= Fixtures.N; j++) {
            vm.prank(trustees[j - 1]);
            coordinator.registerKey(id, Fixtures.encryptionKey(j));
        }
    }

    function _dealAll() internal {
        vm.warp(_schedule()[0] + 1);
        for (uint8 i = 1; i <= Fixtures.N; i++) {
            vm.prank(trustees[i - 1]);
            coordinator.deal(id, Fixtures.pedersen(i), Fixtures.shareBlobs(i));
        }
    }

    function test_happyPathAndViews() public {
        _runDkg(id);
        assertTrue(coordinator.isFinalized(id));
        BabyJubJub.Point memory pk = coordinator.publicKey(id);
        assertEq(pk.x, Fixtures.publicKey().x);
        assertEq(pk.y, Fixtures.publicKey().y);
        // verification keys equal share·G for every trustee
        for (uint8 j = 1; j <= Fixtures.N; j++) {
            BabyJubJub.Point memory vk = coordinator.verificationKey(id, j);
            BabyJubJub.Point memory expected = BabyJubJub.mul(BabyJubJub.generator(), Fixtures.share(j));
            assertTrue(BabyJubJub.eq(vk, expected), "S_j = s_j G");
        }
        assertEq(coordinator.trusteeCount(id), 5);
        assertEq(coordinator.activeTrusteeCount(id), 5);
        assertEq(coordinator.threshold(id), 3);
        assertEq(coordinator.trustees(id).length, 5);
        assertEq(coordinator.trusteeIndex(id, trustees[2]), 3);
        assertEq(coordinator.schedule(id)[5], _schedule()[5]);
        assertEq(coordinator.encryptionKey(id, 1).x, Fixtures.encryptionKey(1).x);
        assertEq(coordinator.pedersenCommitments(id, 1).length, 3);
        assertEq(coordinator.feldmanCommitments(id, 1).length, 3);
        assertEq(coordinator.combinedCommitments(id).length, 3);
        (bool dealt, bool revealed, bool dq, uint8 pending, bool qual) = coordinator.dealerState(id, 1);
        assertTrue(dealt && revealed && !dq && pending == 0 && qual);
        (bool failed,) = coordinator.isFailed(id);
        assertFalse(failed);
        vm.expectRevert(TrusteeCoordinator.AlreadyFinalized.selector);
        coordinator.finalize(id);
        vm.expectRevert(TrusteeCoordinator.NotTrustee.selector);
        coordinator.verificationKey(id, 6);
    }

    function test_viewsBeforeFinalize() public {
        vm.expectRevert(TrusteeCoordinator.NotFinalized.selector);
        coordinator.publicKey(id);
        vm.expectRevert(TrusteeCoordinator.NotFinalized.selector);
        coordinator.verificationKey(id, 1);
    }

    function test_registerKeyRules() public {
        vm.expectRevert(TrusteeCoordinator.NotTrustee.selector);
        coordinator.registerKey(id, Fixtures.encryptionKey(1));
        vm.prank(trustees[0]);
        vm.expectRevert(BabyJubJub.NotInSubgroup.selector);
        coordinator.registerKey(id, BabyJubJub.Point(0, BabyJubJub.P - 1));
        vm.prank(trustees[0]);
        vm.expectRevert(BabyJubJub.NotInSubgroup.selector);
        coordinator.registerKey(id, BabyJubJub.identity());
        vm.prank(trustees[0]);
        coordinator.registerKey(id, Fixtures.encryptionKey(1));
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.AlreadyDone.selector);
        coordinator.registerKey(id, Fixtures.encryptionKey(1));
        vm.warp(_schedule()[0] + 1);
        vm.prank(trustees[1]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowClosed.selector, uint8(0)));
        coordinator.registerKey(id, Fixtures.encryptionKey(2));
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.UnknownElection.selector);
        coordinator.registerKey(id + 1, Fixtures.encryptionKey(1));
    }

    function test_dealRules() public {
        _registerAll();
        vm.prank(trustees[0]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowNotOpen.selector, uint8(1)));
        coordinator.deal(id, Fixtures.pedersen(1), Fixtures.shareBlobs(1));
        vm.warp(_schedule()[0] + 1);
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.WrongCommitmentCount.selector);
        coordinator.deal(id, new BabyJubJub.Point[](2), Fixtures.shareBlobs(1));
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.WrongShareCount.selector);
        coordinator.deal(id, Fixtures.pedersen(1), new bytes[](4));
        bytes[] memory blobs = Fixtures.shareBlobs(1);
        blobs[2] = hex"00";
        vm.prank(trustees[0]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.ShareLengthMismatch.selector, uint8(3)));
        coordinator.deal(id, Fixtures.pedersen(1), blobs);
        BabyJubJub.Point[] memory bad = Fixtures.pedersen(1);
        bad[1] = BabyJubJub.Point(0, BabyJubJub.P - 1);
        vm.prank(trustees[0]);
        vm.expectRevert(BabyJubJub.NotInSubgroup.selector);
        coordinator.deal(id, bad, Fixtures.shareBlobs(1));
        vm.prank(trustees[0]);
        coordinator.deal(id, Fixtures.pedersen(1), Fixtures.shareBlobs(1));
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.AlreadyDone.selector);
        coordinator.deal(id, Fixtures.pedersen(1), Fixtures.shareBlobs(1));
        vm.warp(_schedule()[1] + 1);
        vm.prank(trustees[1]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowClosed.selector, uint8(1)));
        coordinator.deal(id, Fixtures.pedersen(2), Fixtures.shareBlobs(2));
    }

    function test_inactiveTrusteeAndTooFewActive() public {
        // only two trustees register keys: below threshold 3
        vm.prank(trustees[0]);
        coordinator.registerKey(id, Fixtures.encryptionKey(1));
        vm.prank(trustees[1]);
        coordinator.registerKey(id, Fixtures.encryptionKey(2));
        vm.warp(_schedule()[0] + 1);
        vm.prank(trustees[2]);
        vm.expectRevert(TrusteeCoordinator.NotActiveTrustee.selector);
        coordinator.deal(id, Fixtures.pedersen(3), Fixtures.shareBlobs(3));
        vm.prank(trustees[0]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.NotEnoughActiveTrustees.selector, uint8(2), uint8(3)));
        coordinator.deal(id, Fixtures.pedersen(1), Fixtures.shareBlobs(1));
    }

    function test_complaintJustifiedKeepsDealerQualified() public {
        _registerAll();
        _dealAll();
        vm.warp(_schedule()[1] + 1);
        vm.prank(trustees[1]);
        coordinator.complain(id, 1);
        (,,, uint8 pending, bool qual) = coordinator.dealerState(id, 1);
        assertEq(pending, 1);
        assertFalse(qual);
        assertEq(uint8(coordinator.complaintState(id, 1, 2)), uint8(TrusteeCoordinator.ComplaintState.Open));
        (uint256 s, uint256 sp) = Fixtures.sharePair(1, 2);
        vm.prank(trustees[0]);
        coordinator.justify(id, 2, s, sp);
        (,,, pending, qual) = coordinator.dealerState(id, 1);
        assertEq(pending, 0);
        assertTrue(qual);
        assertEq(uint8(coordinator.complaintState(id, 1, 2)), uint8(TrusteeCoordinator.ComplaintState.Justified));
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.NoOpenComplaint.selector);
        coordinator.justify(id, 2, s, sp);
    }

    function test_badJustificationDisqualifiesDealerButDkgSucceeds() public {
        _registerAll();
        _dealAll();
        vm.warp(_schedule()[1] + 1);
        vm.prank(trustees[1]);
        coordinator.complain(id, 1);
        (uint256 s, uint256 sp) = Fixtures.sharePair(1, 2);
        vm.prank(trustees[0]);
        coordinator.justify(id, 2, s + 1, sp);
        (,, bool dq,, bool qual) = coordinator.dealerState(id, 1);
        assertTrue(dq);
        assertFalse(qual);
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.NotQualified.selector);
        coordinator.justify(id, 2, s, sp);
        // remaining 4 dealers reveal; dealer 1 cannot
        vm.warp(_schedule()[3] + 1);
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.NotQualified.selector);
        coordinator.reveal(id, Fixtures.feldman(1));
        for (uint8 i = 2; i <= Fixtures.N; i++) {
            vm.prank(trustees[i - 1]);
            coordinator.reveal(id, Fixtures.feldman(i));
        }
        vm.warp(_schedule()[5] + 1);
        coordinator.finalize(id);
        assertTrue(coordinator.isFinalized(id));
        // key is the sum over QUAL = {2..5}: differs from the 5-dealer fixture key
        BabyJubJub.Point memory pk = coordinator.publicKey(id);
        assertFalse(BabyJubJub.eq(pk, Fixtures.publicKey()));
    }

    function test_unansweredComplaintExcludesDealer() public {
        _registerAll();
        _dealAll();
        vm.warp(_schedule()[1] + 1);
        vm.prank(trustees[1]);
        coordinator.complain(id, 3);
        vm.prank(trustees[1]);
        vm.expectRevert(TrusteeCoordinator.ComplaintExists.selector);
        coordinator.complain(id, 3);
        vm.prank(trustees[1]);
        vm.expectRevert(TrusteeCoordinator.SelfComplaint.selector);
        coordinator.complain(id, 2);
        vm.warp(_schedule()[3] + 1);
        (uint256 s, uint256 sp) = Fixtures.sharePair(3, 2);
        vm.prank(trustees[2]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowClosed.selector, uint8(3)));
        coordinator.justify(id, 2, s, sp);
        for (uint8 i = 1; i <= Fixtures.N; i++) {
            if (i == 3) continue;
            vm.prank(trustees[i - 1]);
            coordinator.reveal(id, Fixtures.feldman(i));
        }
        vm.warp(_schedule()[5] + 1);
        coordinator.finalize(id);
        assertTrue(coordinator.isFinalized(id));
    }

    function test_complainRules() public {
        _registerAll();
        vm.warp(_schedule()[0] + 1);
        vm.prank(trustees[1]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowNotOpen.selector, uint8(2)));
        coordinator.complain(id, 1);
        vm.warp(_schedule()[1] + 1);
        vm.prank(trustees[1]);
        vm.expectRevert(TrusteeCoordinator.NotDealt.selector);
        coordinator.complain(id, 1);
        vm.warp(_schedule()[2] + 1);
        vm.prank(trustees[1]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowClosed.selector, uint8(2)));
        coordinator.complain(id, 1);
    }

    function test_justifyRules() public {
        _registerAll();
        vm.warp(_schedule()[0] + 1);
        vm.prank(trustees[0]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowNotOpen.selector, uint8(3)));
        coordinator.justify(id, 2, 1, 1);
        _dealAll();
        vm.warp(_schedule()[1] + 1);
        vm.prank(trustees[1]);
        coordinator.complain(id, 1);
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.ScalarOutOfRange.selector);
        coordinator.justify(id, 2, BabyJubJub.L, 1);
    }

    function test_maliciousRevealIsExposedAndDkgFails() public {
        _registerAll();
        _dealAll();
        vm.warp(_schedule()[3] + 1);
        // dealer 1 reveals dealer 2's Feldman commitments (inconsistent with its own Pedersen deal)
        vm.prank(trustees[0]);
        coordinator.reveal(id, Fixtures.feldman(2));
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.AlreadyDone.selector);
        coordinator.reveal(id, Fixtures.feldman(1));
        for (uint8 i = 2; i <= Fixtures.N; i++) {
            vm.prank(trustees[i - 1]);
            coordinator.reveal(id, Fixtures.feldman(i));
        }
        (uint256 s, uint256 sp) = Fixtures.sharePair(1, 4);
        // a fake share is rejected (cannot frame an honest dealer)
        vm.prank(trustees[3]);
        vm.expectRevert(TrusteeCoordinator.ShareNotGenuine.selector);
        coordinator.exposeReveal(id, 1, s + 1, sp);
        // exposing an honest dealer fails
        (uint256 s2, uint256 sp2) = Fixtures.sharePair(2, 4);
        vm.prank(trustees[3]);
        vm.expectRevert(TrusteeCoordinator.FeldmanConsistent.selector);
        coordinator.exposeReveal(id, 2, s2, sp2);
        vm.prank(trustees[3]);
        vm.expectRevert(TrusteeCoordinator.ScalarOutOfRange.selector);
        coordinator.exposeReveal(id, 1, BabyJubJub.L, sp);
        vm.prank(trustees[3]);
        coordinator.exposeReveal(id, 1, s, sp);
        (bool failed, uint8 who) = coordinator.isFailed(id);
        assertTrue(failed);
        assertEq(who, 1);
        vm.prank(trustees[2]);
        vm.expectRevert(TrusteeCoordinator.Failed.selector);
        coordinator.exposeReveal(id, 1, s, sp);
        vm.warp(_schedule()[5] + 1);
        vm.expectRevert(TrusteeCoordinator.Failed.selector);
        coordinator.finalize(id);
        // election can be aborted by anyone once voting should have started
        vm.warp(T0 + 30 minutes); // (time only moves forward in practice; re-warp for the phase step)
    }

    function test_exposeRevealRules() public {
        _registerAll();
        _dealAll();
        vm.prank(trustees[3]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowNotOpen.selector, uint8(5)));
        coordinator.exposeReveal(id, 1, 1, 1);
        vm.warp(_schedule()[3] + 1);
        vm.prank(trustees[3]);
        vm.expectRevert(TrusteeCoordinator.NotRevealed.selector);
        coordinator.exposeReveal(id, 1, 1, 1);
        vm.warp(_schedule()[5] + 1);
        vm.prank(trustees[3]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowClosed.selector, uint8(5)));
        coordinator.exposeReveal(id, 1, 1, 1);
    }

    function test_revealRules() public {
        _registerAll();
        _dealAll();
        vm.prank(trustees[0]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowNotOpen.selector, uint8(4)));
        coordinator.reveal(id, Fixtures.feldman(1));
        vm.warp(_schedule()[3] + 1);
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.WrongCommitmentCount.selector);
        coordinator.reveal(id, new BabyJubJub.Point[](1));
        BabyJubJub.Point[] memory bad = Fixtures.feldman(1);
        bad[0] = BabyJubJub.Point(0, BabyJubJub.P - 1);
        vm.prank(trustees[0]);
        vm.expectRevert(BabyJubJub.NotInSubgroup.selector);
        coordinator.reveal(id, bad);
        vm.warp(_schedule()[4] + 1);
        vm.prank(trustees[0]);
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowClosed.selector, uint8(4)));
        coordinator.reveal(id, Fixtures.feldman(1));
    }

    function test_missingRevealFailsDkg() public {
        _registerAll();
        _dealAll();
        vm.warp(_schedule()[3] + 1);
        for (uint8 i = 2; i <= Fixtures.N; i++) {
            vm.prank(trustees[i - 1]);
            coordinator.reveal(id, Fixtures.feldman(i));
        }
        vm.expectRevert(abi.encodeWithSelector(TrusteeCoordinator.WindowNotOpen.selector, uint8(6)));
        coordinator.finalize(id);
        vm.warp(_schedule()[5] + 1);
        coordinator.finalize(id);
        (bool failed, uint8 who) = coordinator.isFailed(id);
        assertTrue(failed);
        assertEq(who, 1);
        assertFalse(coordinator.isFinalized(id));
    }

    function test_tooFewQualifiedFailsDkg() public {
        _registerAll();
        vm.warp(_schedule()[0] + 1);
        for (uint8 i = 1; i <= 2; i++) {
            vm.prank(trustees[i - 1]);
            coordinator.deal(id, Fixtures.pedersen(i), Fixtures.shareBlobs(i));
        }
        vm.warp(_schedule()[3] + 1);
        for (uint8 i = 1; i <= 2; i++) {
            vm.prank(trustees[i - 1]);
            coordinator.reveal(id, Fixtures.feldman(i));
        }
        vm.warp(_schedule()[5] + 1);
        coordinator.finalize(id);
        (bool failed, uint8 who) = coordinator.isFailed(id);
        assertTrue(failed);
        assertEq(who, 0);
    }

    function test_dkgBlockedWhilePaused() public {
        vm.prank(pauser);
        e.pause();
        vm.prank(trustees[0]);
        vm.expectRevert(TrusteeCoordinator.ElectionPaused.selector);
        coordinator.registerKey(id, Fixtures.encryptionKey(1));
        vm.expectRevert(TrusteeCoordinator.UnknownElection.selector);
        coordinator.finalize(id + 1);
    }

    function test_initValidation() public {
        uint64[6] memory s = _schedule();
        vm.startPrank(address(factory));
        vm.expectRevert(TrusteeCoordinator.AlreadyRegistered.selector);
        coordinator.initElection(id, address(e), trustees, 3, s);
        vm.expectRevert(TrusteeCoordinator.InvalidThreshold.selector);
        coordinator.initElection(7, address(e), trustees, 1, s);
        vm.expectRevert(TrusteeCoordinator.InvalidThreshold.selector);
        coordinator.initElection(7, address(e), trustees, 6, s);
        address[] memory many = new address[](33);
        vm.expectRevert(TrusteeCoordinator.TooManyTrustees.selector);
        coordinator.initElection(7, address(e), many, 3, s);
        address[] memory dup = new address[](3);
        dup[0] = trustees[0];
        dup[1] = trustees[0];
        dup[2] = trustees[1];
        vm.expectRevert(TrusteeCoordinator.DuplicateTrustee.selector);
        coordinator.initElection(7, address(e), dup, 2, s);
        uint64[6] memory bad = s;
        bad[3] = bad[2];
        vm.expectRevert(TrusteeCoordinator.InvalidSchedule.selector);
        coordinator.initElection(7, address(e), trustees, 3, bad);
        bad = s;
        bad[0] = uint64(block.timestamp);
        vm.expectRevert(TrusteeCoordinator.InvalidSchedule.selector);
        coordinator.initElection(7, address(e), trustees, 3, bad);
        vm.stopPrank();
        vm.expectRevert(TrusteeCoordinator.NotFactory.selector);
        coordinator.initElection(7, address(e), trustees, 3, s);
    }
}

// ============================================================================================
// Tally
// ============================================================================================

contract TallyTest is Base {
    uint256 internal id;
    Election internal e;
    Fixtures.BallotProof[] internal finals;

    function setUp() public override {
        super.setUp();
        (id, e) = _create(4, 3, true);
        _toVoting(id, e);
        Fixtures.BallotProof[] memory all = Fixtures.ballotsK4();
        for (uint256 i = 0; i < all.length; i++) _cast(e, all[i]);
        Fixtures.BallotProof[] memory f = Fixtures.select(all, Fixtures.finalsK4());
        Fixtures.sortByNullifier(f);
        for (uint256 i = 0; i < f.length; i++) finals.push(f[i]);
    }

    function _batch(uint256 from, uint256 to) internal view returns (ITally.Ballot[] memory b) {
        b = new ITally.Ballot[](to - from);
        for (uint256 i = from; i < to; i++) b[i - from] = Fixtures.toTallyBallot(finals[i]);
    }

    function test_requiresTallyingPhase() public {
        vm.expectRevert(Tally.WrongPhase.selector);
        tally.aggregate(id, _batch(0, 8));
        vm.expectRevert(Tally.UnknownElection.selector);
        tally.aggregate(id + 1, _batch(0, 8));
    }

    function test_batchedAggregationMatchesSingleBatch() public {
        _toTallying(e);
        tally.aggregate(id, _batch(0, 3));
        tally.aggregate(id, _batch(3, 8));
        (,,,,, uint32 aggregated, uint256 last) = tally.status(id);
        assertEq(aggregated, 8);
        assertEq(last, Fixtures.nullifier(finals[7]));
        tally.normalize(id);
        _decryptAndFinalize(id, Fixtures.countsK4());
        assertEq(uint8(e.phase()), uint8(IElection.Phase.Finalized));
        uint32[] memory c = tally.counts(id);
        assertEq(c[2], Fixtures.countsK4()[2]);
        assertTrue(tally.slotFinalized(id, 0));
    }

    function test_cannotOmitBallots() public {
        _toTallying(e);
        tally.aggregate(id, _batch(0, 7));
        vm.expectRevert(abi.encodeWithSelector(Tally.NotAllAggregated.selector, uint32(7), uint32(8)));
        tally.normalize(id);
    }

    function test_cannotDuplicateOrReorder() public {
        _toTallying(e);
        ITally.Ballot[] memory b = _batch(0, 2);
        b[1] = b[0];
        vm.expectRevert(Tally.NullifierOrder.selector);
        tally.aggregate(id, b);
        tally.aggregate(id, _batch(0, 2));
        vm.expectRevert(Tally.NullifierOrder.selector);
        tally.aggregate(id, _batch(1, 3));
    }

    function test_cannotUseSupersededBallot() public {
        _toTallying(e);
        // voter 0's first ballot was replaced by a re-vote
        Fixtures.BallotProof memory old = Fixtures.ballotsK4()[0];
        ITally.Ballot[] memory b = new ITally.Ballot[](1);
        b[0] = Fixtures.toTallyBallot(old);
        vm.expectRevert(abi.encodeWithSelector(Tally.BallotHashMismatch.selector, Fixtures.nullifier(old)));
        tally.aggregate(id, b);
    }

    function test_rejectsUnknownAndMalformedBallots() public {
        _toTallying(e);
        ITally.Ballot[] memory b = _batch(0, 1);
        b[0].nullifier = 1;
        vm.expectRevert(abi.encodeWithSelector(Tally.UnknownBallot.selector, uint256(1)));
        tally.aggregate(id, b);
        b = _batch(0, 1);
        b[0].ciphertext = new uint256[](15);
        vm.expectRevert(Tally.WrongCiphertextLength.selector);
        tally.aggregate(id, b);
        vm.expectRevert(Tally.EmptyBatch.selector);
        tally.aggregate(id, new ITally.Ballot[](0));
        vm.expectRevert(Tally.EmptyBatch.selector);
        tally.aggregate(id, new ITally.Ballot[](257));
    }

    function test_decryptionRules() public {
        _toTallying(e);
        (BabyJubJub.Point[] memory none, ChaumPedersen.Proof[] memory noProofs) =
            (new BabyJubJub.Point[](3), new ChaumPedersen.Proof[](3));
        vm.prank(trustees[0]);
        vm.expectRevert(Tally.NotNormalized.selector);
        tally.submitPartialDecryption(id, none, noProofs);
        uint8[] memory subset = new uint8[](3);
        vm.expectRevert(Tally.NotNormalized.selector);
        tally.finalizeSlot(id, 0, 1, subset);

        tally.aggregate(id, _batch(0, 8));
        tally.normalize(id);
        vm.expectRevert(Tally.AlreadyNormalized.selector);
        tally.normalize(id);
        vm.expectRevert(Tally.AlreadyNormalized.selector);
        tally.aggregate(id, _batch(0, 1));

        (BabyJubJub.Point[] memory ds, ChaumPedersen.Proof[] memory proofs) = _partials(id, 1, 7);
        vm.prank(stranger);
        vm.expectRevert(Tally.NotTrustee.selector);
        tally.submitPartialDecryption(id, ds, proofs);
        // trustee 2 cannot submit trustee 1's partials (its verification key differs)
        vm.prank(trustees[1]);
        vm.expectRevert(abi.encodeWithSelector(Tally.InvalidPartialDecryption.selector, uint8(0)));
        tally.submitPartialDecryption(id, ds, proofs);
        // tampered partial for slot 2
        BabyJubJub.Point memory saved = ds[2];
        ds[2] = BabyJubJub.add(ds[2], BabyJubJub.generator());
        vm.prank(trustees[0]);
        vm.expectRevert(abi.encodeWithSelector(Tally.InvalidPartialDecryption.selector, uint8(2)));
        tally.submitPartialDecryption(id, ds, proofs);
        ds[2] = saved;
        vm.prank(trustees[0]);
        vm.expectRevert(Tally.WrongPartialCount.selector);
        tally.submitPartialDecryption(id, new BabyJubJub.Point[](2), proofs);
        vm.prank(trustees[0]);
        tally.submitPartialDecryption(id, ds, proofs);
        assertEq(tally.partialDecryptions(id, 1).length, 3);
        vm.prank(trustees[0]);
        vm.expectRevert(Tally.AlreadySubmitted.selector);
        tally.submitPartialDecryption(id, ds, proofs);

        _submitPartial(id, 2);
        subset[0] = 1;
        subset[1] = 2;
        subset[2] = 3;
        vm.expectRevert(abi.encodeWithSelector(Tally.TrusteeNotSubmitted.selector, uint8(3)));
        tally.finalizeSlot(id, 0, 1, subset);
        _submitPartial(id, 3);
        _submitPartial(id, 5);
        uint8[] memory two = new uint8[](2);
        vm.expectRevert(abi.encodeWithSelector(Tally.WrongSubsetSize.selector, uint8(3), uint256(2)));
        tally.finalizeSlot(id, 0, 1, two);
        vm.expectRevert(Tally.SlotOutOfRange.selector);
        tally.finalizeSlot(id, 3, 1, subset);
        uint32[] memory expected = Fixtures.countsK4();
        vm.expectRevert(Tally.WrongCount.selector);
        tally.finalizeSlot(id, 0, expected[0] + 1, subset);
        // any threshold subset works: {1, 3, 5}
        uint8[] memory alt = new uint8[](3);
        alt[0] = 1;
        alt[1] = 3;
        alt[2] = 5;
        tally.finalizeSlot(id, 0, expected[0], alt);
        vm.expectRevert(Tally.SlotAlreadyFinalized.selector);
        tally.finalizeSlot(id, 0, expected[0], subset);
        tally.finalizeSlot(id, 1, expected[1], subset);
        tally.finalizeSlot(id, 2, expected[2], alt);
        (, bool normalized, bool finalized, uint8 partialCount, uint8 finalizedSlots,,) = tally.status(id);
        assertTrue(normalized && finalized);
        assertEq(partialCount, 4);
        assertEq(finalizedSlots, 3);
        (BabyJubJub.Point[] memory c1, BabyJubJub.Point[] memory c2) = tally.encryptedTally(id);
        assertEq(c1.length, 3);
        assertEq(c2.length, 3);
    }

    function test_duplicateTrusteeInSubsetRejected() public {
        _toTallying(e);
        tally.aggregate(id, _batch(0, 8));
        tally.normalize(id);
        _submitPartial(id, 1);
        _submitPartial(id, 2);
        uint8[] memory dup = new uint8[](3);
        dup[0] = 1;
        dup[1] = 2;
        dup[2] = 1;
        vm.expectRevert();
        tally.finalizeSlot(id, 0, 1, dup);
    }

    function test_initOnlyByFactoryOnce() public {
        vm.expectRevert(Tally.NotFactory.selector);
        tally.initElection(1, address(1), 4);
        vm.prank(address(factory));
        vm.expectRevert(Tally.AlreadyRegistered.selector);
        tally.initElection(id, address(1), 4);
    }
}

// ============================================================================================
// Factory, roles and upgrades
// ============================================================================================

contract FactoryUpgradeTest is Base {
    function _timelockCall(address target, bytes memory data) internal {
        vm.prank(safe);
        timelock.schedule(target, 0, data, bytes32(0), bytes32(0), TIMELOCK_DELAY);
        vm.warp(block.timestamp + TIMELOCK_DELAY);
        vm.prank(safe);
        timelock.execute(target, 0, data, bytes32(0), bytes32(0));
    }

    function test_createElectionValidation() public {
        ElectionParams memory p = _params(4, 3, true);
        p.slots = 6;
        vm.expectRevert(abi.encodeWithSelector(VeriVoteFactory.NoVerifierForSlots.selector, uint8(6)));
        factory.createElection(p);
        p = _params(4, 5, true);
        vm.expectRevert(VeriVoteFactory.InvalidCandidates.selector);
        factory.createElection(p);
        p = _params(4, 3, true);
        p.admin = address(0);
        vm.expectRevert(VeriVoteFactory.ZeroAddress.selector);
        factory.createElection(p);
        p = _params(4, 3, true);
        p.votingEnd = p.votingStart;
        vm.expectRevert(VeriVoteFactory.InvalidSchedule.selector);
        factory.createElection(p);
        p = _params(4, 3, true);
        p.votingStart = p.registrationStart + 1;
        vm.expectRevert(VeriVoteFactory.TooShort.selector);
        factory.createElection(p);
        p = _params(4, 3, true);
        p.votingEnd = p.votingStart + 1;
        vm.expectRevert(VeriVoteFactory.TooShort.selector);
        factory.createElection(p);
        p = _params(4, 3, true);
        p.tallyDeadline = p.votingEnd + 1;
        vm.expectRevert(VeriVoteFactory.TooShort.selector);
        factory.createElection(p);
        p = _params(4, 3, true);
        p.dkgSchedule[5] = p.votingStart + 1;
        vm.expectRevert(VeriVoteFactory.InvalidSchedule.selector);
        factory.createElection(p);
    }

    function test_adminFunctionsRequireTimelock() public {
        bytes memory err = abi.encodeWithSelector(
            IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), factory.DEFAULT_ADMIN_ROLE()
        );
        vm.expectRevert(err);
        factory.setVerifier(4, address(1), 23);
        vm.expectRevert(err);
        factory.setElectionImplementation(address(1));
        vm.expectRevert(err);
        factory.setModules(address(1), address(2), address(3));

        _timelockCall(address(factory), abi.encodeCall(VeriVoteFactory.setVerifier, (12, address(verifier4), 55)));
        assertEq(factory.verifierFor(12).numSignals, 55);
        _timelockCall(address(factory), abi.encodeCall(VeriVoteFactory.setElectionImplementation, (address(0xBEEF))));
        assertEq(factory.electionImplementation(), address(0xBEEF));
        vm.prank(address(timelock));
        vm.expectRevert(VeriVoteFactory.ElectionsActive.selector);
        factory.setModules(address(1), address(2), address(3));
        vm.prank(address(timelock));
        vm.expectRevert(VeriVoteFactory.ZeroAddress.selector);
        factory.setModules(address(0), address(2), address(3));
        vm.prank(address(timelock));
        vm.expectRevert(VeriVoteFactory.ZeroAddress.selector);
        factory.setVerifier(4, address(0), 23);
        vm.prank(address(timelock));
        vm.expectRevert(VeriVoteFactory.ZeroAddress.selector);
        factory.setElectionImplementation(address(0));
        assertTrue(factory.isUpgradeAuthority(address(timelock)));
        assertFalse(factory.isUpgradeAuthority(deployer));
        assertTrue(factory.isPauser(pauser));
    }

    function test_singletonUpgradesBlockedDuringActiveElection() public {
        (uint256 id, Election e) = _create(4, 3, true);
        vm.warp(T0 + 30 minutes);
        e.advance();
        assertEq(factory.activeElections(), 1);
        address newImpl = address(new Tally());
        vm.prank(address(timelock));
        vm.expectRevert(Tally.ElectionsActive.selector);
        tally.upgradeToAndCall(newImpl, "");
        address regImpl = address(new VoterRegistry());
        address coordImpl = address(new TrusteeCoordinator());
        address factoryImpl = address(new VeriVoteFactory());
        address electionImpl2 = address(new Election());
        vm.prank(address(timelock));
        vm.expectRevert(VoterRegistry.ElectionsActive.selector);
        registry.upgradeToAndCall(regImpl, "");
        vm.prank(address(timelock));
        vm.expectRevert(TrusteeCoordinator.ElectionsActive.selector);
        coordinator.upgradeToAndCall(coordImpl, "");
        vm.prank(address(timelock));
        vm.expectRevert(VeriVoteFactory.ElectionsActive.selector);
        factory.upgradeToAndCall(factoryImpl, "");
        // election proxy itself: only in Setup
        vm.prank(address(timelock));
        vm.expectRevert(Election.UpgradeOnlyInSetup.selector);
        e.upgradeToAndCall(electionImpl2, "");
        // close it and upgrades work again (through the timelock)
        vm.prank(admin);
        e.abort("done");
        assertEq(factory.activeElections(), 0);
        _timelockCall(address(tally), abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (newImpl, "")));
        _timelockCall(address(registry), abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (regImpl, "")));
        _timelockCall(address(coordinator), abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (coordImpl, "")));
        _timelockCall(address(factory), abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (factoryImpl, "")));
        id;
    }

    function test_upgradesRequireAuthority() public {
        (, Election e) = _create(4, 3, true);
        address eImpl = address(new Election());
        address tImpl = address(new Tally());
        address rImpl = address(new VoterRegistry());
        address cImpl = address(new TrusteeCoordinator());
        vm.expectRevert(Election.NotUpgradeAuthority.selector);
        e.upgradeToAndCall(eImpl, "");
        vm.expectRevert(Tally.NotUpgradeAuthority.selector);
        tally.upgradeToAndCall(tImpl, "");
        vm.expectRevert(VoterRegistry.NotUpgradeAuthority.selector);
        registry.upgradeToAndCall(rImpl, "");
        vm.expectRevert(TrusteeCoordinator.NotUpgradeAuthority.selector);
        coordinator.upgradeToAndCall(cImpl, "");
        // election in Setup can be upgraded by the timelock
        _timelockCall(address(e), abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (eImpl, "")));
    }

    function test_callbacksOnlyFromElections() public {
        vm.expectRevert(VeriVoteFactory.NotElection.selector);
        factory.onElectionActivated(1);
        vm.expectRevert(VeriVoteFactory.NotElection.selector);
        factory.onElectionClosed(1);
    }

    function test_initializersLocked() public {
        VeriVoteFactory impl = new VeriVoteFactory();
        vm.expectRevert();
        impl.initialize(address(1), address(2), address(3));
        vm.expectRevert();
        factory.initialize(address(1), address(2), address(3));
        vm.expectRevert();
        tally.initialize(address(1));
        vm.expectRevert();
        registry.initialize(address(1));
        vm.expectRevert();
        coordinator.initialize(address(1));
    }

    function test_initializeRejectsZeroAddresses() public {
        VeriVoteFactory impl = new VeriVoteFactory();
        ERC1967ProxyHelper helper = new ERC1967ProxyHelper();
        vm.expectRevert(VeriVoteFactory.ZeroAddress.selector);
        helper.deploy(address(impl), abi.encodeCall(VeriVoteFactory.initialize, (address(0), pauser, electionImpl)));
    }

    function test_electionIndexing() public {
        (uint256 id1, Election e1) = _create(4, 3, true);
        (uint256 id2,) = _create(8, 5, true);
        assertEq(factory.electionCount(), 2);
        assertEq(factory.electionIdAt(1), id1);
        assertEq(factory.electionIdAt(2), id2);
        assertEq(factory.electionAddress(id1), address(e1));
    }
}

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract ERC1967ProxyHelper {
    function deploy(address impl, bytes memory data) external returns (address) {
        return address(new ERC1967Proxy(impl, data));
    }
}

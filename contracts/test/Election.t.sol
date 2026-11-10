// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Base} from "./utils/Base.t.sol";
import {Fixtures} from "./fixtures/Fixtures.sol";
import {Election} from "../src/Election.sol";
import {Tally} from "../src/Tally.sol";
import {IElection} from "../src/interfaces/IVeriVote.sol";
import {BabyJubJub} from "../src/libraries/BabyJubJub.sol";

contract ElectionTest is Base {
    uint256 internal id;
    Election internal e;

    function setUp() public override {
        super.setUp();
        assertEq(address(factory), Fixtures.FACTORY, "deployment order changed: regenerate fixtures");
        (id, e) = _create(4, 3, true);
        assertEq(id, Fixtures.ELECTION_ID, "election id mismatch: regenerate fixtures");
    }

    // ------------------------------------------------------------------------------------------
    // Full happy path
    // ------------------------------------------------------------------------------------------

    function test_fullElectionWithRevotes() public {
        _toVoting(id, e);
        (uint256 pkx, uint256 pky) = e.snapshotKey();
        assertEq(pkx, Fixtures.publicKey().x, "PK equals the fixture DKG key");
        assertEq(pky, Fixtures.publicKey().y);
        assertEq(e.snapshotRoot(), Fixtures.root());

        Fixtures.BallotProof[] memory all = Fixtures.ballotsK4();
        for (uint256 i = 0; i < all.length; i++) {
            vm.prank(relayer);
            _cast(e, all[i]);
        }
        assertEq(e.ballotCount(), 8, "distinct nullifiers");
        (, uint32 c0) = e.ballotRecord(Fixtures.nullifier(all[0]));
        assertEq(c0, 2, "voter 0 voted twice");
        (, uint32 c3) = e.ballotRecord(Fixtures.nullifier(all[3]));
        assertEq(c3, 3, "voter 3 voted three times");

        _toTallying(e);
        _aggregateAll(id, Fixtures.select(all, Fixtures.finalsK4()));
        _decryptAndFinalize(id, Fixtures.countsK4());

        assertEq(uint8(e.phase()), uint8(IElection.Phase.Finalized));
        uint32[] memory res = e.results();
        uint32[] memory expected = Fixtures.countsK4();
        for (uint256 i = 0; i < res.length; i++) assertEq(res[i], expected[i]);
        assertEq(factory.activeElections(), 0);
    }

    function test_zeroBallotElectionFinalizes() public {
        _toVoting(id, e);
        _toTallying(e);
        tally.normalize(id);
        uint32[] memory zeros = new uint32[](3);
        _decryptAndFinalize(id, zeros);
        assertEq(uint8(e.phase()), uint8(IElection.Phase.Finalized));
    }

    // ------------------------------------------------------------------------------------------
    // castVote rejections
    // ------------------------------------------------------------------------------------------

    function test_doubleVoteSameIndexRejected() public {
        _toVoting(id, e);
        Fixtures.BallotProof[] memory all = Fixtures.ballotsK4();
        _cast(e, all[1]);
        vm.expectRevert(abi.encodeWithSelector(Election.WrongVoteIndex.selector, uint32(1), uint256(0)));
        _cast(e, all[1]);
    }

    /// @notice THREAT_MODEL V-9: a front-runner can only submit the identical ballot; replays of an old ballot
    ///         after a re-vote fail; altering any signal invalidates the proof.
    function test_frontRunCannotAlterOrReplay() public {
        _toVoting(id, e);
        Fixtures.BallotProof[] memory all = Fixtures.ballotsK4();
        Fixtures.BallotProof memory mine = all[0];

        // attacker swaps the ciphertext of slot 0 for their own: proof no longer verifies
        Fixtures.BallotProof memory forged = _copy(mine);
        (forged.signals[0], forged.signals[1]) = (all[1].signals[0], all[1].signals[1]);
        vm.prank(stranger);
        vm.expectRevert(Election.InvalidProof.selector);
        _cast(e, forged);

        // attacker submits the voter's exact ballot first: same outcome as the voter's own submission
        vm.prank(stranger);
        _cast(e, mine);
        (uint224 h,) = e.ballotRecord(Fixtures.nullifier(mine));
        assertEq(h, uint224(uint256(keccak256(abi.encodePacked(Fixtures.ciphertext(mine)))) >> 32));

        // voter re-votes; replaying the original ballot afterwards is rejected
        _cast(e, all[8]);
        vm.expectRevert(abi.encodeWithSelector(Election.WrongVoteIndex.selector, uint32(2), uint256(0)));
        _cast(e, mine);
        // replaying the re-vote itself is rejected too
        vm.expectRevert(abi.encodeWithSelector(Election.WrongVoteIndex.selector, uint32(2), uint256(1)));
        _cast(e, all[8]);
    }

    function test_tamperedVoteIndexRejected() public {
        _toVoting(id, e);
        Fixtures.BallotProof memory b = _copy(Fixtures.ballotsK4()[2]);
        _cast(e, b);
        b.signals[b.signals.length - 1] = 1; // claim it is the re-vote
        vm.expectRevert(Election.InvalidProof.selector);
        _cast(e, b);
    }

    function test_publicInputMismatchesRejected() public {
        _toVoting(id, e);
        Fixtures.BallotProof memory b = Fixtures.ballotsK4()[1];
        uint256 base = 16;

        Fixtures.BallotProof memory x = _copy(b);
        x.signals[base + 1] = Fixtures.rootAfter(4);
        vm.expectRevert(Election.WrongRoot.selector);
        _cast(e, x);

        x = _copy(b);
        x.signals[base + 2] = id + 1;
        vm.expectRevert(Election.WrongElectionId.selector);
        _cast(e, x);

        x = _copy(b);
        x.signals[base + 3] = 1;
        vm.expectRevert(Election.WrongPublicKey.selector);
        _cast(e, x);

        x = _copy(b);
        x.signals[base + 4] = 1;
        vm.expectRevert(Election.WrongPublicKey.selector);
        _cast(e, x);

        x = _copy(b);
        x.signals[base + 5] = 4;
        vm.expectRevert(Election.WrongCandidateCount.selector);
        _cast(e, x);

        uint256[] memory shortSignals = new uint256[](22);
        vm.expectRevert(abi.encodeWithSelector(Election.WrongSignalCount.selector, uint256(23), uint256(22)));
        e.castVote(b.a, b.b, b.c, shortSignals);

        x = _copy(b);
        x.a[0] = x.a[0] ^ 1;
        vm.expectRevert(Election.InvalidProof.selector);
        _cast(e, x);
    }

    function test_crossElectionReplayRejected() public {
        (uint256 id2, Election e2) = _create(4, 3, true);
        assertTrue(id2 != id);
        vm.warp(T0 + 30 minutes);
        e.advance();
        e2.advance();
        _publishRoll(id);
        vm.prank(registrar);
        registry.publishRoot(id2, Fixtures.root(), Fixtures.leaves(), uint32(Fixtures.VOTERS));
        _runDkg(id);
        vm.warp(_schedule()[0] - 1); // too late for election 2's DKG windows; give it its own run
        // election 2 never completes DKG -> cannot reach Voting; a ballot for election 1 is useless there
        vm.warp(T0 + 7 hours);
        vm.expectRevert(Election.DkgNotFinalized.selector);
        e2.advance();
        e.advance();
        Fixtures.BallotProof memory b = Fixtures.ballotsK4()[0];
        vm.expectRevert(abi.encodeWithSelector(Election.WrongPhase.selector, IElection.Phase.Voting, IElection.Phase.Registration));
        _cast(e2, b);
        _cast(e, b);
    }

    function test_castOutsideVotingRejected() public {
        Fixtures.BallotProof memory b = Fixtures.ballotsK4()[0];
        vm.expectRevert(abi.encodeWithSelector(Election.WrongPhase.selector, IElection.Phase.Voting, IElection.Phase.Setup));
        _cast(e, b);
        _toVoting(id, e);
        (,, uint64 votingEnd,) = e.schedule();
        vm.warp(votingEnd);
        vm.expectRevert(Election.VotingClosed.selector);
        _cast(e, b);
    }

    // ------------------------------------------------------------------------------------------
    // Phase machine
    // ------------------------------------------------------------------------------------------

    function test_phasesAreTimeLocked() public {
        vm.expectRevert(abi.encodeWithSelector(Election.TooEarly.selector, uint64(T0 + 30 minutes)));
        e.advance();
        vm.warp(T0 + 30 minutes);
        e.advance();
        assertEq(uint8(e.phase()), uint8(IElection.Phase.Registration));
        _publishRoll(id);
        _runDkg(id);
        vm.warp(T0 + 7 hours - 1);
        vm.expectRevert(abi.encodeWithSelector(Election.TooEarly.selector, uint64(T0 + 7 hours)));
        e.advance();
        vm.warp(T0 + 7 hours);
        e.advance();
        vm.expectRevert(abi.encodeWithSelector(Election.TooEarly.selector, uint64(T0 + 9 hours)));
        e.advance();
        vm.warp(T0 + 9 hours);
        e.advance();
        vm.expectRevert(abi.encodeWithSelector(Election.WrongPhase.selector, IElection.Phase.Voting, IElection.Phase.Tallying));
        e.advance();
    }

    function test_votingNeedsRollAndDkg() public {
        vm.warp(T0 + 30 minutes);
        e.advance();
        vm.warp(T0 + 7 hours);
        vm.expectRevert(Election.DkgNotFinalized.selector);
        e.advance();
    }

    function test_votingNeedsNonEmptyRoll() public {
        vm.warp(T0 + 30 minutes);
        e.advance();
        _runDkg(id);
        vm.warp(T0 + 7 hours);
        vm.expectRevert(Election.EmptyRoll.selector);
        e.advance();
    }

    function test_setupConfigurationOnlyByAdminInSetup() public {
        string[] memory c = new string[](2);
        c[0] = "A";
        c[1] = "B";
        vm.expectRevert(Election.NotAdmin.selector);
        e.setCandidates(c);
        vm.prank(admin);
        e.setCandidates(c);
        assertEq(e.numCandidates(), 2);
        vm.prank(admin);
        e.setSchedule(T0 + 31 minutes, T0 + 7 hours, T0 + 10 hours, T0 + 13 hours);
        vm.prank(admin);
        e.setMetadata("New", "ipfs://new");
        assertEq(e.title(), "New");

        string[] memory tooMany = new string[](5);
        for (uint256 i = 0; i < 5; i++) tooMany[i] = "x";
        vm.prank(admin);
        vm.expectRevert(Election.InvalidCandidates.selector);
        e.setCandidates(tooMany);
        string[] memory empty = new string[](2);
        empty[0] = "x";
        vm.prank(admin);
        vm.expectRevert(Election.InvalidCandidates.selector);
        e.setCandidates(empty);
        vm.prank(admin);
        vm.expectRevert(Election.InvalidSchedule.selector);
        e.setSchedule(T0 + 7 hours, T0 + 7 hours, T0 + 10 hours, T0 + 13 hours);

        vm.warp(T0 + 31 minutes);
        e.advance();
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Election.WrongPhase.selector, IElection.Phase.Setup, IElection.Phase.Registration));
        e.setCandidates(c);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Election.WrongPhase.selector, IElection.Phase.Setup, IElection.Phase.Registration));
        e.setSchedule(T0 + 31 minutes, T0 + 7 hours, T0 + 10 hours, T0 + 13 hours);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Election.WrongPhase.selector, IElection.Phase.Setup, IElection.Phase.Registration));
        e.setMetadata("x", "y");
    }

    function test_markFinalizedOnlyByTally() public {
        _toVoting(id, e);
        _toTallying(e);
        vm.expectRevert(Election.NotTally.selector);
        e.markFinalized(new uint32[](3));
        vm.prank(address(tally));
        vm.expectRevert(Election.WrongResultsLength.selector);
        e.markFinalized(new uint32[](2));
    }

    // ------------------------------------------------------------------------------------------
    // Abort
    // ------------------------------------------------------------------------------------------

    function test_adminAbortBeforeVoting() public {
        vm.expectRevert(Election.CannotAbort.selector);
        e.abort("not admin");
        vm.prank(admin);
        e.abort("cancelled");
        assertEq(uint8(e.phase()), uint8(IElection.Phase.Aborted));
        assertEq(factory.activeElections(), 0);
    }

    function test_adminAbortDuringRegistrationReleasesActiveCount() public {
        vm.warp(T0 + 30 minutes);
        e.advance();
        assertEq(factory.activeElections(), 1);
        vm.prank(admin);
        e.abort("cancelled");
        assertEq(factory.activeElections(), 0);
    }

    function test_anyoneAbortsWhenDkgMissedDeadline() public {
        vm.warp(T0 + 30 minutes);
        e.advance();
        vm.warp(T0 + 7 hours - 1);
        vm.prank(stranger);
        vm.expectRevert(Election.CannotAbort.selector);
        e.abort("too early");
        vm.warp(T0 + 7 hours);
        vm.prank(stranger);
        e.abort("dkg failed");
        assertEq(uint8(e.phase()), uint8(IElection.Phase.Aborted));
    }

    function test_votingCannotBeAborted() public {
        _toVoting(id, e);
        vm.prank(admin);
        vm.expectRevert(Election.CannotAbort.selector);
        e.abort("no");
    }

    function test_anyoneAbortsStalledTally() public {
        _toVoting(id, e);
        _toTallying(e);
        vm.expectRevert(Election.CannotAbort.selector);
        e.abort("early");
        vm.warp(T0 + 12 hours);
        e.abort("trustees unresponsive");
        assertEq(uint8(e.phase()), uint8(IElection.Phase.Aborted));
        vm.expectRevert(Tally.WrongPhase.selector);
        tally.normalize(id);
    }

    // ------------------------------------------------------------------------------------------
    // Pause (limited powers)
    // ------------------------------------------------------------------------------------------

    function test_pauseOnlyByPauser() public {
        vm.expectRevert(Election.NotPauser.selector);
        e.pause();
        vm.prank(pauser);
        e.pause();
        vm.prank(pauser);
        vm.expectRevert(Election.IsPaused.selector);
        e.pause();
        vm.expectRevert(Election.NotPauser.selector);
        e.unpause();
        vm.prank(pauser);
        e.unpause();
        vm.prank(pauser);
        vm.expectRevert(Election.NotPaused.selector);
        e.unpause();
    }

    function test_pauseBlocksCastingAndExtendsVotingWindow() public {
        _toVoting(id, e);
        Fixtures.BallotProof memory b = Fixtures.ballotsK4()[0];
        vm.warp(T0 + 8 hours);
        vm.prank(pauser);
        e.pause();
        vm.expectRevert(Election.IsPaused.selector);
        _cast(e, b);
        vm.warp(T0 + 8 hours + 90 minutes);
        vm.prank(pauser);
        e.unpause();
        (,, uint64 votingEnd, uint64 tallyDeadline) = e.schedule();
        assertEq(votingEnd, T0 + 9 hours + 90 minutes, "voting extended by paused time");
        assertEq(tallyDeadline, T0 + 12 hours + 90 minutes);
        vm.warp(T0 + 9 hours + 30 minutes); // after the original end, still open
        _cast(e, b);
        assertEq(e.ballotCount(), 1);
    }

    function test_pauseDuringRegistrationOnlyExtendsOverlapWithVoting() public {
        vm.warp(T0 + 30 minutes);
        e.advance();
        vm.prank(pauser);
        e.pause();
        vm.warp(T0 + 2 hours);
        vm.prank(pauser);
        e.unpause();
        (,, uint64 votingEnd,) = e.schedule();
        assertEq(votingEnd, T0 + 9 hours, "no extension: pause ended before voting started");
    }

    function test_pauseDuringTallyingExtendsDeadline() public {
        _toVoting(id, e);
        _toTallying(e);
        vm.prank(pauser);
        e.pause();
        vm.expectRevert(Tally.ElectionPaused.selector);
        tally.normalize(id);
        vm.warp(block.timestamp + 1 hours);
        vm.prank(pauser);
        e.unpause();
        (,,, uint64 tallyDeadline) = e.schedule();
        assertEq(tallyDeadline, T0 + 13 hours);
    }

    function test_cannotPauseFinishedElection() public {
        vm.prank(admin);
        e.abort("x");
        vm.prank(pauser);
        vm.expectRevert(abi.encodeWithSelector(Election.WrongPhase.selector, IElection.Phase.Voting, IElection.Phase.Aborted));
        e.pause();
    }

    function test_advanceBlockedWhilePaused() public {
        vm.prank(pauser);
        e.pause();
        vm.warp(T0 + 30 minutes);
        vm.expectRevert(Election.IsPaused.selector);
        e.advance();
    }

    // ------------------------------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------------------------------

    function test_views() public view {
        assertEq(e.electionId(), id);
        assertEq(e.admin(), admin);
        assertEq(e.slots(), 4);
        assertTrue(e.allowRevote());
        assertFalse(e.paused());
        assertEq(e.candidates().length, 3);
        assertEq(e.metadataURI(), "ipfs://metadata");
        assertEq(e.leafCount(), 0);
        assertEq(e.pausedAt(), 0);
        assertEq(e.numSignals(), 23);
        assertEq(e.verifier(), address(verifier4));
        assertEq(e.tally(), address(tally));
        assertEq(address(e.registry()), address(registry));
        assertEq(address(e.coordinator()), address(coordinator));
        assertEq(address(e.factory()), address(factory));
        assertEq(e.resultsHash(), bytes32(0));
    }

    function _copy(Fixtures.BallotProof memory b) internal pure returns (Fixtures.BallotProof memory c) {
        c.voter = b.voter;
        c.choice = b.choice;
        c.voteIndex = b.voteIndex;
        c.a = b.a;
        c.b = b.b;
        c.c = b.c;
        c.signals = new uint256[](b.signals.length);
        for (uint256 i = 0; i < b.signals.length; i++) c.signals[i] = b.signals[i];
    }
}

contract ElectionK8Test is Base {
    function test_k8Election() public {
        (uint256 id8, Election e8) = _create(8, 5, false);
        assertEq(id8, Fixtures.ELECTION_ID);
        _toVoting(id8, e8);
        Fixtures.BallotProof[] memory b = Fixtures.ballotsK8();
        _cast(e8, b[0]);
        _cast(e8, b[1]);
        _toTallying(e8);
        _aggregateAll(id8, b);
        uint32[] memory expected = new uint32[](5);
        expected[3] = 1;
        expected[4] = 1;
        _decryptAndFinalize(id8, expected);
        assertEq(uint8(e8.phase()), uint8(IElection.Phase.Finalized));
    }
}

contract ElectionNoRevoteTest is Base {
    function test_revoteDisabledRejected() public {
        (uint256 id2, Election e2) = _create(4, 3, false);
        assertFalse(e2.allowRevote());
        _toVoting(id2, e2);
        Fixtures.BallotProof[] memory all = Fixtures.ballotsK4();
        _cast(e2, all[0]);
        vm.expectRevert(Election.RevoteNotAllowed.selector);
        _cast(e2, all[8]);
    }
}

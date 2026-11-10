// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Base} from "./utils/Base.t.sol";
import {Fixtures} from "./fixtures/Fixtures.sol";
import {Election} from "../src/Election.sol";
import {IElection} from "../src/interfaces/IVeriVote.sol";

/// forge-config: default.fuzz.runs = 256
contract ElectionFuzzTest is Base {
    uint256 internal id;
    Election internal e;

    function setUp() public override {
        super.setUp();
        (id, e) = _create(4, 3, true);
        _toVoting(id, e);
    }

    /// Any change to any public signal or proof element is rejected, and nothing is recorded.
    function testFuzz_anyTamperingRejected(uint256 ballotSeed, uint256 position, uint256 delta) public {
        Fixtures.BallotProof[] memory all = Fixtures.ballotsK4();
        Fixtures.BallotProof memory b = all[bound(ballotSeed, 0, 7)]; // first votes only
        delta = bound(delta, 1, type(uint128).max);
        position = bound(position, 0, 23 + 7); // 23 signals + 8 proof words
        if (position < 23) {
            b.signals[position] = addmod(b.signals[position], delta, type(uint256).max);
        } else if (position < 25) {
            b.a[position - 23] ^= delta;
        } else if (position < 29) {
            uint256 q = position - 25;
            b.b[q / 2][q % 2] ^= delta;
        } else {
            b.c[position - 29] ^= delta;
        }
        uint256 n = Fixtures.nullifier(Fixtures.ballotsK4()[bound(ballotSeed, 0, 7)]);
        vm.expectRevert();
        e.castVote(b.a, b.b, b.c, b.signals);
        (, uint32 count) = e.ballotRecord(n);
        assertEq(count, 0);
        assertEq(e.ballotCount(), 0);
    }

    /// Pausing for any duration at any time during voting extends the end by exactly the overlap.
    function testFuzz_pauseExtendsVotingExactly(uint64 pauseAfter, uint64 duration) public {
        pauseAfter = uint64(bound(pauseAfter, 0, 2 hours - 1));
        duration = uint64(bound(duration, 0, 30 days));
        (,, uint64 endBefore, uint64 tallyBefore) = e.schedule();
        vm.warp(block.timestamp + pauseAfter);
        vm.prank(pauser);
        e.pause();
        vm.warp(block.timestamp + duration);
        vm.prank(pauser);
        e.unpause();
        (,, uint64 endAfter, uint64 tallyAfter) = e.schedule();
        assertEq(endAfter, endBefore + duration);
        assertEq(tallyAfter, tallyBefore + duration);
        assertEq(uint8(e.phase()), uint8(IElection.Phase.Voting));
        // remaining voting time is never shortened
        assertGe(endAfter - block.timestamp, endBefore - (T0 + 7 hours + pauseAfter));
    }

    /// Random time travel never lets advance() skip a phase or move backwards.
    function testFuzz_advanceIsMonotonic(uint32[4] memory jumps) public {
        uint8 last = uint8(e.phase());
        for (uint256 i = 0; i < jumps.length; i++) {
            vm.warp(block.timestamp + bound(jumps[i], 0, 6 hours));
            try e.advance() {} catch {}
            uint8 p = uint8(e.phase());
            assertGe(p, last);
            assertLe(p - last, 1);
            last = p;
        }
    }
}

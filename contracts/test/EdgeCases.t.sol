// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Base} from "./utils/Base.t.sol";
import {Fixtures} from "./fixtures/Fixtures.sol";
import {Election} from "../src/Election.sol";
import {Tally} from "../src/Tally.sol";
import {TrusteeCoordinator} from "../src/TrusteeCoordinator.sol";
import {VeriVoteFactory} from "../src/VeriVoteFactory.sol";
import {ElectionParams, ITally} from "../src/interfaces/IVeriVote.sol";
import {BabyJubJub} from "../src/libraries/BabyJubJub.sol";
import {ChaumPedersen} from "../src/libraries/ChaumPedersen.sol";
import {LibHarness} from "./Libraries.t.sol";

/// @dev A deliberately broken verifier that accepts every proof.
contract BrokenVerifier {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(true);
    }
}

/**
 * Defence in depth: even if the Groth16 verifier (or the circuit) were broken and accepted a ballot that
 * votes for two candidates, the tally refuses to finalize because Σ counts ≠ number of ballots.
 */
contract DefenseInDepthTest is Base {
    function test_overVoteCaughtByTallySumCheck() public {
        BrokenVerifier broken = new BrokenVerifier();
        vm.prank(address(timelock));
        factory.setVerifier(4, address(broken), 23);
        (uint256 id, Election e) = _create(4, 3, true);
        _toVoting(id, e);

        BabyJubJub.Point memory pk = Fixtures.publicKey();
        uint256[] memory signals = new uint256[](23);
        uint8[4] memory m = [1, 1, 0, 0]; // two-hot: illegal ballot
        for (uint256 i = 0; i < 4; i++) {
            uint256 r = uint256(keccak256(abi.encode("r", i))) % (BabyJubJub.L - 1) + 1;
            BabyJubJub.Point memory c1 = BabyJubJub.mul(BabyJubJub.generator(), r);
            BabyJubJub.Point memory c2 = BabyJubJub.add(BabyJubJub.mul(BabyJubJub.generator(), m[i]), BabyJubJub.mul(pk, r));
            signals[2 * i] = c1.x;
            signals[2 * i + 1] = c1.y;
            signals[8 + 2 * i] = c2.x;
            signals[8 + 2 * i + 1] = c2.y;
        }
        signals[16] = 12345; // nullifier
        signals[17] = Fixtures.root();
        signals[18] = id;
        signals[19] = pk.x;
        signals[20] = pk.y;
        signals[21] = 3;
        signals[22] = 0;
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        e.castVote(a, b, c, signals);

        _toTallying(e);
        ITally.Ballot[] memory batch = new ITally.Ballot[](1);
        uint256[] memory ct = new uint256[](16);
        for (uint256 i = 0; i < 16; i++) ct[i] = signals[i];
        batch[0] = ITally.Ballot(12345, ct);
        tally.aggregate(id, batch);
        tally.normalize(id);
        for (uint8 j = 1; j <= Fixtures.T; j++) _submitPartial(id, j);
        uint8[] memory subset = new uint8[](3);
        subset[0] = 1;
        subset[1] = 2;
        subset[2] = 3;
        tally.finalizeSlot(id, 0, 1, subset);
        tally.finalizeSlot(id, 1, 1, subset);
        vm.expectRevert(abi.encodeWithSelector(Tally.CountSumMismatch.selector, uint256(2), uint32(1)));
        tally.finalizeSlot(id, 2, 0, subset);
    }
}

contract BranchEdgeCasesTest is Base {
    function test_strangerCannotAbortWhenDkgSucceeded() public {
        (uint256 id, Election e) = _create(4, 3, true);
        vm.warp(T0 + 30 minutes);
        e.advance();
        _publishRoll(id);
        _runDkg(id);
        vm.warp(T0 + 7 hours);
        vm.prank(stranger);
        vm.expectRevert(Election.CannotAbort.selector);
        e.abort("dkg is fine");
    }

    function test_adminCannotAbortAfterFinalOrAbort() public {
        (, Election e) = _create(4, 3, true);
        vm.prank(admin);
        e.abort("first");
        vm.prank(admin);
        vm.expectRevert(Election.CannotAbort.selector);
        e.abort("second");
    }

    function test_dkgScheduleMustStartInFuture() public {
        ElectionParams memory p = _params(4, 3, true);
        p.dkgSchedule[0] = uint64(block.timestamp);
        vm.expectRevert(TrusteeCoordinator.InvalidSchedule.selector);
        factory.createElection(p);
    }

    function test_verifierSignalCountMustMatchSlots() public {
        vm.prank(address(timelock));
        factory.setVerifier(4, address(verifier4), 22);
        vm.expectRevert(abi.encodeWithSelector(VeriVoteFactory.NoVerifierForSlots.selector, uint8(4)));
        factory.createElection(_params(4, 3, true));
    }
}

contract LibraryEdgeCasesTest is Test {
    LibHarness internal h = new LibHarness();

    function test_projEqualsAffineRejectsZeroZ() public pure {
        assertFalse(BabyJubJub.projEqualsAffine(BabyJubJub.ProjectivePoint(0, 0, 0), BabyJubJub.Point(0, 0)));
    }

    function test_inSubgroupRejectsOffCurve() public pure {
        assertFalse(BabyJubJub.inSubgroup(BabyJubJub.Point(1, 2)));
    }

    function test_modInvRevertsWhenPrecompileFails() public {
        vm.mockCallRevert(address(0x05), bytes(""), bytes(""));
        vm.expectRevert(BabyJubJub.PrecompileFailed.selector);
        h.inverse(3);
    }

    function test_chaumPedersenRejectsOffCurveCommitments() public view {
        BabyJubJub.Point memory g = BabyJubJub.generator();
        ChaumPedersen.Proof memory p = ChaumPedersen.Proof(BabyJubJub.Point(1, 2), g, 1);
        assertFalse(h.cpVerify(g, g, g, p, 1, 0));
        p = ChaumPedersen.Proof(g, BabyJubJub.Point(1, 2), 1);
        assertFalse(h.cpVerify(g, g, g, p, 1, 0));
    }
}

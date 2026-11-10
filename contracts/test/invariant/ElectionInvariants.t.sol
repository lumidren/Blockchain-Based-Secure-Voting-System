// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {Base} from "../utils/Base.t.sol";
import {Fixtures} from "../fixtures/Fixtures.sol";
import {Election} from "../../src/Election.sol";
import {Tally} from "../../src/Tally.sol";
import {IElection, ITally} from "../../src/interfaces/IVeriVote.sol";
import {BabyJubJub} from "../../src/libraries/BabyJubJub.sol";
import {ChaumPedersen} from "../../src/libraries/ChaumPedersen.sol";

/**
 * @dev Stateful fuzzing handler. Starts in Voting and randomly interleaves: casting the next ballot of a
 *      voter, replaying stale ballots, pausing/unpausing (with state snapshots around it), time jumps,
 *      phase advances and a full tally. Ghost variables mirror what the contract must have recorded.
 */
contract ElectionHandler is Test {
    Election public immutable e;
    Tally public immutable tally;
    uint256 public immutable id;
    address public immutable pauser;
    address[] internal trusteeAddrs;

    Fixtures.BallotProof[] internal ballots;
    uint256[][] internal voterBallots; // voter -> indices into ballots, ordered by voteIndex

    // ghosts
    mapping(uint256 voter => uint256) public ghostCasts;
    uint256 public ghostDistinct;
    uint8 public ghostMaxPhase;
    bool public phaseWentBackwards;
    bool public pauseChangedState;
    bool public staleReplayAccepted;
    bool public tallyMismatch;
    uint256 public calls;

    constructor(Election e_, Tally tally_, uint256 id_, address pauser_, address[] memory trustees_) {
        e = e_;
        tally = tally_;
        id = id_;
        pauser = pauser_;
        trusteeAddrs = trustees_;
        Fixtures.BallotProof[] memory all = Fixtures.ballotsK4();
        for (uint256 i = 0; i < all.length; i++) ballots.push(all[i]);
        for (uint256 v = 0; v < Fixtures.VOTERS; v++) voterBallots.push();
        for (uint256 i = 0; i < all.length; i++) voterBallots[all[i].voter].push(i); // fixture order = voteIndex order
        ghostMaxPhase = uint8(e.phase());
    }

    function _afterCall() internal {
        calls++;
        uint8 p = uint8(e.phase());
        if (p < ghostMaxPhase) phaseWentBackwards = true;
        if (p > ghostMaxPhase) ghostMaxPhase = p;
    }

    function castNext(uint256 voterSeed) external {
        uint256 v = voterSeed % Fixtures.VOTERS;
        uint256 n = ghostCasts[v];
        if (n >= voterBallots[v].length) return;
        Fixtures.BallotProof memory b = ballots[voterBallots[v][n]];
        try e.castVote(b.a, b.b, b.c, b.signals) {
            if (n == 0) ghostDistinct++;
            ghostCasts[v] = n + 1;
        } catch {}
        _afterCall();
    }

    function replayStale(uint256 voterSeed, uint256 which) external {
        uint256 v = voterSeed % Fixtures.VOTERS;
        uint256 n = ghostCasts[v];
        if (n == 0) return;
        Fixtures.BallotProof memory b = ballots[voterBallots[v][which % n]];
        try e.castVote(b.a, b.b, b.c, b.signals) {
            staleReplayAccepted = true;
        } catch {}
        _afterCall();
    }

    function pauseWindow(uint256 duration) external {
        IElection.Phase p = e.phase();
        if (p == IElection.Phase.Finalized || p == IElection.Phase.Aborted || e.paused()) return;
        bytes32 before = _stateHash();
        vm.prank(pauser);
        e.pause();
        vm.warp(block.timestamp + bound(duration, 0, 3 hours));
        vm.prank(pauser);
        e.unpause();
        if (_stateHash() != before) pauseChangedState = true;
        _afterCall();
    }

    function warp(uint256 dt) external {
        vm.warp(block.timestamp + bound(dt, 0, 2 hours));
        _afterCall();
    }

    function advance() external {
        try e.advance() {} catch {}
        _afterCall();
    }

    /// @dev Runs aggregation, decryption and finalisation with the counts implied by the ghosts.
    function finish() external {
        if (e.phase() != IElection.Phase.Tallying) return;
        (, bool normalized, bool finalized,,,,) = tally.status(id);
        if (finalized || normalized) return;
        uint256 k;
        Fixtures.BallotProof[] memory finals = new Fixtures.BallotProof[](ghostDistinct);
        uint32[] memory expected = new uint32[](3);
        for (uint256 v = 0; v < Fixtures.VOTERS; v++) {
            uint256 n = ghostCasts[v];
            if (n == 0) continue;
            Fixtures.BallotProof memory b = ballots[voterBallots[v][n - 1]];
            finals[k++] = b;
            expected[b.choice]++;
        }
        if (k > 0) {
            Fixtures.sortByNullifier(finals);
            ITally.Ballot[] memory batch = new ITally.Ballot[](k);
            for (uint256 i = 0; i < k; i++) batch[i] = Fixtures.toTallyBallot(finals[i]);
            tally.aggregate(id, batch);
        }
        tally.normalize(id);
        for (uint8 j = 1; j <= Fixtures.T; j++) _submitPartial(j);
        uint8[] memory subset = new uint8[](Fixtures.T);
        for (uint8 j = 0; j < Fixtures.T; j++) subset[j] = j + 1;
        for (uint8 i = 0; i < 3; i++) tally.finalizeSlot(id, i, expected[i], subset);
        uint32[] memory res = e.results();
        for (uint256 i = 0; i < 3; i++) if (res[i] != expected[i]) tallyMismatch = true;
        _afterCall();
    }

    function _submitPartial(uint8 j) internal {
        (BabyJubJub.Point[] memory c1,) = tally.encryptedTally(id);
        uint256 share = Fixtures.share(j);
        BabyJubJub.Point memory s = BabyJubJub.mul(BabyJubJub.generator(), share);
        BabyJubJub.Point[] memory ds = new BabyJubJub.Point[](c1.length);
        ChaumPedersen.Proof[] memory proofs = new ChaumPedersen.Proof[](c1.length);
        for (uint256 i = 0; i < c1.length; i++) {
            uint256 w = uint256(keccak256(abi.encode(j, i, calls))) % (BabyJubJub.L - 1) + 1;
            ds[i] = BabyJubJub.mul(c1[i], share);
            BabyJubJub.Point memory a = BabyJubJub.mul(BabyJubJub.generator(), w);
            BabyJubJub.Point memory b = BabyJubJub.mul(c1[i], w);
            uint256 ch = ChaumPedersen.challenge(id, i, s, c1[i], ds[i], a, b);
            proofs[i] = ChaumPedersen.Proof(a, b, addmod(w, mulmod(ch, share, BabyJubJub.L), BabyJubJub.L));
        }
        vm.prank(trusteeAddrs[j - 1]);
        tally.submitPartialDecryption(id, ds, proofs);
    }

    /// @dev Everything a pause must not touch: every ballot record, the ballot count and the results.
    function _stateHash() internal view returns (bytes32 h) {
        h = keccak256(abi.encode(e.ballotCount(), e.results(), e.resultsHash(), e.phase()));
        for (uint256 v = 0; v < Fixtures.VOTERS; v++) {
            (uint224 bh, uint32 c) = e.ballotRecord(Fixtures.nullifier(ballots[voterBallots[v][0]]));
            h = keccak256(abi.encode(h, bh, c));
        }
    }

    function recordCount(uint256 v) external view returns (uint32 c) {
        (, c) = e.ballotRecord(Fixtures.nullifier(ballots[voterBallots[v][0]]));
    }
}

/// forge-config: default.invariant.runs = 48
/// forge-config: default.invariant.depth = 24
/// forge-config: ci.invariant.runs = 256
/// forge-config: ci.invariant.depth = 32
contract ElectionInvariants is Base {
    ElectionHandler internal handler;
    uint256 internal id;
    Election internal e;

    function setUp() public override {
        super.setUp();
        (id, e) = _create(4, 3, true);
        _toVoting(id, e);
        handler = new ElectionHandler(e, tally, id, pauser, trustees);
        targetContract(address(handler));
    }

    /// total tally == number of valid nullifiers (checked inside finish() and here)
    function invariant_tallyEqualsDistinctNullifiers() public view {
        assertEq(e.ballotCount(), handler.ghostDistinct(), "ballotCount == distinct nullifiers");
        assertFalse(handler.tallyMismatch(), "decrypted counts == ghost final choices");
        if (e.phase() == IElection.Phase.Finalized) {
            uint32[] memory r = e.results();
            uint256 sum;
            for (uint256 i = 0; i < r.length; i++) sum += r[i];
            assertEq(sum, handler.ghostDistinct(), "sum(results) == valid nullifiers");
        }
    }

    /// no nullifier is used twice: each record count equals the number of accepted casts for that voter
    function invariant_noNullifierReuse() public view {
        for (uint256 v = 0; v < Fixtures.VOTERS; v++) {
            assertEq(handler.recordCount(v), handler.ghostCasts(v));
        }
        assertFalse(handler.staleReplayAccepted(), "stale ballot accepted");
    }

    function invariant_phasesMonotonic() public view {
        assertFalse(handler.phaseWentBackwards());
        assertGe(uint8(e.phase()), uint8(IElection.Phase.Voting));
    }

    function invariant_pauseCannotChangeResults() public view {
        assertFalse(handler.pauseChangedState());
    }

    function afterInvariant() public view {
        console2.log("phase at end of run", uint8(e.phase()), "distinct", handler.ghostDistinct());
    }
}

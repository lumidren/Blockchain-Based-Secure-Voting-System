// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Election} from "../../src/Election.sol";
import {IElection} from "../../src/interfaces/IVeriVote.sol";
import {BabyJubJub} from "../../src/libraries/BabyJubJub.sol";

/**
 * Formal (symbolic) specifications for the Election state machine, checked with Halmos:
 *
 *   halmos --contract ElectionHalmos --function check_ --solver-timeout-assertion 0
 *
 * The real Election contract runs against minimal mocks of the factory, registry, coordinator and an
 * always-accepting verifier, so the properties below quantify over ALL public-signal values, timestamps and
 * pause durations (the proof check is abstracted away; its soundness is the circuit's job).
 */

contract MockFactory {
    address public registry;
    address public coordinator;
    address public tally;
    address public pauserAddr;
    uint256 public activated;
    uint256 public closed;

    constructor(address r, address c, address t, address p) {
        registry = r;
        coordinator = c;
        tally = t;
        pauserAddr = p;
    }

    function isPauser(address a) external view returns (bool) {
        return a == pauserAddr;
    }

    function isUpgradeAuthority(address) external pure returns (bool) {
        return false;
    }

    function onElectionActivated(uint256) external {
        activated++;
    }

    function onElectionClosed(uint256) external {
        closed++;
    }

    function deploy(address impl, Election.InitArgs calldata args) external returns (Election) {
        return Election(address(new ERC1967Proxy(impl, abi.encodeCall(Election.initialize, (args)))));
    }
}

contract MockRegistry {
    function currentRoot(uint256) external pure returns (uint256, uint32) {
        return (777, 10);
    }
}

contract MockCoordinator {
    function trusteeCount(uint256) external pure returns (uint8) {
        return 5;
    }

    function threshold(uint256) external pure returns (uint8) {
        return 3;
    }

    function isFinalized(uint256) external pure returns (bool) {
        return true;
    }

    function publicKey(uint256) external pure returns (BabyJubJub.Point memory) {
        return BabyJubJub.Point(11, 22);
    }
}

contract AcceptingVerifier {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(true);
    }
}

contract ElectionHalmos is Test {
    uint64 internal constant T0 = 1000;
    uint256 internal constant ID = 42;
    address internal pauser = address(0xBEEF);
    address internal tallyAddr = address(0x7A11);
    MockFactory internal factory;
    Election internal e;

    function setUp() public {
        vm.warp(T0);
        factory = new MockFactory(address(new MockRegistry()), address(new MockCoordinator()), tallyAddr, pauser);
        string[] memory names = new string[](3);
        names[0] = "a";
        names[1] = "b";
        names[2] = "c";
        Election.InitArgs memory args = Election.InitArgs({
            electionId: ID,
            admin: address(0xAD),
            title: "t",
            metadataURI: "m",
            candidates: names,
            slots: 4,
            allowRevote: true,
            registrationStart: T0 + 10,
            votingStart: T0 + 100,
            votingEnd: T0 + 1000,
            tallyDeadline: T0 + 2000,
            verifier: address(new AcceptingVerifier()),
            verifierSelector: bytes4(0x12345678),
            numSignals: 23
        });
        e = factory.deploy(address(new Election()), args);
        vm.warp(T0 + 10);
        e.advance();
        vm.warp(T0 + 100);
        e.advance();
    }

    function _signals(uint256 nullifier, uint256 voteIndex, uint256 ct0) internal pure returns (uint256[] memory s) {
        s = new uint256[](23);
        s[0] = ct0;
        s[16] = nullifier;
        s[17] = 777;
        s[18] = ID;
        s[19] = 11;
        s[20] = 22;
        s[21] = 3;
        s[22] = voteIndex;
    }

    function _cast(uint256 nullifier, uint256 voteIndex, uint256 ct0) internal {
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        e.castVote(a, b, c, _signals(nullifier, voteIndex, ct0));
    }

    /// For every nullifier, cast history, pause start and pause duration: pause + unpause leaves every
    /// ballot record, the ballot count, the results and the phase untouched.
    function check_pauseCannotMutateResults(uint256 n1, uint256 n2, uint256 ct, uint32 before, uint32 duration, uint256 probe)
        public
    {
        vm.assume(n1 != n2);
        _cast(n1, 0, ct);
        _cast(n2, 0, ct);
        _cast(n1, 1, ct ^ 1);
        vm.assume(before < 800);
        vm.warp(block.timestamp + before);

        (uint224 h1, uint32 c1) = e.ballotRecord(n1);
        (uint224 hp, uint32 cp) = e.ballotRecord(probe);
        uint32 count = e.ballotCount();
        IElection.Phase phase = e.phase();

        vm.prank(pauser);
        e.pause();
        vm.warp(block.timestamp + duration);
        vm.prank(pauser);
        e.unpause();

        (uint224 h1b, uint32 c1b) = e.ballotRecord(n1);
        (uint224 hpb, uint32 cpb) = e.ballotRecord(probe);
        assert(h1 == h1b && c1 == c1b);
        assert(hp == hpb && cp == cpb);
        assert(count == e.ballotCount());
        assert(phase == e.phase());
        assert(e.results().length == 0);
    }

    /// A pause never shortens the voting window: votingEnd after unpause ≥ votingEnd before.
    function check_pauseNeverShortensVoting(uint32 before, uint32 duration) public {
        vm.assume(before < 800);
        vm.warp(block.timestamp + before);
        (,, uint64 endBefore,) = e.schedule();
        vm.prank(pauser);
        e.pause();
        vm.warp(block.timestamp + duration);
        vm.prank(pauser);
        e.unpause();
        (,, uint64 endAfter,) = e.schedule();
        assert(endAfter == endBefore + duration);
    }

    /// castVote increments a nullifier's count by exactly one, counts a nullifier once, and accepts only
    /// voteIndex == previous count (replay / out-of-order submissions always revert).
    function check_castVoteCountsOnce(uint256 n, uint256 voteIndex, uint256 ct) public {
        _cast(n, 0, ct);
        (, uint32 c0) = e.ballotRecord(n);
        uint32 total0 = e.ballotCount();
        assert(c0 == 1 && total0 == 1);
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        try e.castVote(a, b, c, _signals(n, voteIndex, ct)) {
            assert(voteIndex == 1);
            (, uint32 c1) = e.ballotRecord(n);
            assert(c1 == 2);
            assert(e.ballotCount() == 1);
        } catch {
            assert(voteIndex != 1);
            (, uint32 c1) = e.ballotRecord(n);
            assert(c1 == 1);
        }
    }

    /// Only the pauser can pause; the pauser cannot abort or finalize during Voting.
    function check_pauserHasNoOtherPowers(address caller, uint32[] calldata counts) public {
        vm.assume(caller != pauser);
        vm.prank(caller);
        try e.pause() {
            assert(false);
        } catch {}
        vm.prank(pauser);
        try e.abort("x") {
            assert(false);
        } catch {}
        vm.prank(pauser);
        try e.markFinalized(counts) {
            assert(false);
        } catch {}
        assert(e.phase() == IElection.Phase.Voting);
    }

    /// Phase transitions from Voting: advance() moves to Tallying exactly when now ≥ votingEnd, never back.
    function check_advanceFromVoting(uint32 dt) public {
        vm.warp(block.timestamp + dt);
        try e.advance() {
            assert(block.timestamp >= T0 + 1000);
            assert(e.phase() == IElection.Phase.Tallying);
        } catch {
            assert(block.timestamp < T0 + 1000);
            assert(e.phase() == IElection.Phase.Voting);
        }
    }
}

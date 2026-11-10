// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {console2} from "forge-std/Test.sol";
import {Base} from "./utils/Base.t.sol";
import {Fixtures} from "./fixtures/Fixtures.sol";
import {Election} from "../src/Election.sol";

/// @dev Per-vote gas budgets (committed in GAS_REPORT.md). Fails if a change regresses past the target.
contract GasK4Test is Base {
    uint256 internal constant FIRST_VOTE_BUDGET_K4 = 400_000;
    uint256 internal constant REVOTE_BUDGET_K4 = 400_000;

    function test_gasPerVoteK4() public {
        (uint256 id, Election e) = _create(4, 3, true);
        _toVoting(id, e);
        Fixtures.BallotProof[] memory b = Fixtures.ballotsK4();
        _cast(e, b[1]); // warm the contract once so the measurement is a typical vote
        uint256 g = gasleft();
        _cast(e, b[0]);
        uint256 first = g - gasleft();
        g = gasleft();
        _cast(e, b[8]);
        uint256 revote = g - gasleft();
        console2.log("K4 first vote gas", first);
        console2.log("K4 re-vote gas", revote);
        assertLt(first, FIRST_VOTE_BUDGET_K4);
        assertLt(revote, REVOTE_BUDGET_K4);
    }
}

contract GasK8Test is Base {
    uint256 internal constant FIRST_VOTE_BUDGET_K8 = 600_000;

    function test_gasPerVoteK8() public {
        (uint256 id, Election e) = _create(8, 5, false);
        _toVoting(id, e);
        Fixtures.BallotProof[] memory b = Fixtures.ballotsK8();
        _cast(e, b[1]);
        uint256 g = gasleft();
        _cast(e, b[0]);
        uint256 first = g - gasleft();
        console2.log("K8 first vote gas", first);
        assertLt(first, FIRST_VOTE_BUDGET_K8);
    }
}

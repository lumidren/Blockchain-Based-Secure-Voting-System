// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BabyJubJub} from "./BabyJubJub.sol";

/// @title Lagrange
/// @notice Lagrange coefficients at x = 0 over Z_L for distinct, positive trustee indices.
library Lagrange {
    error DuplicateIndex();
    error ZeroIndex();

    function coefficients(uint256[] memory indices) internal view returns (uint256[] memory lambda) {
        uint256 n = indices.length;
        lambda = new uint256[](n);
        uint256 l = BabyJubJub.L;
        for (uint256 i = 0; i < n; i++) {
            uint256 j = indices[i];
            if (j == 0) revert ZeroIndex();
            uint256 num = 1;
            uint256 den = 1;
            for (uint256 k = 0; k < n; k++) {
                if (k == i) continue;
                uint256 m = indices[k];
                if (m == j) revert DuplicateIndex();
                num = mulmod(num, m, l);
                den = mulmod(den, m > j ? m - j : l - (j - m), l);
            }
            lambda[i] = mulmod(num, BabyJubJub.modInv(den, l), l);
        }
    }
}

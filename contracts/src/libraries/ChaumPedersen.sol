// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BabyJubJub} from "./BabyJubJub.sol";

/**
 * @title ChaumPedersen
 * @notice Verifies a Chaum–Pedersen proof that log_G(S) = log_{C1}(D), used for trustee partial decryptions.
 * @dev Fiat–Shamir: e = keccak256(abi.encodePacked(DST, electionId, slot, S, C1, D, A, B)) mod L.
 *      Verification checks z·G − e·S == A and z·C1 − e·D == B using projective double-scalar
 *      multiplication, so no field inversion is required. Only D must be subgroup-checked: A and B are
 *      forced into the subgroup by the equations once G, S, C1 and D are.
 */
library ChaumPedersen {
    using BabyJubJub for BabyJubJub.Point;

    bytes32 internal constant DST = keccak256("VeriVote/CP/v1");

    struct Proof {
        BabyJubJub.Point a;
        BabyJubJub.Point b;
        uint256 z;
    }

    function challenge(
        uint256 electionId,
        uint256 slot,
        BabyJubJub.Point memory s,
        BabyJubJub.Point memory c1,
        BabyJubJub.Point memory d,
        BabyJubJub.Point memory a,
        BabyJubJub.Point memory b
    ) internal pure returns (uint256) {
        return uint256(
            keccak256(abi.encodePacked(DST, electionId, slot, s.x, s.y, c1.x, c1.y, d.x, d.y, a.x, a.y, b.x, b.y))
        ) % BabyJubJub.L;
    }

    /// @param s   trustee verification key S = s·G (subgroup element, from the DKG)
    /// @param c1  first ciphertext component (subgroup element, aggregated on-chain)
    /// @param d   claimed partial decryption D = s·C1
    function verify(
        BabyJubJub.Point memory s,
        BabyJubJub.Point memory c1,
        BabyJubJub.Point memory d,
        Proof memory proof,
        uint256 electionId,
        uint256 slot
    ) internal view returns (bool) {
        if (proof.z >= BabyJubJub.L) return false;
        if (!BabyJubJub.isOnCurve(proof.a) || !BabyJubJub.isOnCurve(proof.b)) return false;
        if (!BabyJubJub.inSubgroup(d)) return false;
        uint256 e = challenge(electionId, slot, s, c1, d, proof.a, proof.b);
        uint256 negE = (BabyJubJub.L - e) % BabyJubJub.L; // −e mod L (e = 0 maps to 0)
        BabyJubJub.ProjectivePoint memory r1 = BabyJubJub.projMul2(BabyJubJub.generator(), proof.z, s, negE);
        if (!BabyJubJub.projEqualsAffine(r1, proof.a)) return false;
        BabyJubJub.ProjectivePoint memory r2 = BabyJubJub.projMul2(c1, proof.z, d, negE);
        return BabyJubJub.projEqualsAffine(r2, proof.b);
    }
}

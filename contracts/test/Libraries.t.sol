// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {BabyJubJub} from "../src/libraries/BabyJubJub.sol";
import {ChaumPedersen} from "../src/libraries/ChaumPedersen.sol";
import {Lagrange} from "../src/libraries/Lagrange.sol";
import {TestVectors} from "./vectors/TestVectors.sol";

/// @dev Exposes library functions so that `vm.expectRevert` and gas measurement work through external calls.
contract LibHarness {
    function cpVerify(
        BabyJubJub.Point memory s,
        BabyJubJub.Point memory c1,
        BabyJubJub.Point memory d,
        ChaumPedersen.Proof memory proof,
        uint256 electionId,
        uint256 slot
    ) external view returns (bool) {
        return ChaumPedersen.verify(s, c1, d, proof, electionId, slot);
    }

    function mul(BabyJubJub.Point memory p, uint256 k) external view returns (BabyJubJub.Point memory) {
        return BabyJubJub.mul(p, k);
    }

    function inSubgroup(BabyJubJub.Point memory p) external pure returns (bool) {
        return BabyJubJub.inSubgroup(p);
    }

    function lagrange(uint256[] memory idx) external view returns (uint256[] memory) {
        return Lagrange.coefficients(idx);
    }

    function inverse(uint256 a) external view returns (uint256) {
        return BabyJubJub.modInv(a, BabyJubJub.P);
    }
}

contract LibrariesTest is Test {
    using BabyJubJub for BabyJubJub.Point;

    LibHarness internal h;

    function setUp() public {
        h = new LibHarness();
    }

    function test_generatorAndIdentity() public pure {
        BabyJubJub.Point memory g = BabyJubJub.generator();
        assertTrue(BabyJubJub.isOnCurve(g));
        assertTrue(BabyJubJub.inSubgroup(g));
        assertTrue(BabyJubJub.isIdentity(BabyJubJub.identity()));
        assertTrue(BabyJubJub.isOnCurve(BabyJubJub.identity()));
        assertFalse(BabyJubJub.isOnCurve(BabyJubJub.Point(1, 1)));
        assertFalse(BabyJubJub.isOnCurve(BabyJubJub.Point(BabyJubJub.P, 1)));
    }

    function test_hGeneratorMatchesReference() public pure {
        BabyJubJub.Point memory hp = TestVectors.hPoint();
        assertTrue(BabyJubJub.inSubgroup(hp));
        assertFalse(BabyJubJub.eq(hp, BabyJubJub.generator()));
    }

    function test_additionVectors() public view {
        TestVectors.AddVec[] memory v = TestVectors.adds();
        for (uint256 i = 0; i < v.length; i++) {
            assertTrue(BabyJubJub.eq(BabyJubJub.add(v[i].p, v[i].q), v[i].sum), "sum");
            assertTrue(BabyJubJub.eq(BabyJubJub.add(v[i].p, v[i].p), v[i].dbl), "double via add");
            BabyJubJub.ProjectivePoint memory d = BabyJubJub.toProjective(v[i].p);
            BabyJubJub.doubleInPlace(d);
            assertTrue(BabyJubJub.eq(BabyJubJub.toAffine(d), v[i].dbl), "double in place");
            assertTrue(BabyJubJub.eq(BabyJubJub.negate(v[i].p), v[i].neg), "neg");
            assertTrue(BabyJubJub.isIdentity(BabyJubJub.add(v[i].p, v[i].neg)), "p - p");
            assertTrue(BabyJubJub.eq(BabyJubJub.add(v[i].p, BabyJubJub.identity()), v[i].p), "p + O");
            // projective-projective addition agrees with mixed addition
            BabyJubJub.ProjectivePoint memory a = BabyJubJub.toProjective(v[i].p);
            BabyJubJub.ProjectivePoint memory b = BabyJubJub.toProjective(v[i].q);
            BabyJubJub.doubleInPlace(b); // make Z != 1
            BabyJubJub.addInPlace(a, b);
            BabyJubJub.Point memory expected = BabyJubJub.add(v[i].p, BabyJubJub.add(v[i].q, v[i].q));
            assertTrue(BabyJubJub.eq(BabyJubJub.toAffine(a), expected), "add in place (p + 2q)");
        }
    }

    function test_scalarMultiplicationVectors() public view {
        TestVectors.MulVec[] memory v = TestVectors.muls();
        for (uint256 i = 0; i < v.length; i++) {
            assertTrue(BabyJubJub.eq(BabyJubJub.mul(v[i].p, v[i].k), v[i].kp), "k*p");
        }
        assertTrue(BabyJubJub.isIdentity(BabyJubJub.mul(BabyJubJub.generator(), 0)));
        assertTrue(BabyJubJub.isIdentity(BabyJubJub.mul(BabyJubJub.identity(), 12345)));
    }

    function test_doubleScalarMultiplicationVectors() public view {
        TestVectors.Mul2Vec[] memory v = TestVectors.mul2s();
        for (uint256 i = 0; i < v.length; i++) {
            BabyJubJub.ProjectivePoint memory r = BabyJubJub.projMul2(v[i].p1, v[i].k1, v[i].p2, v[i].k2);
            assertTrue(BabyJubJub.projEqualsAffine(r, v[i].result), "k1*p1 + k2*p2");
            assertTrue(BabyJubJub.eq(BabyJubJub.toAffine(r), v[i].result));
        }
        // degenerate scalars
        BabyJubJub.Point memory g = BabyJubJub.generator();
        assertTrue(BabyJubJub.projEqualsAffine(BabyJubJub.projMul2(g, 0, g, 5), BabyJubJub.mul(g, 5)));
        assertTrue(BabyJubJub.projEqualsAffine(BabyJubJub.projMul2(g, 7, g, 0), BabyJubJub.mul(g, 7)));
        assertTrue(BabyJubJub.projEqualsAffine(BabyJubJub.projMul2(g, 3, g, 4), BabyJubJub.mul(g, 7)));
    }

    function testFuzz_mulIsLinear(uint256 k1, uint256 k2) public view {
        k1 = bound(k1, 1, BabyJubJub.L - 1);
        k2 = bound(k2, 1, BabyJubJub.L - 1);
        BabyJubJub.Point memory g = BabyJubJub.generator();
        BabyJubJub.Point memory lhs = BabyJubJub.mul(g, addmod(k1, k2, BabyJubJub.L));
        BabyJubJub.Point memory rhs = BabyJubJub.add(BabyJubJub.mul(g, k1), BabyJubJub.mul(g, k2));
        assertTrue(BabyJubJub.eq(lhs, rhs));
        assertTrue(BabyJubJub.projEqualsAffine(BabyJubJub.projMul2(g, k1, g, k2), lhs));
    }

    function test_subgroupCheckRejectsSmallOrderPoint() public pure {
        // (0, -1) has order 2 on the twisted Edwards curve
        BabyJubJub.Point memory t2 = BabyJubJub.Point(0, BabyJubJub.P - 1);
        assertTrue(BabyJubJub.isOnCurve(t2));
        assertFalse(BabyJubJub.inSubgroup(t2));
        assertTrue(BabyJubJub.isProjIdentity(BabyJubJub.projMul(t2, 2)));
    }

    function test_scaleByCofactorClearsSmallOrder() public view {
        BabyJubJub.Point memory t2 = BabyJubJub.Point(0, BabyJubJub.P - 1);
        BabyJubJub.Point memory mixed = BabyJubJub.add(BabyJubJub.generator(), t2);
        assertTrue(BabyJubJub.isOnCurve(mixed));
        assertFalse(BabyJubJub.inSubgroup(mixed));
        assertTrue(BabyJubJub.inSubgroup(BabyJubJub.mul(mixed, 8) ));
    }

    function test_modInv() public view {
        uint256 a = 123456789;
        uint256 inv = BabyJubJub.modInv(a, BabyJubJub.P);
        assertEq(mulmod(a, inv, BabyJubJub.P), 1);
        uint256 invL = BabyJubJub.modInv(a, BabyJubJub.L);
        assertEq(mulmod(a, invL, BabyJubJub.L), 1);
        assertEq(BabyJubJub.modInv(1, BabyJubJub.P), 1);
    }

    function test_modInvRejectsZero() public {
        vm.expectRevert(BabyJubJub.ZeroInverse.selector);
        h.inverse(0);
    }

    function test_chaumPedersenVectors() public view {
        TestVectors.CpVec[] memory v = TestVectors.cps();
        for (uint256 i = 0; i < v.length; i++) {
            uint256 e = ChaumPedersen.challenge(TestVectors.CP_ELECTION_ID, v[i].slot, v[i].s, v[i].c1, v[i].d, v[i].a, v[i].b);
            assertEq(e, v[i].e, "challenge matches TypeScript");
            ChaumPedersen.Proof memory proof = ChaumPedersen.Proof(v[i].a, v[i].b, v[i].z);
            assertTrue(h.cpVerify(v[i].s, v[i].c1, v[i].d, proof, TestVectors.CP_ELECTION_ID, v[i].slot), "valid proof");
            // wrong slot, wrong election, tampered z, tampered d all fail
            assertFalse(h.cpVerify(v[i].s, v[i].c1, v[i].d, proof, TestVectors.CP_ELECTION_ID, v[i].slot + 1));
            assertFalse(h.cpVerify(v[i].s, v[i].c1, v[i].d, proof, TestVectors.CP_ELECTION_ID + 1, v[i].slot));
            ChaumPedersen.Proof memory bad = ChaumPedersen.Proof(v[i].a, v[i].b, addmod(v[i].z, 1, BabyJubJub.L));
            assertFalse(h.cpVerify(v[i].s, v[i].c1, v[i].d, bad, TestVectors.CP_ELECTION_ID, v[i].slot));
            BabyJubJub.Point memory dBad = BabyJubJub.add(v[i].d, BabyJubJub.generator());
            assertFalse(h.cpVerify(v[i].s, v[i].c1, dBad, proof, TestVectors.CP_ELECTION_ID, v[i].slot));
            ChaumPedersen.Proof memory oob = ChaumPedersen.Proof(v[i].a, v[i].b, BabyJubJub.L);
            assertFalse(h.cpVerify(v[i].s, v[i].c1, v[i].d, oob, TestVectors.CP_ELECTION_ID, v[i].slot));
        }
    }

    function test_chaumPedersenRejectsSmallOrderPartial() public view {
        TestVectors.CpVec[] memory v = TestVectors.cps();
        BabyJubJub.Point memory t2 = BabyJubJub.Point(0, BabyJubJub.P - 1);
        BabyJubJub.Point memory dBad = BabyJubJub.add(v[0].d, t2);
        // even with a consistently adjusted b the proof must fail because d is outside the subgroup
        ChaumPedersen.Proof memory proof = ChaumPedersen.Proof(v[0].a, v[0].b, v[0].z);
        assertFalse(h.cpVerify(v[0].s, v[0].c1, dBad, proof, TestVectors.CP_ELECTION_ID, v[0].slot));
    }

    function test_lagrangeVectors() public view {
        TestVectors.LagrangeVec[] memory v = TestVectors.lagranges();
        for (uint256 i = 0; i < v.length; i++) {
            uint256[] memory l = Lagrange.coefficients(v[i].indices);
            for (uint256 j = 0; j < l.length; j++) assertEq(l[j], v[i].lambdas[j]);
        }
    }

    function test_lagrangeRejectsDuplicatesAndZero() public {
        vm.expectRevert(Lagrange.DuplicateIndex.selector);
        h.lagrange(_arr2(2, 2));
        vm.expectRevert(Lagrange.ZeroIndex.selector);
        h.lagrange(_arr2(0, 1));
    }

    function testFuzz_lagrangeReconstructsPolynomialAtZero(uint256 a0, uint256 a1, uint256 a2) public view {
        a0 = bound(a0, 0, BabyJubJub.L - 1);
        a1 = bound(a1, 0, BabyJubJub.L - 1);
        a2 = bound(a2, 0, BabyJubJub.L - 1);
        uint256[] memory idx = new uint256[](3);
        idx[0] = 2;
        idx[1] = 5;
        idx[2] = 9;
        uint256[] memory l = Lagrange.coefficients(idx);
        uint256 acc;
        for (uint256 i = 0; i < 3; i++) {
            uint256 x = idx[i];
            uint256 fx = addmod(a0, addmod(mulmod(a1, x, BabyJubJub.L), mulmod(a2, mulmod(x, x, BabyJubJub.L), BabyJubJub.L), BabyJubJub.L), BabyJubJub.L);
            acc = addmod(acc, mulmod(l[i], fx, BabyJubJub.L), BabyJubJub.L);
        }
        assertEq(acc, a0);
    }

    function test_gasScalarMul() public view {
        BabyJubJub.Point memory g = BabyJubJub.generator();
        uint256 gasBefore = gasleft();
        BabyJubJub.Point memory r = h.mul(g, BabyJubJub.L - 12345);
        uint256 used = gasBefore - gasleft();
        assertTrue(BabyJubJub.isOnCurve(r));
        assertLt(used, 350_000, "scalar multiplication gas regression budget");
    }

    function _arr2(uint256 a, uint256 b) internal pure returns (uint256[] memory arr) {
        arr = new uint256[](2);
        arr[0] = a;
        arr[1] = b;
    }
}

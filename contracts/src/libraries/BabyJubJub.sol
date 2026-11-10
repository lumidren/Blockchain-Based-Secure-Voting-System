// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title BabyJubJub
 * @notice Twisted Edwards arithmetic for Baby Jubjub (a·x² + y² = 1 + d·x²·y² over the BN254 scalar field).
 * @dev `a` is a quadratic residue and `d` is a non-residue, so the addition law is complete: every formula
 *      here is valid for all inputs including the identity and doubling. Projective coordinates
 *      (X : Y : Z) avoid field inversions inside scalar multiplication; a single inversion (modexp
 *      precompile) converts back to affine. All functions operate in place on memory structs to avoid
 *      memory growth in loops. Mirrors packages/crypto-core/src/babyjub.ts.
 */
library BabyJubJub {
    uint256 internal constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant A = 168700;
    uint256 internal constant D = 168696;
    /// @dev prime order of the large subgroup
    uint256 internal constant L = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    uint256 internal constant GX = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    uint256 internal constant GY = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    struct Point {
        uint256 x;
        uint256 y;
    }

    struct ProjectivePoint {
        uint256 X;
        uint256 Y;
        uint256 Z;
    }

    error NotOnCurve();
    error NotInSubgroup();
    error ScalarOutOfRange();
    error ZeroInverse();
    error PrecompileFailed();

    function generator() internal pure returns (Point memory) {
        return Point(GX, GY);
    }

    function identity() internal pure returns (Point memory) {
        return Point(0, 1);
    }

    function projIdentity() internal pure returns (ProjectivePoint memory) {
        return ProjectivePoint(0, 1, 1);
    }

    function isIdentity(Point memory p) internal pure returns (bool) {
        return p.x == 0 && p.y == 1;
    }

    function isProjIdentity(ProjectivePoint memory p) internal pure returns (bool) {
        return p.X == 0 && p.Y == p.Z && p.Z != 0;
    }

    function eq(Point memory p, Point memory q) internal pure returns (bool) {
        return p.x == q.x && p.y == q.y;
    }

    /// @dev r (projective) == a (affine) without an inversion.
    function projEqualsAffine(ProjectivePoint memory r, Point memory a) internal pure returns (bool) {
        if (r.Z == 0) return false;
        return r.X == mulmod(a.x, r.Z, P) && r.Y == mulmod(a.y, r.Z, P);
    }

    function isOnCurve(Point memory p) internal pure returns (bool) {
        if (p.x >= P || p.y >= P) return false;
        uint256 xx = mulmod(p.x, p.x, P);
        uint256 yy = mulmod(p.y, p.y, P);
        uint256 lhs = addmod(mulmod(A, xx, P), yy, P);
        uint256 rhs = addmod(1, mulmod(mulmod(D, xx, P), yy, P), P);
        return lhs == rhs;
    }

    function requireOnCurve(Point memory p) internal pure {
        if (!isOnCurve(p)) revert NotOnCurve();
    }

    /// @notice True when p is on the curve and L·p = O (prime-order subgroup).
    function inSubgroup(Point memory p) internal pure returns (bool) {
        if (!isOnCurve(p)) return false;
        return isProjIdentity(projMul(p, L));
    }

    function requireInSubgroup(Point memory p) internal pure {
        if (!inSubgroup(p)) revert NotInSubgroup();
    }

    function negate(Point memory p) internal pure returns (Point memory) {
        return Point(p.x == 0 ? 0 : P - p.x, p.y);
    }

    function toProjective(Point memory p) internal pure returns (ProjectivePoint memory) {
        return ProjectivePoint(p.x, p.y, 1);
    }

    // ------------------------------------------------------------------------------------------
    // In-place projective arithmetic ("madd-2008-bbjlp", "add-2008-bbjlp", "dbl-2008-bbjlp")
    // ------------------------------------------------------------------------------------------

    /// @dev r = r + (qx, qy) where q is affine (Z = 1).
    function addAffineInPlace(ProjectivePoint memory r, uint256 qx, uint256 qy) internal pure {
        (r.X, r.Y, r.Z) = _madd(r.X, r.Y, r.Z, qx, qy);
    }

    /// @dev r = r + q, both projective.
    function addInPlace(ProjectivePoint memory r, ProjectivePoint memory q) internal pure {
        uint256 a = mulmod(r.Z, q.Z, P);
        uint256 b = mulmod(a, a, P);
        uint256 c = mulmod(r.X, q.X, P);
        uint256 d = mulmod(r.Y, q.Y, P);
        uint256 e = mulmod(mulmod(D, c, P), d, P);
        uint256 f = addmod(b, P - e, P);
        uint256 g = addmod(b, e, P);
        uint256 t = mulmod(addmod(r.X, r.Y, P), addmod(q.X, q.Y, P), P);
        t = addmod(addmod(t, P - c, P), P - d, P);
        r.X = mulmod(mulmod(a, f, P), t, P);
        r.Y = mulmod(mulmod(a, g, P), addmod(d, P - mulmod(A, c, P), P), P);
        r.Z = mulmod(f, g, P);
    }

    /// @dev r = 2r.
    function doubleInPlace(ProjectivePoint memory r) internal pure {
        (r.X, r.Y, r.Z) = _dbl(r.X, r.Y, r.Z);
    }

    // Stack-based kernels: coordinates never touch memory inside the scalar-multiplication loops.

    /// @dev Projective doubling ("dbl-2008-bbjlp"); inputs are reused as temporaries to stay within the stack.
    function _dbl(uint256 x1, uint256 y1, uint256 z1) private pure returns (uint256 x3, uint256 y3, uint256 z3) {
        assembly ("memory-safe") {
            let c := mulmod(x1, x1, P)
            let d := mulmod(y1, y1, P)
            x1 := addmod(x1, y1, P)
            x1 := addmod(mulmod(x1, x1, P), sub(P, addmod(c, d, P)), P) // B - C - D
            c := mulmod(A, c, P) // E
            y1 := addmod(c, d, P) // F
            z1 := addmod(y1, sub(P, mulmod(2, mulmod(z1, z1, P), P)), P) // J
            x3 := mulmod(x1, z1, P)
            y3 := mulmod(y1, addmod(c, sub(P, d), P), P)
            z3 := mulmod(y1, z1, P)
        }
    }

    /// @dev Mixed addition with an affine point ("madd-2008-bbjlp").
    function _madd(uint256 x1, uint256 y1, uint256 z1, uint256 qx, uint256 qy)
        private
        pure
        returns (uint256 x3, uint256 y3, uint256 z3)
    {
        assembly ("memory-safe") {
            let c := mulmod(x1, qx, P)
            let d := mulmod(y1, qy, P)
            x1 := addmod(mulmod(addmod(x1, y1, P), addmod(qx, qy, P), P), sub(P, addmod(c, d, P)), P)
            y1 := addmod(d, sub(P, mulmod(A, c, P)), P)
            d := mulmod(mulmod(D, c, P), d, P) // E
            c := mulmod(z1, z1, P) // B
            qx := addmod(c, sub(P, d), P) // F
            qy := addmod(c, d, P) // G
            x3 := mulmod(mulmod(z1, qx, P), x1, P)
            y3 := mulmod(mulmod(z1, qy, P), y1, P)
            z3 := mulmod(qx, qy, P)
        }
    }

    /// @notice k·p in projective coordinates (left-to-right double-and-add).
    /// @dev Not constant-time; every input is public on-chain anyway. The whole loop runs in one assembly
    ///      block (same formulas as _dbl/_madd) so no stack frames are created per bit.
    function projMul(Point memory p, uint256 k) internal pure returns (ProjectivePoint memory) {
        if (k == 0 || isIdentity(p)) return ProjectivePoint(0, 1, 1);
        uint256 x;
        uint256 y;
        uint256 z;
        uint256 px = p.x;
        uint256 py = p.y;
        assembly ("memory-safe") {
            let bit := shl(255, 1)
            for {} iszero(and(bit, k)) {} { bit := shr(1, bit) }
            x := px
            y := py
            z := 1
            bit := shr(1, bit)
            for {} bit { bit := shr(1, bit) } {
                // double
                {
                    let c := mulmod(x, x, P)
                    let d := mulmod(y, y, P)
                    let b := addmod(x, y, P)
                    b := addmod(mulmod(b, b, P), sub(P, addmod(c, d, P)), P)
                    c := mulmod(A, c, P)
                    let f := addmod(c, d, P)
                    let j := addmod(f, sub(P, mulmod(2, mulmod(z, z, P), P)), P)
                    x := mulmod(b, j, P)
                    y := mulmod(f, addmod(c, sub(P, d), P), P)
                    z := mulmod(f, j, P)
                }
                if and(k, bit) {
                    let c := mulmod(x, px, P)
                    let d := mulmod(y, py, P)
                    let t := addmod(mulmod(addmod(x, y, P), addmod(px, py, P), P), sub(P, addmod(c, d, P)), P)
                    let u := addmod(d, sub(P, mulmod(A, c, P)), P)
                    d := mulmod(mulmod(D, c, P), d, P)
                    c := mulmod(z, z, P)
                    let f := addmod(c, sub(P, d), P)
                    let g := addmod(c, d, P)
                    x := mulmod(mulmod(z, f, P), t, P)
                    y := mulmod(mulmod(z, g, P), u, P)
                    z := mulmod(f, g, P)
                }
            }
        }
        return ProjectivePoint(x, y, z);
    }

    /// @notice k1·p1 + k2·p2 with Straus' trick (shared doublings, table {p1, p2, p1+p2}).
    function projMul2(Point memory p1, uint256 k1, Point memory p2, uint256 k2)
        internal
        view
        returns (ProjectivePoint memory r)
    {
        if (k1 == 0) return projMul(p2, k2);
        if (k2 == 0) return projMul(p1, k1);
        Point memory p3 = add(p1, p2);
        uint256[6] memory table = [p1.x, p1.y, p2.x, p2.y, p3.x, p3.y];
        uint256 x;
        uint256 y = 1;
        uint256 z = 1;
        assembly ("memory-safe") {
            let bit := shl(255, 1)
            let ks := or(k1, k2)
            for {} iszero(and(bit, ks)) {} { bit := shr(1, bit) }
            for {} bit { bit := shr(1, bit) } {
                {
                    let c := mulmod(x, x, P)
                    let d := mulmod(y, y, P)
                    let b := addmod(x, y, P)
                    b := addmod(mulmod(b, b, P), sub(P, addmod(c, d, P)), P)
                    c := mulmod(A, c, P)
                    let f := addmod(c, d, P)
                    let j := addmod(f, sub(P, mulmod(2, mulmod(z, z, P), P)), P)
                    x := mulmod(b, j, P)
                    y := mulmod(f, addmod(c, sub(P, d), P), P)
                    z := mulmod(f, j, P)
                }
                let sel := or(iszero(iszero(and(k1, bit))), shl(1, iszero(iszero(and(k2, bit)))))
                if sel {
                    let ptr := add(table, mul(sub(sel, 1), 0x40))
                    let qx := mload(ptr)
                    let qy := mload(add(ptr, 0x20))
                    let c := mulmod(x, qx, P)
                    let d := mulmod(y, qy, P)
                    let t := addmod(mulmod(addmod(x, y, P), addmod(qx, qy, P), P), sub(P, addmod(c, d, P)), P)
                    qy := addmod(d, sub(P, mulmod(A, c, P)), P)
                    d := mulmod(mulmod(D, c, P), d, P)
                    c := mulmod(z, z, P)
                    qx := addmod(c, sub(P, d), P)
                    d := addmod(c, d, P)
                    x := mulmod(mulmod(z, qx, P), t, P)
                    y := mulmod(mulmod(z, d, P), qy, P)
                    z := mulmod(qx, d, P)
                }
            }
        }
        r = ProjectivePoint(x, y, z);
    }

    // ------------------------------------------------------------------------------------------
    // Affine helpers (one modexp inversion each)
    // ------------------------------------------------------------------------------------------

    function toAffine(ProjectivePoint memory p) internal view returns (Point memory) {
        if (p.Z == 1) return Point(p.X, p.Y);
        uint256 zi = modInv(p.Z, P);
        return Point(mulmod(p.X, zi, P), mulmod(p.Y, zi, P));
    }

    function add(Point memory p, Point memory q) internal view returns (Point memory) {
        ProjectivePoint memory r = ProjectivePoint(p.x, p.y, 1);
        addAffineInPlace(r, q.x, q.y);
        return toAffine(r);
    }

    function sub(Point memory p, Point memory q) internal view returns (Point memory) {
        return add(p, negate(q));
    }

    function mul(Point memory p, uint256 k) internal view returns (Point memory) {
        return toAffine(projMul(p, k));
    }

    /// @dev a^(m-2) mod m through the modexp precompile (m prime).
    function modInv(uint256 a, uint256 m) internal view returns (uint256 inv) {
        if (a % m == 0) revert ZeroInverse();
        bool ok;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 32)
            mstore(add(ptr, 32), 32)
            mstore(add(ptr, 64), 32)
            mstore(add(ptr, 96), a)
            mstore(add(ptr, 128), sub(m, 2))
            mstore(add(ptr, 160), m)
            ok := staticcall(gas(), 0x05, ptr, 192, ptr, 32)
            inv := mload(ptr)
        }
        if (!ok) revert PrecompileFailed();
    }
}

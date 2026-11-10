// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {BabyJubJub} from "./libraries/BabyJubJub.sol";
import {IElection, IVeriVoteFactory, ITrusteeCoordinator} from "./interfaces/IVeriVote.sol";

/**
 * @title TrusteeCoordinator
 * @notice On-chain coordination of a Pedersen-VSS distributed key generation with Feldman reveal.
 *
 * Timeline per election (`schedule`): keyDeadline < dealDeadline < complaintDeadline < justifyDeadline
 * < revealDeadline < revealComplaintDeadline (≤ election votingStart).
 *
 *  1. registerKey      (≤ keyDeadline)        trustees publish Baby Jubjub encryption keys; those who do are "active"
 *  2. deal             (≤ dealDeadline)        Pedersen commitments C_k = a_k·G + b_k·H and ECIES-encrypted share pairs
 *  3. complain         (≤ complaintDeadline)   a trustee whose share pair fails s·G + s'·H = Σ C_k j^k complains
 *  4. justify          (≤ justifyDeadline)     the dealer reveals the pair; the contract checks it, else the dealer is disqualified
 *     QUAL = dealers that dealt, were not disqualified and have no unjustified complaint
 *  5. reveal           (≤ revealDeadline)      QUAL dealers publish Feldman commitments A_k = a_k·G
 *  6. exposeReveal     (≤ revealComplaintDeadline) a trustee proves a dealer's A_k are inconsistent with its (genuine) share → DKG fails
 *  7. finalize         (> revealComplaintDeadline) PK = Σ A_0, combined_k = Σ A_k over QUAL
 *
 * Verification keys S_j = Σ_k combined_k·j^k are derived on demand (j ≤ 32 so this is cheap).
 */
contract TrusteeCoordinator is ITrusteeCoordinator, Initializable, UUPSUpgradeable {
    using BabyJubJub for BabyJubJub.Point;

    struct Dkg {
        address election;
        uint8 n;
        uint8 t;
        uint8 activeCount;
        uint8 qualCount;
        bool finalized;
        bool failed;
        uint8 maliciousDealer;
        uint64[6] schedule;
        address[] trustees;
        BabyJubJub.Point publicKey;
        BabyJubJub.Point[] combined;
    }

    struct Dealer {
        bool dealt;
        bool revealed;
        bool disqualified;
        uint8 pendingComplaints;
        BabyJubJub.Point[] pedersen;
        BabyJubJub.Point[] feldman;
    }

    enum ComplaintState {
        None,
        Open,
        Justified
    }

    error NotFactory();
    error NotTrustee();
    error NotActiveTrustee();
    error NotUpgradeAuthority();
    error ElectionsActive();
    error AlreadyRegistered();
    error UnknownElection();
    error InvalidThreshold();
    error TooManyTrustees();
    error DuplicateTrustee();
    error InvalidSchedule();
    error WindowClosed(uint8 step);
    error WindowNotOpen(uint8 step);
    error AlreadyDone();
    error NotEnoughActiveTrustees(uint8 active, uint8 threshold);
    error WrongCommitmentCount();
    error WrongShareCount();
    error ShareLengthMismatch(uint8 trustee);
    error NotDealt();
    error NotRevealed();
    error NotQualified();
    error NoOpenComplaint();
    error ComplaintExists();
    error SelfComplaint();
    error InvalidJustification();
    error ShareNotGenuine();
    error FeldmanConsistent();
    error AlreadyFinalized();
    error Failed();
    error NotFinalized();
    error ElectionPaused();
    error ScalarOutOfRange();

    uint8 public constant MAX_TRUSTEES = 32;
    uint256 public constant SHARE_BLOB_LENGTH = 156;

    IVeriVoteFactory public factory;
    mapping(uint256 electionId => Dkg) private _dkgs;
    mapping(uint256 electionId => mapping(address => uint8)) private _trusteeIndex;
    mapping(uint256 electionId => mapping(uint8 => BabyJubJub.Point)) private _encryptionKeys;
    mapping(uint256 electionId => mapping(uint8 => Dealer)) private _dealers;
    mapping(uint256 electionId => mapping(uint8 dealer => mapping(uint8 complainant => ComplaintState))) private _complaints;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address factory_) external initializer {
        __UUPSUpgradeable_init();
        factory = IVeriVoteFactory(factory_);
    }

    // ------------------------------------------------------------------------------------------
    // Setup
    // ------------------------------------------------------------------------------------------

    function initElection(uint256 electionId, address election, address[] calldata trusteeList, uint8 t, uint64[6] calldata timeline)
        external
    {
        if (msg.sender != address(factory)) revert NotFactory();
        Dkg storage d = _dkgs[electionId];
        if (d.election != address(0)) revert AlreadyRegistered();
        uint256 n = trusteeList.length;
        if (n > MAX_TRUSTEES) revert TooManyTrustees();
        if (t < 2 || t > n) revert InvalidThreshold();
        for (uint256 i = 1; i < 6; i++) {
            if (timeline[i] <= timeline[i - 1]) revert InvalidSchedule();
        }
        if (timeline[0] <= block.timestamp) revert InvalidSchedule();
        d.election = election;
        d.n = uint8(n);
        d.t = t;
        d.schedule = timeline;
        for (uint256 i = 0; i < n; i++) {
            address tr = trusteeList[i];
            if (tr == address(0) || _trusteeIndex[electionId][tr] != 0) revert DuplicateTrustee();
            _trusteeIndex[electionId][tr] = uint8(i + 1);
            d.trustees.push(tr);
        }
        emit ElectionRegistered(electionId, election, trusteeList, t);
    }

    // ------------------------------------------------------------------------------------------
    // Protocol steps
    // ------------------------------------------------------------------------------------------

    function registerKey(uint256 electionId, BabyJubJub.Point calldata ek) external {
        Dkg storage d = _dkgs[electionId];
        uint8 j = _requireTrustee(electionId, d);
        _notPaused(d);
        if (block.timestamp > d.schedule[0]) revert WindowClosed(0);
        if (_encryptionKeys[electionId][j].y != 0) revert AlreadyDone();
        BabyJubJub.requireInSubgroup(ek);
        if (BabyJubJub.isIdentity(ek)) revert BabyJubJub.NotInSubgroup();
        _encryptionKeys[electionId][j] = ek;
        d.activeCount += 1;
        emit EncryptionKeyRegistered(electionId, j, ek.x, ek.y);
    }

    /**
     * @param pedersen        t Pedersen commitments C_k = a_k·G + b_k·H
     * @param encryptedShares n blobs (index j-1 for trustee j); 156 bytes for active trustees, empty otherwise
     */
    function deal(uint256 electionId, BabyJubJub.Point[] calldata pedersen, bytes[] calldata encryptedShares) external {
        Dkg storage d = _dkgs[electionId];
        uint8 i = _requireActive(electionId, d);
        _notPaused(d);
        if (block.timestamp <= d.schedule[0]) revert WindowNotOpen(1);
        if (block.timestamp > d.schedule[1]) revert WindowClosed(1);
        if (d.activeCount < d.t) revert NotEnoughActiveTrustees(d.activeCount, d.t);
        Dealer storage dl = _dealers[electionId][i];
        if (dl.dealt) revert AlreadyDone();
        if (pedersen.length != d.t) revert WrongCommitmentCount();
        if (encryptedShares.length != d.n) revert WrongShareCount();
        for (uint256 k = 0; k < pedersen.length; k++) {
            BabyJubJub.requireInSubgroup(pedersen[k]);
            dl.pedersen.push(pedersen[k]);
        }
        for (uint8 j = 1; j <= d.n; j++) {
            bool active = _encryptionKeys[electionId][j].y != 0;
            uint256 len = encryptedShares[j - 1].length;
            if ((active && len != SHARE_BLOB_LENGTH) || (!active && len != 0)) revert ShareLengthMismatch(j);
        }
        dl.dealt = true;
        emit Dealt(electionId, i);
        emit SharesDelivered(electionId, i, encryptedShares);
    }

    function complain(uint256 electionId, uint8 dealer) external {
        Dkg storage d = _dkgs[electionId];
        uint8 j = _requireActive(electionId, d);
        _notPaused(d);
        if (block.timestamp <= d.schedule[1]) revert WindowNotOpen(2);
        if (block.timestamp > d.schedule[2]) revert WindowClosed(2);
        if (dealer == j) revert SelfComplaint();
        Dealer storage dl = _dealers[electionId][dealer];
        if (!dl.dealt) revert NotDealt();
        if (_complaints[electionId][dealer][j] != ComplaintState.None) revert ComplaintExists();
        _complaints[electionId][dealer][j] = ComplaintState.Open;
        dl.pendingComplaints += 1;
        emit ComplaintFiled(electionId, dealer, j);
    }

    /// @notice The dealer answers a complaint by revealing the pair; a valid pair clears it, an invalid one disqualifies the dealer.
    function justify(uint256 electionId, uint8 complainant, uint256 s, uint256 sPrime) external {
        Dkg storage d = _dkgs[electionId];
        uint8 i = _requireActive(electionId, d);
        _notPaused(d);
        if (block.timestamp <= d.schedule[1]) revert WindowNotOpen(3);
        if (block.timestamp > d.schedule[3]) revert WindowClosed(3);
        if (_complaints[electionId][i][complainant] != ComplaintState.Open) revert NoOpenComplaint();
        Dealer storage dl = _dealers[electionId][i];
        if (dl.disqualified) revert NotQualified();
        if (s >= BabyJubJub.L || sPrime >= BabyJubJub.L) revert ScalarOutOfRange();
        if (_pedersenHolds(dl.pedersen, complainant, s, sPrime)) {
            _complaints[electionId][i][complainant] = ComplaintState.Justified;
            dl.pendingComplaints -= 1;
            emit ComplaintJustified(electionId, i, complainant, s, sPrime);
        } else {
            dl.disqualified = true;
            emit DealerDisqualified(electionId, i, "invalid justification");
        }
    }

    function reveal(uint256 electionId, BabyJubJub.Point[] calldata feldman) external {
        Dkg storage d = _dkgs[electionId];
        uint8 i = _requireActive(electionId, d);
        _notPaused(d);
        if (block.timestamp <= d.schedule[3]) revert WindowNotOpen(4);
        if (block.timestamp > d.schedule[4]) revert WindowClosed(4);
        Dealer storage dl = _dealers[electionId][i];
        if (!_isQualified(dl)) revert NotQualified();
        if (dl.revealed) revert AlreadyDone();
        if (feldman.length != d.t) revert WrongCommitmentCount();
        for (uint256 k = 0; k < feldman.length; k++) {
            BabyJubJub.requireInSubgroup(feldman[k]);
            dl.feldman.push(feldman[k]);
        }
        dl.revealed = true;
        emit Revealed(electionId, i);
    }

    /**
     * @notice Trustee j proves that dealer i's Feldman commitments are inconsistent with the share pair it
     *         received: the pair satisfies the Pedersen equation (so it is genuine) but not the Feldman one.
     *         The DKG is then failed and the dealer recorded as malicious.
     */
    function exposeReveal(uint256 electionId, uint8 dealer, uint256 s, uint256 sPrime) external {
        Dkg storage d = _dkgs[electionId];
        uint8 j = _requireActive(electionId, d);
        _notPaused(d);
        if (block.timestamp <= d.schedule[3]) revert WindowNotOpen(5);
        if (block.timestamp > d.schedule[5]) revert WindowClosed(5);
        if (d.failed) revert Failed();
        Dealer storage dl = _dealers[electionId][dealer];
        if (!dl.revealed) revert NotRevealed();
        if (s >= BabyJubJub.L || sPrime >= BabyJubJub.L) revert ScalarOutOfRange();
        if (!_pedersenHolds(dl.pedersen, j, s, sPrime)) revert ShareNotGenuine();
        if (_feldmanHolds(dl.feldman, j, s)) revert FeldmanConsistent();
        d.failed = true;
        d.maliciousDealer = dealer;
        emit DkgFailed(electionId, dealer, "feldman commitments inconsistent with pedersen share");
    }

    /// @notice Finalizes the key after the last window. Fails the DKG if a qualified dealer did not reveal or |QUAL| < t.
    function finalize(uint256 electionId) external {
        Dkg storage d = _dkgs[electionId];
        if (d.election == address(0)) revert UnknownElection();
        _notPaused(d);
        if (block.timestamp <= d.schedule[5]) revert WindowNotOpen(6);
        if (d.finalized) revert AlreadyFinalized();
        if (d.failed) revert Failed();
        uint8 qual = 0;
        for (uint8 i = 1; i <= d.n; i++) {
            Dealer storage dl = _dealers[electionId][i];
            if (!_isQualified(dl)) continue;
            if (!dl.revealed) {
                d.failed = true;
                d.maliciousDealer = i;
                emit DkgFailed(electionId, i, "qualified dealer did not reveal");
                return;
            }
            qual += 1;
        }
        if (qual < d.t) {
            d.failed = true;
            emit DkgFailed(electionId, 0, "fewer qualified dealers than threshold");
            return;
        }
        for (uint8 k = 0; k < d.t; k++) {
            BabyJubJub.ProjectivePoint memory acc = BabyJubJub.projIdentity();
            for (uint8 i = 1; i <= d.n; i++) {
                Dealer storage dl = _dealers[electionId][i];
                if (!_isQualified(dl)) continue;
                BabyJubJub.Point storage a = dl.feldman[k];
                BabyJubJub.addAffineInPlace(acc, a.x, a.y);
            }
            d.combined.push(BabyJubJub.toAffine(acc));
        }
        d.publicKey = d.combined[0];
        d.qualCount = qual;
        d.finalized = true;
        emit DkgFinalized(electionId, d.publicKey.x, d.publicKey.y, qual);
    }

    // ------------------------------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------------------------------

    function publicKey(uint256 electionId) external view returns (BabyJubJub.Point memory) {
        Dkg storage d = _dkgs[electionId];
        if (!d.finalized) revert NotFinalized();
        return d.publicKey;
    }

    function isFinalized(uint256 electionId) external view returns (bool) {
        return _dkgs[electionId].finalized;
    }

    function isFailed(uint256 electionId) external view returns (bool, uint8) {
        return (_dkgs[electionId].failed, _dkgs[electionId].maliciousDealer);
    }

    /// @notice S_j = Σ_k combined_k · j^k (Horner with small-scalar multiplication).
    function verificationKey(uint256 electionId, uint8 j) external view returns (BabyJubJub.Point memory) {
        Dkg storage d = _dkgs[electionId];
        if (!d.finalized) revert NotFinalized();
        if (j == 0 || j > d.n) revert NotTrustee();
        return BabyJubJub.toAffine(_horner(d.combined, j));
    }

    function trusteeIndex(uint256 electionId, address trustee) external view returns (uint8) {
        return _trusteeIndex[electionId][trustee];
    }

    function trusteeCount(uint256 electionId) external view returns (uint8) {
        return _dkgs[electionId].n;
    }

    function activeTrusteeCount(uint256 electionId) external view returns (uint8) {
        return _dkgs[electionId].activeCount;
    }

    function threshold(uint256 electionId) external view returns (uint8) {
        return _dkgs[electionId].t;
    }

    function trustees(uint256 electionId) external view returns (address[] memory) {
        return _dkgs[electionId].trustees;
    }

    function schedule(uint256 electionId) external view returns (uint64[6] memory) {
        return _dkgs[electionId].schedule;
    }

    function encryptionKey(uint256 electionId, uint8 j) external view returns (BabyJubJub.Point memory) {
        return _encryptionKeys[electionId][j];
    }

    function dealerState(uint256 electionId, uint8 i)
        external
        view
        returns (bool dealt, bool revealed, bool disqualified, uint8 pendingComplaints, bool qualified)
    {
        Dealer storage dl = _dealers[electionId][i];
        return (dl.dealt, dl.revealed, dl.disqualified, dl.pendingComplaints, _isQualified(dl));
    }

    function pedersenCommitments(uint256 electionId, uint8 i) external view returns (BabyJubJub.Point[] memory) {
        return _dealers[electionId][i].pedersen;
    }

    function feldmanCommitments(uint256 electionId, uint8 i) external view returns (BabyJubJub.Point[] memory) {
        return _dealers[electionId][i].feldman;
    }

    function combinedCommitments(uint256 electionId) external view returns (BabyJubJub.Point[] memory) {
        return _dkgs[electionId].combined;
    }

    function complaintState(uint256 electionId, uint8 dealer, uint8 complainant) external view returns (ComplaintState) {
        return _complaints[electionId][dealer][complainant];
    }

    // ------------------------------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------------------------------

    function _requireTrustee(uint256 electionId, Dkg storage d) internal view returns (uint8 j) {
        if (d.election == address(0)) revert UnknownElection();
        j = _trusteeIndex[electionId][msg.sender];
        if (j == 0) revert NotTrustee();
    }

    function _requireActive(uint256 electionId, Dkg storage d) internal view returns (uint8 j) {
        j = _requireTrustee(electionId, d);
        if (_encryptionKeys[electionId][j].y == 0) revert NotActiveTrustee();
    }

    function _notPaused(Dkg storage d) internal view {
        if (IElection(d.election).paused()) revert ElectionPaused();
    }

    function _isQualified(Dealer storage dl) internal view returns (bool) {
        return dl.dealt && !dl.disqualified && dl.pendingComplaints == 0;
    }

    /// @dev Σ_k C_k · j^k evaluated with Horner's rule in projective coordinates.
    function _horner(BabyJubJub.Point[] storage commitments, uint8 j) internal view returns (BabyJubJub.ProjectivePoint memory acc) {
        uint256 t = commitments.length;
        BabyJubJub.Point memory top = commitments[t - 1];
        acc = BabyJubJub.toProjective(top);
        for (uint256 k = t - 1; k > 0; k--) {
            _scaleInPlace(acc, j);
            BabyJubJub.Point memory c = commitments[k - 1];
            BabyJubJub.addAffineInPlace(acc, c.x, c.y);
        }
    }

    /// @dev acc = small · acc for small ≤ 255 (double-and-add on a copy of acc).
    function _scaleInPlace(BabyJubJub.ProjectivePoint memory acc, uint8 small) internal pure {
        BabyJubJub.ProjectivePoint memory base = BabyJubJub.ProjectivePoint(acc.X, acc.Y, acc.Z);
        acc.X = 0;
        acc.Y = 1;
        acc.Z = 1;
        uint8 bit = 128;
        while (bit != 0) {
            BabyJubJub.doubleInPlace(acc);
            if (small & bit != 0) BabyJubJub.addInPlace(acc, base);
            bit >>= 1;
        }
    }

    function _pedersenHolds(BabyJubJub.Point[] storage pedersen, uint8 j, uint256 s, uint256 sPrime) internal view returns (bool) {
        BabyJubJub.ProjectivePoint memory lhs = BabyJubJub.projMul2(BabyJubJub.generator(), s, _hPoint(), sPrime);
        BabyJubJub.ProjectivePoint memory rhs = _horner(pedersen, j);
        return _projEq(lhs, rhs);
    }

    function _feldmanHolds(BabyJubJub.Point[] storage feldman, uint8 j, uint256 s) internal view returns (bool) {
        BabyJubJub.ProjectivePoint memory lhs = BabyJubJub.projMul(BabyJubJub.generator(), s);
        BabyJubJub.ProjectivePoint memory rhs = _horner(feldman, j);
        return _projEq(lhs, rhs);
    }

    function _projEq(BabyJubJub.ProjectivePoint memory a, BabyJubJub.ProjectivePoint memory b) internal pure returns (bool) {
        return mulmod(a.X, b.Z, BabyJubJub.P) == mulmod(b.X, a.Z, BabyJubJub.P)
            && mulmod(a.Y, b.Z, BabyJubJub.P) == mulmod(b.Y, a.Z, BabyJubJub.P);
    }

    /// @dev Pedersen second generator H (see packages/crypto-core/src/babyjub.ts#deriveH); pinned by test.
    function _hPoint() internal pure returns (BabyJubJub.Point memory) {
        return BabyJubJub.Point(H_X, H_Y);
    }

    uint256 internal constant H_X = 7097968314694622375263308368172430128932354468556880273637255029561402104728;
    uint256 internal constant H_Y = 1123420383106222657549122671377657702038375402433406593219220838160909378437;

    function _authorizeUpgrade(address) internal view override {
        if (!factory.isUpgradeAuthority(msg.sender)) revert NotUpgradeAuthority();
        if (factory.activeElections() != 0) revert ElectionsActive();
    }
}

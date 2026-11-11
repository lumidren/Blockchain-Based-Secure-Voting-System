# Halmos results

Run: `halmos --contract ElectionHalmos --function check_` (Halmos 0.3.3, z3 4.12.6, Foundry 1.5.1), 2026-11-11.

| Specification | Property (for all symbolic inputs) | Paths | Result |
|---|---|---:|---|
| `check_pauseCannotMutateResults` | pause + unpause at any time, for any duration, leaves every ballot record, the ballot count, the results and the phase unchanged | 9 | PASS |
| `check_pauseNeverShortensVoting` | voting end after unpause = voting end before + paused duration | 9 | PASS |
| `check_castVoteCountsOnce` | a nullifier's count rises by exactly one per accepted ballot; only `voteIndex == count` is accepted; a voter is counted once | 2 | PASS |
| `check_pauserHasNoOtherPowers` | only the pauser can pause; the pauser cannot abort or finalize during Voting | 7 | PASS |
| `check_advanceFromVoting` | `advance()` moves Voting → Tallying exactly when `now ≥ votingEnd`, never backwards | 3 | PASS |

Total: 5 passed, 0 failed, 3.50 s.

Scope: the real `Election` contract runs against minimal mocks of the factory, registry, coordinator and an
always-accepting verifier, so the properties hold for every public-signal value; the soundness of the proof
check itself is the circuit's responsibility (see `circuits/test`). Dynamic arrays use Halmos' default
bounded lengths (`counts` ∈ {0, 1, 2}).

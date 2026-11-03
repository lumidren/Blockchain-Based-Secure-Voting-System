pragma circom 2.1.6;

include "ballot.circom";

component main {public [root, electionId, pk, numCandidates, voteIndex]} = Ballot(8, 20);

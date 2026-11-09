pragma circom 2.2.3;
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "../../circuits/auth_private.circom";
component main = Poseidon(16);

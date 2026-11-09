pragma circom 2.2.3;

include "./distance_only.circom";

component main {public [epsilon]} = DistanceOnly(128, 16, 65535, 48);


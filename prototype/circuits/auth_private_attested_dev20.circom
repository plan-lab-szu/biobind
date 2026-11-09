pragma circom 2.2.3;
include "./auth_private_attested.circom";
component main {public [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]} = AuthPrivateAttested(20, 20);

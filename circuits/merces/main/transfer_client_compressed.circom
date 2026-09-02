pragma circom 2.2.2;

include "merces/client.circom";

// 26: ID registry tree depth. 10: user group tree depth, matching
// MercesUserGroupRegistryV1's configured treeDepth. 80: amount bit size.
component main {public [alpha]} = TransferCompressed(26, 10, 80);

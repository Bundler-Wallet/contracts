// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

library zkConnect {

    function verify (bytes32 zkProof) internal pure returns (bool) {
        
        // Integrate the Sismo's zkConnect on-chain proof verification here
        // Was not available at time of writing, but was ready to be released in end of March.
        // An alternative is to use the zkConnect's off-chain verification and then submit it to a centralized server,
        // which ChainLink would then receive a response from and allow the transaction or not.

        return true;
    }
}
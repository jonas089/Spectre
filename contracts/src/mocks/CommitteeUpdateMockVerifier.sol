
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { CommitteeUpdateVerifier } from "../interfaces/CommitteeUpdateVerifier.sol";

contract CommitteeUpdateMockVerifier is CommitteeUpdateVerifier {
    function verify(uint256[77] calldata _input, bytes calldata _proof) external override returns (bool) {
        return true;
    }
}

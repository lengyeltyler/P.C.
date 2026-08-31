// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationTypes} from "./IPhilAuthorizationTypes.sol";

interface IPhilUnlockProofVerifier is IPhilAuthorizationTypes {
    /// @notice Verifies a concrete unlock proof for one already-selected proof family.
    /// @dev `proof` is the raw `stwo-unlock-keccak-v1` proof-byte codec consumed by the verifier backend.
    /// @dev The blob must not embed routing metadata such as schema version, proof type, artifact version, or verifier key id.
    /// @dev Routing metadata stays outside this blob and is checked by the gate.
    /// @dev Returns `true` on cryptographic success, `false` on proof failure, and may revert on malformed bytes.
    function verifyUnlockProof(
        bytes calldata proof,
        UnlockProofPublicInputs calldata publicInputs
    ) external view returns (bool);
}

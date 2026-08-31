// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.27;

import {
    IPhilCoreV2StaticAuthorityVerifier,
    PhilCoreV2VerifierRequestV1
} from "../base/erc4337/v2/IPhilCoreV2StaticAuthorityVerifier.sol";
import {
    PhilCoreV2AccountInitializationV1
} from "../base/erc4337/v2/IPhilCoreV2MinimalAccountV2.sol";
import {
    PhilCoreV2MinimalAccountV2
} from "../base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol";

contract PhilCoreV2AuthorityVerifierMock is
    IPhilCoreV2StaticAuthorityVerifier
{
    bytes4 private immutable _result;
    bool private immutable _mustRevert;

    constructor(bytes4 result_, bool mustRevert_) {
        _result = result_;
        _mustRevert = mustRevert_;
    }

    function verifyAuthority(
        PhilCoreV2VerifierRequestV1 calldata,
        bytes calldata
    ) external view returns (bytes4) {
        if (_mustRevert) revert();
        return _result;
    }
}

contract PhilCoreV2ConfirmationTargetMock {
    bytes32 public lastActionId;
    bytes32 public lastAuthorizationDigest;
    uint256 public confirmationCount;

    function confirmPhilCoreAction(
        bytes32 actionId,
        bytes32 authorizationDigest
    ) external {
        lastActionId = actionId;
        lastAuthorizationDigest = authorizationDigest;
        unchecked {
            ++confirmationCount;
        }
    }
}

contract PhilCoreV2RejectNativeMock {
    receive() external payable {
        revert();
    }
}

contract PhilCoreV2ReentrantRecipientMock {
    address private _account;
    bytes private _callData;
    bool public attempted;
    bool public succeeded;

    function configure(address account_, bytes calldata callData_) external {
        _account = account_;
        _callData = callData_;
    }

    receive() external payable {
        attempted = true;
        (succeeded,) = _account.call(_callData);
    }
}

contract PhilCoreV2BindingHarness {
    address private immutable _verifier;
    bytes32 private immutable _codeHash;
    uint8 private immutable _returnMode;

    constructor(address verifier_, bytes32 codeHash_, uint8 returnMode_) {
        _verifier = verifier_;
        _codeHash = codeHash_;
        _returnMode = returnMode_;
    }

    function deploy(
        PhilCoreV2AccountInitializationV1 calldata initialization
    ) external returns (PhilCoreV2MinimalAccountV2) {
        return new PhilCoreV2MinimalAccountV2(initialization);
    }

    fallback() external {
        address verifier = _verifier;
        bytes32 codeHash = _codeHash;
        uint8 mode = _returnMode;
        assembly ("memory-safe") {
            if eq(mode, 1) {
                mstore(0, verifier)
                return(0, 32)
            }
            if eq(mode, 2) {
                mstore(0, verifier)
                mstore(32, codeHash)
                mstore(64, 1)
                return(0, 96)
            }
            mstore(0, verifier)
            mstore(32, codeHash)
            return(0, 64)
        }
    }
}

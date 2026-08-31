// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PhilCore4337Account} from "./PhilCore4337Account.sol";

/// @notice Deterministic local/Beta factory for the minimal PhilCore ERC-4337 account.
/// @dev This is intentionally narrow and unaudited. It does not deploy on live networks in M.9A.
contract PhilCore4337AccountFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable approvedActionGate;
    address public immutable recoveryAuthority;
    uint64 public immutable recoveryDelaySeconds;
    uint64 public immutable recoveryExpirySeconds;
    mapping(address => bool) public isPhilSepoliaMintAccount;

    event PhilCore4337AccountCreated(
        address indexed account,
        address indexed owner,
        bytes32 indexed ownerCommitment,
        address approvedActionGate,
        address recoveryAuthority,
        uint256 salt
    );

    error InvalidEntryPoint();
    error InvalidOwner();
    error InvalidActionGate();
    error InvalidRecoveryAuthority();
    error InvalidRecoveryDelay();

    constructor(
        IEntryPoint entryPoint_,
        address approvedActionGate_,
        address recoveryAuthority_,
        uint64 recoveryDelaySeconds_,
        uint64 recoveryExpirySeconds_
    ) {
        if (address(entryPoint_) == address(0)) revert InvalidEntryPoint();
        if (approvedActionGate_ == address(0)) revert InvalidActionGate();
        if (recoveryAuthority_ == address(0)) revert InvalidRecoveryAuthority();
        if (recoveryDelaySeconds_ == 0 || recoveryExpirySeconds_ <= recoveryDelaySeconds_) revert InvalidRecoveryDelay();
        entryPoint = entryPoint_;
        approvedActionGate = approvedActionGate_;
        recoveryAuthority = recoveryAuthority_;
        recoveryDelaySeconds = recoveryDelaySeconds_;
        recoveryExpirySeconds = recoveryExpirySeconds_;
    }

    function createAccount(address owner, bytes32 ownerCommitment, uint256 salt)
        public
        returns (PhilCore4337Account account)
    {
        if (owner == address(0)) revert InvalidOwner();
        if (owner == recoveryAuthority) revert InvalidRecoveryAuthority();
        address accountAddress = getAddress(owner, ownerCommitment, salt);
        if (accountAddress.code.length > 0) {
            isPhilSepoliaMintAccount[accountAddress] = true;
            return PhilCore4337Account(payable(accountAddress));
        }

        account = new PhilCore4337Account{salt: bytes32(salt)}(
            entryPoint,
            owner,
            ownerCommitment,
            approvedActionGate,
            recoveryAuthority,
            recoveryDelaySeconds,
            recoveryExpirySeconds
        );
        isPhilSepoliaMintAccount[address(account)] = true;
        emit PhilCore4337AccountCreated(
            address(account),
            owner,
            ownerCommitment,
            approvedActionGate,
            recoveryAuthority,
            salt
        );
    }

    function getAddress(address owner, bytes32 ownerCommitment, uint256 salt)
        public
        view
        returns (address)
    {
        bytes32 bytecodeHash = keccak256(
            abi.encodePacked(
                type(PhilCore4337Account).creationCode,
                abi.encode(
                    entryPoint,
                    owner,
                    ownerCommitment,
                    approvedActionGate,
                    recoveryAuthority,
                    recoveryDelaySeconds,
                    recoveryExpirySeconds
                )
            )
        );
        return Create2.computeAddress(bytes32(salt), bytecodeHash);
    }
}

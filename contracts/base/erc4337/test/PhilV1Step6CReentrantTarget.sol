// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Test-only target that attempts to call the Step 6C account again while its one action is executing.
contract PhilV1Step6CReentrantTarget {
    error PhilStep6CIntentionalTargetFailure();
    error PhilStep6CUnexpectedReentrySuccess();

    bytes32 public recordedValue;
    uint64 public recordedSequence;
    bool public reentryAttempted;
    bool public reentrySucceeded;

    event ValueRecorded(bytes32 indexed value, uint64 sequence);

    function record(bytes32 value, bool shouldRevert) external payable {
        if (shouldRevert) revert PhilStep6CIntentionalTargetFailure();
        reentryAttempted = true;
        (reentrySucceeded,) = msg.sender.call(abi.encodePacked(bytes4(0x5a99466a)));
        if (reentrySucceeded) revert PhilStep6CUnexpectedReentrySuccess();
        recordedValue = value;
        recordedSequence += 1;
        emit ValueRecorded(value, recordedSequence);
    }
}

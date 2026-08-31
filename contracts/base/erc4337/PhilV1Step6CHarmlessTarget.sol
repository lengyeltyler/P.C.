// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Disposable local-only target for the Phil V1 Step 6C composition gate.
/// @dev It accepts one disclosed bytes32 value and has no authority-bearing method.
contract PhilV1Step6CHarmlessTarget {
    bytes32 public recordedValue;
    uint64 public recordedSequence;

    event ValueRecorded(bytes32 indexed value, uint64 sequence);

    error PhilStep6CValueForbidden();
    error PhilStep6CIntentionalRevert();
    error PhilStep6CSequenceOverflow();

    function record(bytes32 value, bool shouldRevert) external payable {
        if (msg.value != 0) revert PhilStep6CValueForbidden();
        if (shouldRevert) revert PhilStep6CIntentionalRevert();
        if (recordedSequence == type(uint64).max) revert PhilStep6CSequenceOverflow();
        recordedValue = value;
        recordedSequence += 1;
        emit ValueRecorded(value, recordedSequence);
    }
}

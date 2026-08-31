// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract PhilSmartAccountExecutionTarget {
    bytes32 public lastValue;
    address public lastCaller;
    uint256 public calls;

    event Ping(address indexed caller, bytes32 value);

    error ForcedRevert();

    function ping(bytes32 value) external payable returns (bytes32) {
        lastValue = value;
        lastCaller = msg.sender;
        calls += 1;
        emit Ping(msg.sender, value);
        return value;
    }

    function fail() external pure {
        revert ForcedRevert();
    }
}

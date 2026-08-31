// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Read-only view of the subset of an account's configuration this
///         target needs to bind a caller to a specific account version,
///         security model, chain, and confirmation target address.
/// @dev Any contract can implement this interface and report any values it
///      likes under its own address; that is not a vulnerability of this
///      target -- see the contract-level NatSpec for the full evidence-sink
///      caveat.
interface IPhilCoreV2AccountConfigurationView {
    function accountConfiguration()
        external
        view
        returns (
            address entryPoint,
            uint256 deploymentChainId,
            bytes32 ownerCommitment,
            bytes32 identityBindingCommitment,
            address factoryBinding,
            bytes32 accountVersionId,
            bytes32 securityModelId,
            address confirmationTarget
        );
}

/// @title PhilCoreV2ConfirmationTargetV1
/// @notice Minimal, non-payable confirmation-recording sink for the current
///         deployable PhilCore V2 account (`philcore-v2-typed-intent-local-proof-gated-v1`,
///         `ACCOUNT_VERSION_ID` below).
/// @dev This contract is an evidence sink only. It has no owner, no admin,
///      no upgrade path, and performs no proof verification or authorization
///      decisioning of its own -- it only records, per calling address, that
///      a call bearing a self-reported matching configuration occurred.
///
///      Trust boundary: `confirmedAction` is keyed by `msg.sender`. Any
///      contract, including one with no relationship to a real PhilCore
///      account, can implement `IPhilCoreV2AccountConfigurationView` and
///      report `accountConfiguration()` values that satisfy every check
///      below (matching chain, this target's own address, the frozen
///      account version and security model IDs) purely to have its own
///      calls recorded under its own address. That imitation grants the
///      imitator no authority over, and reveals no information about, any
///      other account's recorded confirmations -- state is scoped strictly
///      per caller address. Consumers reading `confirmedAction` must
///      independently trust the specific account address they are querying;
///      this target does not and cannot attest to that trust on their
///      behalf.
///
///      There is no `payable` function, `receive`, or `fallback`; this
///      contract never holds or moves value. Exactly one external call is
///      made per invocation (the `accountConfiguration()` read), and it is
///      made strictly before the storage write, so no external call can
///      observe or interfere with the write or the event.
contract PhilCoreV2ConfirmationTargetV1 {
    bytes32 public constant ACCOUNT_VERSION_ID =
        0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f;
    bytes32 public constant SECURITY_MODEL_ID =
        keccak256("philcore-v2-typed-intent-local-proof-gated-v1");

    /// @notice Confirmation record, keyed by the confirming account address
    ///         and then by the action ID it confirmed. This is the sole
    ///         confirmation state held by this contract.
    mapping(address account => mapping(bytes32 actionId => bool confirmed))
        public confirmedAction;

    event PhilCoreV2ActionConfirmed(
        address indexed account,
        bytes32 indexed actionId,
        bytes32 indexed authorizationDigest
    );

    error CallerIsNotContract();
    error ChainBindingMismatch();
    error TargetBindingMismatch();
    error UnsupportedAccountVersion();
    error UnsupportedSecurityModel();
    error InvalidActionId();
    error InvalidAuthorizationDigest();
    error ActionAlreadyConfirmed();

    /// @notice Records that `msg.sender` confirmed `actionId` under
    ///         `authorizationDigest`. Reverts on any binding mismatch,
    ///         invalid input, or duplicate.
    /// @dev See the contract-level NatSpec for the trust boundary this
    ///      function does and does not enforce.
    function confirmPhilCoreAction(
        bytes32 actionId,
        bytes32 authorizationDigest
    ) external {
        if (msg.sender.code.length == 0) revert CallerIsNotContract();

        (
            ,
            uint256 deploymentChainId,
            ,
            ,
            ,
            bytes32 accountVersionId,
            bytes32 securityModelId,
            address confirmationTarget
        ) = IPhilCoreV2AccountConfigurationView(msg.sender)
            .accountConfiguration();

        if (deploymentChainId != block.chainid) revert ChainBindingMismatch();
        if (confirmationTarget != address(this)) {
            revert TargetBindingMismatch();
        }
        if (accountVersionId != ACCOUNT_VERSION_ID) {
            revert UnsupportedAccountVersion();
        }
        if (securityModelId != SECURITY_MODEL_ID) {
            revert UnsupportedSecurityModel();
        }
        if (actionId == bytes32(0)) revert InvalidActionId();
        if (authorizationDigest == bytes32(0)) {
            revert InvalidAuthorizationDigest();
        }
        if (confirmedAction[msg.sender][actionId]) {
            revert ActionAlreadyConfirmed();
        }

        confirmedAction[msg.sender][actionId] = true;

        emit PhilCoreV2ActionConfirmed(
            msg.sender,
            actionId,
            authorizationDigest
        );
    }
}

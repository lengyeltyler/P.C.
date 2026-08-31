// Local-only reference tests. No fork, RPC endpoint, transaction, or chain mutation.

use phil_v1_step4_account_gate::composed_account_gate::{
    IPhilStep4ComposedAccountGateDispatcher,
    IPhilStep4ComposedAccountGateDispatcherTrait,
    IPhilStep4ComposedAccountGateSafeDispatcher,
    IPhilStep4ComposedAccountGateSafeDispatcherTrait,
    PhilStep4AccountConfigurationV1,
    accepted_step3_verifier_class_hash,
    assert_reference_action_policy_ceilings,
    derive_authorization_envelope_digest,
    derive_device_approval_digest,
    is_valid_device_public_key,
    is_valid_initial_account_nonce,
};
use snforge_std::cheatcodes::storage::{map_entry_address, store};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
};
use starknet::SyscallResultTrait;

const CONSUMED_ENVELOPE_DIGESTS_SELECTOR: felt252 =
    0x1e33abce57c9ab326c5128d8f0086e5e714d9aa3a64957ad751ba5028ac96fa;
const CONSUMED_ROOT_NULLIFIERS_SELECTOR: felt252 =
    0x26e59465c7e76a19a2d77ab76d3bcd956783fcb8fcba415642bdc3ddedac880;
const CONSUMED_APPROVAL_NONCES_SELECTOR: felt252 =
    0x224db5dc2188413b971dd190753b15f60ae931994d6391461242feb027b3d97;

use crate::canonical_fixture::{
    ACCEPTED_STEP3_VERIFIER_CLASS_HASH, APPROVAL_NONCE, AUTHORIZATION_ENVELOPE_DIGEST,
    BLOCK_TIMESTAMP, DEVICE_APPROVAL_DIGEST, EXPECTED_RECEIPT_DIGEST,
    ROOT_PROOF_NULLIFIER, WRONG_KEY_SIGNATURE_R, WRONG_KEY_SIGNATURE_S,
    canonical_approval, canonical_config, canonical_envelope,
};

fn proof_calldata() -> Array<felt252> {
    read_txt(@FileTrait::new("tests/proof_calldata.txt"))
}

fn deploy_gate_with_config(
    config: PhilStep4AccountConfigurationV1,
) -> IPhilStep4ComposedAccountGateDispatcher {
    let gate_class = declare("PhilV1Step4ComposedAccountGate").unwrap().contract_class();
    let mut constructor_calldata = array![];
    config.serialize(ref constructor_calldata);
    let (contract_address, _) = gate_class.deploy(@constructor_calldata).unwrap_syscall();
    start_cheat_block_timestamp(contract_address, BLOCK_TIMESTAMP);
    IPhilStep4ComposedAccountGateDispatcher { contract_address }
}

fn deploy_canonical_gate() -> IPhilStep4ComposedAccountGateDispatcher {
    let verifier_class = declare("UltraKeccakZKHonkVerifier").unwrap().contract_class();
    let verifier_class_hash: felt252 = (*verifier_class.class_hash).into();
    assert(
        verifier_class_hash == ACCEPTED_STEP3_VERIFIER_CLASS_HASH,
        'S4_VERIFIER_HASH_DRIFT',
    );
    deploy_gate_with_config(canonical_config())
}

fn mark_consumed(
    dispatcher: IPhilStep4ComposedAccountGateDispatcher,
    map_selector: felt252,
    key: u256,
) {
    let mut keys = array![];
    key.serialize(ref keys);
    let entry_address = map_entry_address(map_selector, keys.span());
    store(dispatcher.contract_address, entry_address, array![1].span());
}

#[test]
fn generated_digests_match_typescript_reference() {
    let envelope = canonical_envelope();
    let approval = canonical_approval();
    assert(
        derive_authorization_envelope_digest(@envelope) == AUTHORIZATION_ENVELOPE_DIGEST,
        'S4_ENVELOPE_DIGEST',
    );
    assert(
        derive_device_approval_digest(@approval) == DEVICE_APPROVAL_DIGEST,
        'S4_APPROVAL_DIGEST',
    );
}

#[test]
fn valid_proof_signature_policy_and_epochs_authorize_one_receipt() {
    let dispatcher = deploy_canonical_gate();
    let receipt = dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), proof_calldata().span(),
    );
    assert(receipt == EXPECTED_RECEIPT_DIGEST, 'S4_RECEIPT_MISMATCH');

    let (next_nonce, receipt_count, last_receipt) = dispatcher.authorization_state();
    assert(next_nonce == 12, 'S4_NONCE_NOT_ADVANCED');
    assert(receipt_count == 1, 'S4_COUNT_NOT_ADVANCED');
    assert(last_receipt == EXPECTED_RECEIPT_DIGEST, 'S4_RECEIPT_NOT_STORED');
    let (envelope_used, nullifier_used, approval_used) = dispatcher.replay_state(
        AUTHORIZATION_ENVELOPE_DIGEST, ROOT_PROOF_NULLIFIER, APPROVAL_NONCE,
    );
    assert(envelope_used, 'S4_ENVELOPE_NOT_USED');
    assert(nullifier_used, 'S4_NULLIFIER_NOT_USED');
    assert(approval_used, 'S4_APPROVAL_NOT_USED');
}

#[test]
#[should_panic(expected: 'S4_DEVICE_SIGNATURE')]
fn wrong_device_signature_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.signature_r += 1;
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), approval, array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_DEVICE_SIGNATURE')]
fn signature_from_wrong_device_key_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.signature_r = WRONG_KEY_SIGNATURE_R;
    approval.signature_s = WRONG_KEY_SIGNATURE_S;
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), approval, array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_ENVELOPE')]
fn approval_for_another_envelope_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.authorization_envelope_digest += 1;
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), approval, array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_NETWORK')]
fn wrong_network_binding_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.network_id_hash += 1;
    dispatcher.execute_exceptional_reference_action(
        envelope, canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_ACTION')]
fn wrong_action_binding_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.action_type_hash += 1;
    dispatcher.execute_exceptional_reference_action(
        envelope, canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_PARAMETERS')]
fn wrong_parameters_binding_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.parameters_hash += 1;
    dispatcher.execute_exceptional_reference_action(
        envelope, canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_SCOPE_EPOCH')]
fn stale_scope_epoch_is_rejected() {
    let mut config = canonical_config();
    config.scope_epoch += 1;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_DEVICE_EPOCH')]
fn stale_device_epoch_is_rejected() {
    let mut config = canonical_config();
    config.device_epoch += 1;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_ACCOUNT_NONCE')]
fn wrong_account_nonce_is_rejected() {
    let mut config = canonical_config();
    config.next_nonce += 1;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_NOT_YET_VALID')]
fn future_envelope_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    start_cheat_block_timestamp(dispatcher.contract_address, 1799999999);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_EXPIRED')]
fn expired_device_approval_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.approval_expires_at = BLOCK_TIMESTAMP - 1;
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), approval, array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_FEE_LIMIT')]
fn envelope_fee_limit_is_enforced() {
    let mut config = canonical_config();
    config.reference_action_fee = 1000000000000001;
    config.policy_max_fee = 1000000000000001;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_SCOPE_INACTIVE')]
fn inactive_scope_is_rejected() {
    let mut config = canonical_config();
    config.scope_active = false;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_POLICY_REVOKED')]
fn revoked_policy_is_rejected() {
    let mut config = canonical_config();
    config.policy_active = false;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_DEVICE_REVOKED')]
fn revoked_device_is_rejected() {
    let mut config = canonical_config();
    config.device_active = false;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_EMERGENCY_STOP')]
fn emergency_stop_is_enforced() {
    let mut config = canonical_config();
    config.emergency_stopped = true;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_ACCOUNT_NONCE')]
fn successful_authorization_cannot_be_replayed() {
    let dispatcher = deploy_canonical_gate();
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), proof_calldata().span(),
    );
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), proof_calldata().span(),
    );
}

#[test]
#[should_panic]
fn malformed_root_proof_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let original = proof_calldata();
    let mut tampered = array![];
    for index in 0..original.len() {
        let value = *original.at(index);
        tampered.append(if index == 1 { value + 1 } else { value });
    }
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), tampered.span(),
    );
}

#[test]
#[should_panic(expected: 'S4_SCOPE_BINDING')]
fn wrong_secret_derived_commitment_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.scoped_owner_commitment += 1;
    dispatcher.execute_exceptional_reference_action(envelope, canonical_approval(), array![].span());
}

#[test]
#[should_panic(expected: 'S4_SCOPE_BINDING')]
fn wrong_scope_id_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.scope_id += 1;
    dispatcher.execute_exceptional_reference_action(envelope, canonical_approval(), array![].span());
}

#[test]
#[should_panic(expected: 'S4_SCOPE_BINDING')]
fn wrong_scope_instance_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.scope_instance += 1;
    dispatcher.execute_exceptional_reference_action(envelope, canonical_approval(), array![].span());
}

#[test]
#[should_panic(expected: 'S4_ACCOUNT')]
fn wrong_account_binding_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.account_binding_hash += 1;
    dispatcher.execute_exceptional_reference_action(envelope, canonical_approval(), array![].span());
}

#[test]
#[should_panic(expected: 'S4_ADAPTER')]
fn wrong_adapter_binding_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.adapter_id += 1;
    dispatcher.execute_exceptional_reference_action(envelope, canonical_approval(), array![].span());
}

#[test]
#[should_panic(expected: 'S4_PRINCIPAL')]
fn wrong_principal_binding_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.principal_id_hash += 1;
    dispatcher.execute_exceptional_reference_action(envelope, canonical_approval(), array![].span());
}

#[test]
#[should_panic(expected: 'S4_INTENT')]
fn wrong_intent_binding_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.intent_digest += 1;
    dispatcher.execute_exceptional_reference_action(envelope, canonical_approval(), array![].span());
}

#[test]
#[should_panic(expected: 'S4_POLICY')]
fn wrong_policy_binding_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.policy_hash += 1;
    dispatcher.execute_exceptional_reference_action(envelope, canonical_approval(), array![].span());
}

#[test]
#[should_panic(expected: 'S4_DESCRIPTOR')]
fn wrong_proof_descriptor_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.proof_descriptor_hash += 1;
    dispatcher.execute_exceptional_reference_action(envelope, canonical_approval(), array![].span());
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_DEVICE')]
fn wrong_device_id_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.device_id += 1;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_DEVICE')]
fn wrong_device_key_id_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.device_key_id += 1;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_EPOCH')]
fn wrong_approval_device_epoch_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.device_epoch += 1;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_DEVICE_SIGNATURE')]
fn altered_approval_nonce_is_rejected_by_signature_binding() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.approval_nonce += 1;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_SUITE')]
fn wrong_device_suite_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.signature_suite_id += 1;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_PRESENTATION')]
fn wrong_device_presentation_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.human_presentation_hash += 1;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_FUTURE')]
fn future_device_approval_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.approved_at = BLOCK_TIMESTAMP + 1;
    approval.approval_expires_at = BLOCK_TIMESTAMP + 2;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_TIME')]
fn inverted_device_approval_window_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.approval_expires_at = approval.approved_at - 1;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_DEVICE_SIG_FORMAT')]
fn missing_device_signature_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.signature_r = 0;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_DEVICE_SIG_FORMAT')]
fn high_s_device_signature_is_rejected_before_curve_verification() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.signature_s =
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
            - approval.signature_s;
    dispatcher.execute_exceptional_reference_action(canonical_envelope(), approval, array![].span());
}

#[test]
#[should_panic(expected: 'S4_CAP_EPOCH')]
fn stale_capability_epoch_is_rejected() {
    let mut config = canonical_config();
    config.capability_epoch += 1;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_RECOVERY_EPOCH')]
fn stale_recovery_epoch_is_rejected() {
    let mut config = canonical_config();
    config.recovery_epoch += 1;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_VALIDATOR_EPOCH')]
fn stale_validator_epoch_is_rejected() {
    let mut config = canonical_config();
    config.validator_epoch += 1;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_ENVELOPE_EXPIRED')]
fn expired_envelope_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    start_cheat_block_timestamp(dispatcher.contract_address, 1800000301);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_VALUE_LIMIT')]
fn envelope_value_limit_is_enforced() {
    let mut config = canonical_config();
    config.reference_action_value = 1;
    config.policy_max_value = 1;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_DESCRIPTOR_REVOKED')]
fn revoked_proof_descriptor_is_rejected() {
    let mut config = canonical_config();
    config.proof_descriptor_active = false;
    let dispatcher = deploy_gate_with_config(config);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic]
fn missing_root_proof_is_rejected() {
    let dispatcher = deploy_canonical_gate();
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic]
fn wrong_root_nullifier_is_rejected_after_proof_verification() {
    let dispatcher = deploy_canonical_gate();
    let mut envelope = canonical_envelope();
    envelope.root_proof_nullifier += 1;
    dispatcher.execute_exceptional_reference_action(
        envelope, canonical_approval(), proof_calldata().span(),
    );
}

#[test]
#[feature("safe_dispatcher")]
fn rejected_composition_leaves_all_state_unchanged() {
    let dispatcher = deploy_canonical_gate();
    let safe_dispatcher = IPhilStep4ComposedAccountGateSafeDispatcher {
        contract_address: dispatcher.contract_address,
    };
    let mut approval = canonical_approval();
    approval.signature_r += 1;
    let result = safe_dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), approval, array![].span(),
    );
    assert(result.is_err(), 'S4_BAD_COMPOSITION_ACCEPTED');

    let (next_nonce, receipt_count, last_receipt) = dispatcher.authorization_state();
    assert(next_nonce == 11, 'S4_FAILED_NONCE_WRITE');
    assert(receipt_count == 0, 'S4_FAILED_COUNT_WRITE');
    assert(last_receipt == 0, 'S4_FAILED_RECEIPT_WRITE');
    let (envelope_used, nullifier_used, approval_used) = dispatcher.replay_state(
        AUTHORIZATION_ENVELOPE_DIGEST, ROOT_PROOF_NULLIFIER, APPROVAL_NONCE,
    );
    assert(!envelope_used, 'S4_FAILED_ENVELOPE_WRITE');
    assert(!nullifier_used, 'S4_FAILED_NULLIFIER_WRITE');
    assert(!approval_used, 'S4_FAILED_APPROVAL_WRITE');
}

#[test]
fn substitute_verifier_configuration_is_absent_and_empty_proof_fails() {
    let dispatcher = deploy_canonical_gate();
    let reported_hash: felt252 = dispatcher.accepted_root_verifier_class_hash().into();
    assert(reported_hash == ACCEPTED_STEP3_VERIFIER_CLASS_HASH, 'S4_PINNED_HASH_DRIFT');
    let safe_dispatcher = IPhilStep4ComposedAccountGateSafeDispatcher {
        contract_address: dispatcher.contract_address,
    };
    #[feature("safe_dispatcher")]
    let gate_result = safe_dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
    assert(gate_result.is_err(), 'S4_SUBSTITUTE_BYPASS');
}

#[test]
fn accepted_verifier_hash_is_a_contract_constant_not_configuration() {
    let expected: felt252 = accepted_step3_verifier_class_hash().into();
    assert(expected == ACCEPTED_STEP3_VERIFIER_CLASS_HASH, 'S4_CONSTANT_HASH_DRIFT');
    // canonical_config has no verifier-class field or argument; this compile-time
    // construction is the substitution boundary.
    let _config = canonical_config();
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_NONCE')]
fn zero_approval_nonce_is_rejected_as_noncanonical() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.approval_nonce = 0;
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), approval, array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_APPROVED_AT')]
fn zero_approved_at_is_rejected_as_noncanonical() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.approved_at = 0;
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), approval, array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_EXPIRES')]
fn zero_approval_expires_at_is_rejected_as_noncanonical() {
    let dispatcher = deploy_canonical_gate();
    let mut approval = canonical_approval();
    approval.approval_expires_at = 0;
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), approval, array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_CONFIG_VALUE_LIMIT')]
fn action_value_above_policy_ceiling_executes_exact_constructor_rejection() {
    assert_reference_action_policy_ceilings(1, 0, 0, 0);
}

#[test]
#[should_panic(expected: 'S4_CONFIG_FEE_LIMIT')]
fn action_fee_above_policy_ceiling_executes_exact_constructor_rejection() {
    assert_reference_action_policy_ceilings(0, 0, 1, 0);
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_FORMAT')]
fn approval_format_precedes_replay_state() {
    let dispatcher = deploy_canonical_gate();
    mark_consumed(dispatcher, CONSUMED_APPROVAL_NONCES_SELECTOR, APPROVAL_NONCE);
    let mut approval = canonical_approval();
    approval.format_version_hash += 1;
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), approval, array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_ENVELOPE_REPLAY')]
fn consumed_envelope_digest_is_independently_rejected() {
    let dispatcher = deploy_canonical_gate();
    mark_consumed(
        dispatcher, CONSUMED_ENVELOPE_DIGESTS_SELECTOR, AUTHORIZATION_ENVELOPE_DIGEST,
    );
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_NULLIFIER_REPLAY')]
fn consumed_root_nullifier_is_independently_rejected() {
    let dispatcher = deploy_canonical_gate();
    mark_consumed(dispatcher, CONSUMED_ROOT_NULLIFIERS_SELECTOR, ROOT_PROOF_NULLIFIER);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
#[should_panic(expected: 'S4_APPROVAL_REPLAY')]
fn consumed_approval_nonce_is_independently_rejected() {
    let dispatcher = deploy_canonical_gate();
    mark_consumed(dispatcher, CONSUMED_APPROVAL_NONCES_SELECTOR, APPROVAL_NONCE);
    dispatcher.execute_exceptional_reference_action(
        canonical_envelope(), canonical_approval(), array![].span(),
    );
}

#[test]
fn constructor_helpers_reject_invalid_key_and_terminal_nonce() {
    let config = canonical_config();
    assert(
        is_valid_device_public_key(config.device_public_key_x, config.device_public_key_y),
        'S4_CANONICAL_KEY_INVALID',
    );
    assert(!is_valid_device_public_key(1, 1), 'S4_OFF_CURVE_KEY_ACCEPTED');
    assert(is_valid_initial_account_nonce(config.next_nonce), 'S4_CANONICAL_NONCE_INVALID');
    assert(
        !is_valid_initial_account_nonce(0xffffffffffffffff),
        'S4_TERMINAL_NONCE_ACCEPTED',
    );
}

use core::integer::u128_byte_reverse;
use core::keccak::keccak_u256s_be_inputs;
use starknet::SyscallResultTrait;
use starknet::secp256_trait::Secp256Trait;
use starknet::secp256r1::Secp256r1Point;

const PHIL_AUTHORIZATION_ENVELOPE_V1_HASH: u256 =
    0x5d0b7dd98e921d0bc3fbac7ec76871b31df57c731ac1ee1bb2b7b033262f7a53;
const PHIL_DEVICE_APPROVAL_V1_HASH: u256 =
    0x20660a40bf44b8b7730ce3947e69173a5119e45d101926b2aaa6ef6f8de5eccd;
const PHIL_STEP4_REFERENCE_RECEIPT_V1_HASH: u256 =
    0xc3413f2c3097e7982055e1cf65519fc1ecdccbdf5b464b006a2751946d210a55;
const P256_HALF_CURVE_ORDER: u256 =
    0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
const ACCEPTED_STEP3_VERIFIER_CLASS_HASH: felt252 =
    0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd;

#[derive(Copy, Drop, Serde)]
pub struct PhilAuthorizationEnvelopeV1 {
    pub format_version_hash: u256,
    pub operation_class: u8,
    pub scoped_owner_commitment: u256,
    pub scope_id: u256,
    pub scope_instance: u256,
    pub scope_epoch: u64,
    pub principal_id_hash: u256,
    pub capability_id: u256,
    pub capability_epoch: u64,
    pub network_id_hash: u256,
    pub account_binding_hash: u256,
    pub adapter_id: u256,
    pub action_type_hash: u256,
    pub parameters_hash: u256,
    pub intent_digest: u256,
    pub policy_hash: u256,
    pub nonce_domain: u256,
    pub nonce: u256,
    pub root_proof_nullifier: u256,
    pub valid_after: u64,
    pub valid_until: u64,
    pub value_limit: u256,
    pub fee_limit: u256,
    pub device_epoch: u64,
    pub recovery_epoch: u64,
    pub validator_epoch: u64,
    pub device_signature_suite_id: u256,
    pub proof_descriptor_hash: u256,
    pub human_presentation_hash: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct PhilDeviceApprovalV1 {
    pub format_version_hash: u256,
    pub authorization_envelope_digest: u256,
    pub device_id: u256,
    pub device_key_id: u256,
    pub device_epoch: u64,
    pub approval_nonce: u256,
    pub approved_at: u64,
    pub approval_expires_at: u64,
    pub human_presentation_hash: u256,
    pub signature_suite_id: u256,
    pub signature_r: u256,
    pub signature_s: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct PhilStep4AccountConfigurationV1 {
    pub scoped_owner_commitment: u256,
    pub scope_id: u256,
    pub scope_instance: u256,
    pub scope_epoch: u64,
    pub principal_id_hash: u256,
    pub capability_epoch: u64,
    pub network_id_hash: u256,
    pub account_binding_hash: u256,
    pub adapter_id: u256,
    pub action_type_hash: u256,
    pub parameters_hash: u256,
    pub intent_digest: u256,
    pub policy_hash: u256,
    pub nonce_domain: u256,
    pub next_nonce: u64,
    pub device_epoch: u64,
    pub recovery_epoch: u64,
    pub validator_epoch: u64,
    pub device_signature_suite_id: u256,
    pub proof_descriptor_hash: u256,
    pub human_presentation_hash: u256,
    pub device_id: u256,
    pub device_key_id: u256,
    pub device_public_key_x: u256,
    pub device_public_key_y: u256,
    pub reference_action_value: u256,
    pub reference_action_fee: u256,
    pub policy_max_value: u256,
    pub policy_max_fee: u256,
    pub scope_active: bool,
    pub policy_active: bool,
    pub proof_descriptor_active: bool,
    pub device_active: bool,
    pub emergency_stopped: bool,
}

pub fn accepted_step3_verifier_class_hash() -> starknet::ClassHash {
    ACCEPTED_STEP3_VERIFIER_CLASS_HASH.try_into().unwrap()
}

pub fn is_valid_initial_account_nonce(next_nonce: u64) -> bool {
    next_nonce != 0xffffffffffffffff
}

pub fn is_valid_device_public_key(device_public_key_x: u256, device_public_key_y: u256) -> bool {
    Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(
        device_public_key_x, device_public_key_y,
    )
        .unwrap_syscall()
        .is_some()
}

pub fn assert_reference_action_policy_ceilings(
    reference_action_value: u256,
    policy_max_value: u256,
    reference_action_fee: u256,
    policy_max_fee: u256,
) {
    assert(reference_action_value <= policy_max_value, 'S4_CONFIG_VALUE_LIMIT');
    assert(reference_action_fee <= policy_max_fee, 'S4_CONFIG_FEE_LIMIT');
}

fn u256_from_u8(value: u8) -> u256 {
    u256 { low: value.into(), high: 0 }
}

fn u256_from_u64(value: u64) -> u256 {
    u256 { low: value.into(), high: 0 }
}

fn flip_endianness_u256(value: u256) -> u256 {
    u256 { low: u128_byte_reverse(value.high), high: u128_byte_reverse(value.low) }
}

pub fn derive_authorization_envelope_digest(envelope: @PhilAuthorizationEnvelopeV1) -> u256 {
    let mut words = array![];
    words.append(PHIL_AUTHORIZATION_ENVELOPE_V1_HASH);
    words.append(u256_from_u8((*envelope).operation_class));
    words.append((*envelope).scoped_owner_commitment);
    words.append((*envelope).scope_id);
    words.append((*envelope).scope_instance);
    words.append(u256_from_u64((*envelope).scope_epoch));
    words.append((*envelope).principal_id_hash);
    words.append((*envelope).capability_id);
    words.append(u256_from_u64((*envelope).capability_epoch));
    words.append((*envelope).network_id_hash);
    words.append((*envelope).account_binding_hash);
    words.append((*envelope).adapter_id);
    words.append((*envelope).action_type_hash);
    words.append((*envelope).parameters_hash);
    words.append((*envelope).intent_digest);
    words.append((*envelope).policy_hash);
    words.append((*envelope).nonce_domain);
    words.append((*envelope).nonce);
    // root_proof_nullifier is the one architecture-defined omission.
    words.append(u256_from_u64((*envelope).valid_after));
    words.append(u256_from_u64((*envelope).valid_until));
    words.append((*envelope).value_limit);
    words.append((*envelope).fee_limit);
    words.append(u256_from_u64((*envelope).device_epoch));
    words.append(u256_from_u64((*envelope).recovery_epoch));
    words.append(u256_from_u64((*envelope).validator_epoch));
    words.append((*envelope).device_signature_suite_id);
    words.append((*envelope).proof_descriptor_hash);
    words.append((*envelope).human_presentation_hash);
    flip_endianness_u256(keccak_u256s_be_inputs(words.span()))
}

pub fn derive_device_approval_digest(approval: @PhilDeviceApprovalV1) -> u256 {
    let words = array![
        PHIL_DEVICE_APPROVAL_V1_HASH,
        (*approval).authorization_envelope_digest,
        (*approval).device_id,
        (*approval).device_key_id,
        u256_from_u64((*approval).device_epoch),
        (*approval).approval_nonce,
        u256_from_u64((*approval).approved_at),
        u256_from_u64((*approval).approval_expires_at),
    ];
    flip_endianness_u256(keccak_u256s_be_inputs(words.span()))
}

pub fn derive_reference_receipt_digest(
    authorization_envelope_digest: u256,
    root_proof_nullifier: u256,
    device_approval_digest: u256,
    account_nonce: u64,
    receipt_sequence: u64,
) -> u256 {
    let words = array![
        PHIL_STEP4_REFERENCE_RECEIPT_V1_HASH,
        authorization_envelope_digest,
        root_proof_nullifier,
        device_approval_digest,
        u256_from_u64(account_nonce),
        u256_from_u64(receipt_sequence),
    ];
    flip_endianness_u256(keccak_u256s_be_inputs(words.span()))
}

fn public_pair(inputs: Span<u256>, high_index: usize, low_index: usize) -> u256 {
    let high_word = *inputs.at(high_index);
    let low_word = *inputs.at(low_index);
    assert(high_word.high == 0 && low_word.high == 0, 'S4_PROOF_LIMB_RANGE');
    u256 { high: high_word.low, low: low_word.low }
}

#[starknet::interface]
pub trait IPhilStep4ComposedAccountGate<TContractState> {
    fn execute_exceptional_reference_action(
        ref self: TContractState,
        envelope: PhilAuthorizationEnvelopeV1,
        approval: PhilDeviceApprovalV1,
        full_proof_with_hints: Span<felt252>,
    ) -> u256;
    fn authorization_state(
        self: @TContractState,
    ) -> (u64, u64, u256);
    fn replay_state(
        self: @TContractState,
        envelope_digest: u256,
        root_proof_nullifier: u256,
        approval_nonce: u256,
    ) -> (bool, bool, bool);
    fn accepted_root_verifier_class_hash(self: @TContractState) -> starknet::ClassHash;
}

#[starknet::contract]
pub mod PhilV1Step4ComposedAccountGate {
    use super::{
        IPhilStep4ComposedAccountGate, PhilAuthorizationEnvelopeV1,
        PhilDeviceApprovalV1, PhilStep4AccountConfigurationV1,
        derive_authorization_envelope_digest, derive_device_approval_digest,
        derive_reference_receipt_digest, public_pair, u256_from_u64,
        accepted_step3_verifier_class_hash, assert_reference_action_policy_ceilings,
        is_valid_device_public_key, is_valid_initial_account_nonce,
        PHIL_AUTHORIZATION_ENVELOPE_V1_HASH, PHIL_DEVICE_APPROVAL_V1_HASH,
        P256_HALF_CURVE_ORDER,
    };
    use phil_v1_step3_verifier::honk_verifier::{
        IUltraKeccakZKHonkVerifierDispatcherTrait,
        IUltraKeccakZKHonkVerifierLibraryDispatcher,
    };
    use starknet::SyscallResultTrait;
    use starknet::secp256_trait::{Secp256Trait, is_valid_signature};
    use starknet::secp256r1::Secp256r1Point;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess,
    };

    #[storage]
    struct Storage {
        scoped_owner_commitment: u256,
        scope_id: u256,
        scope_instance: u256,
        scope_epoch: u64,
        principal_id_hash: u256,
        capability_epoch: u64,
        network_id_hash: u256,
        account_binding_hash: u256,
        adapter_id: u256,
        action_type_hash: u256,
        parameters_hash: u256,
        intent_digest: u256,
        policy_hash: u256,
        nonce_domain: u256,
        next_nonce: u64,
        device_epoch: u64,
        recovery_epoch: u64,
        validator_epoch: u64,
        device_signature_suite_id: u256,
        proof_descriptor_hash: u256,
        human_presentation_hash: u256,
        device_id: u256,
        device_key_id: u256,
        device_public_key_x: u256,
        device_public_key_y: u256,
        reference_action_value: u256,
        reference_action_fee: u256,
        policy_max_value: u256,
        policy_max_fee: u256,
        scope_active: bool,
        policy_active: bool,
        proof_descriptor_active: bool,
        device_active: bool,
        emergency_stopped: bool,
        consumed_envelope_digests: Map<u256, bool>,
        consumed_root_nullifiers: Map<u256, bool>,
        consumed_approval_nonces: Map<u256, bool>,
        receipt_count: u64,
        last_receipt_digest: u256,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ExceptionalReferenceActionAuthorized: ExceptionalReferenceActionAuthorized,
    }

    #[derive(Drop, starknet::Event)]
    struct ExceptionalReferenceActionAuthorized {
        #[key]
        authorization_envelope_digest: u256,
        #[key]
        root_proof_nullifier: u256,
        device_approval_digest: u256,
        account_nonce: u64,
        receipt_sequence: u64,
        receipt_digest: u256,
    }

    #[constructor]
    fn constructor(ref self: ContractState, config: PhilStep4AccountConfigurationV1) {
        assert(config.scoped_owner_commitment != 0, 'S4_CONFIG_OWNER');
        assert(config.scope_id != 0 && config.scope_instance != 0, 'S4_CONFIG_SCOPE');
        assert(config.principal_id_hash != 0, 'S4_CONFIG_PRINCIPAL');
        assert(config.network_id_hash != 0, 'S4_CONFIG_NETWORK');
        assert(config.account_binding_hash != 0, 'S4_CONFIG_ACCOUNT');
        assert(config.adapter_id != 0 && config.action_type_hash != 0, 'S4_CONFIG_ACTION');
        assert(config.parameters_hash != 0 && config.intent_digest != 0, 'S4_CONFIG_INTENT');
        assert(config.policy_hash != 0, 'S4_CONFIG_POLICY');
        assert(config.nonce_domain != 0, 'S4_CONFIG_NONCE');
        assert(config.device_signature_suite_id != 0, 'S4_CONFIG_SUITE');
        assert(config.proof_descriptor_hash != 0, 'S4_CONFIG_DESCRIPTOR');
        assert(config.human_presentation_hash != 0, 'S4_CONFIG_PRESENTATION');
        assert(config.device_id != 0 && config.device_key_id != 0, 'S4_CONFIG_DEVICE');
        assert(config.device_public_key_x != 0 && config.device_public_key_y != 0, 'S4_CONFIG_KEY');
        assert(
            is_valid_device_public_key(config.device_public_key_x, config.device_public_key_y),
            'S4_CONFIG_KEY_INVALID',
        );
        assert(is_valid_initial_account_nonce(config.next_nonce), 'S4_CONFIG_NONCE_MAX');
        assert(config.scope_epoch != 0, 'S4_CONFIG_SCOPE_EPOCH');
        assert(config.capability_epoch != 0, 'S4_CONFIG_CAP_EPOCH');
        assert(config.device_epoch != 0, 'S4_CONFIG_DEVICE_EPOCH');
        assert(config.recovery_epoch != 0, 'S4_CONFIG_REC_EPOCH');
        assert(config.validator_epoch != 0, 'S4_CONFIG_VAL_EPOCH');
        assert_reference_action_policy_ceilings(
            config.reference_action_value,
            config.policy_max_value,
            config.reference_action_fee,
            config.policy_max_fee,
        );

        self.scoped_owner_commitment.write(config.scoped_owner_commitment);
        self.scope_id.write(config.scope_id);
        self.scope_instance.write(config.scope_instance);
        self.scope_epoch.write(config.scope_epoch);
        self.principal_id_hash.write(config.principal_id_hash);
        self.capability_epoch.write(config.capability_epoch);
        self.network_id_hash.write(config.network_id_hash);
        self.account_binding_hash.write(config.account_binding_hash);
        self.adapter_id.write(config.adapter_id);
        self.action_type_hash.write(config.action_type_hash);
        self.parameters_hash.write(config.parameters_hash);
        self.intent_digest.write(config.intent_digest);
        self.policy_hash.write(config.policy_hash);
        self.nonce_domain.write(config.nonce_domain);
        self.next_nonce.write(config.next_nonce);
        self.device_epoch.write(config.device_epoch);
        self.recovery_epoch.write(config.recovery_epoch);
        self.validator_epoch.write(config.validator_epoch);
        self.device_signature_suite_id.write(config.device_signature_suite_id);
        self.proof_descriptor_hash.write(config.proof_descriptor_hash);
        self.human_presentation_hash.write(config.human_presentation_hash);
        self.device_id.write(config.device_id);
        self.device_key_id.write(config.device_key_id);
        self.device_public_key_x.write(config.device_public_key_x);
        self.device_public_key_y.write(config.device_public_key_y);
        self.reference_action_value.write(config.reference_action_value);
        self.reference_action_fee.write(config.reference_action_fee);
        self.policy_max_value.write(config.policy_max_value);
        self.policy_max_fee.write(config.policy_max_fee);
        self.scope_active.write(config.scope_active);
        self.policy_active.write(config.policy_active);
        self.proof_descriptor_active.write(config.proof_descriptor_active);
        self.device_active.write(config.device_active);
        self.emergency_stopped.write(config.emergency_stopped);
    }

    #[abi(embed_v0)]
    impl PhilStep4ComposedAccountGateImpl of IPhilStep4ComposedAccountGate<ContractState> {
        fn execute_exceptional_reference_action(
            ref self: ContractState,
            envelope: PhilAuthorizationEnvelopeV1,
            approval: PhilDeviceApprovalV1,
            full_proof_with_hints: Span<felt252>,
        ) -> u256 {
            assert(
                envelope.format_version_hash == PHIL_AUTHORIZATION_ENVELOPE_V1_HASH,
                'S4_ENVELOPE_FORMAT',
            );
            assert(envelope.operation_class == 2, 'S4_OPERATION_CLASS');
            assert(envelope.capability_id == 0, 'S4_CAPABILITY_FORBIDDEN');
            assert(envelope.root_proof_nullifier != 0, 'S4_NULLIFIER_REQUIRED');
            assert(envelope.proof_descriptor_hash != 0, 'S4_DESCRIPTOR_REQUIRED');
            assert(envelope.device_signature_suite_id != 0, 'S4_DEVICE_SUITE_REQUIRED');
            assert(approval.format_version_hash == PHIL_DEVICE_APPROVAL_V1_HASH, 'S4_APPROVAL_FORMAT');
            assert(approval.approval_nonce != 0, 'S4_APPROVAL_NONCE');
            assert(approval.approved_at != 0, 'S4_APPROVED_AT');
            assert(approval.approval_expires_at != 0, 'S4_APPROVAL_EXPIRES');

            assert(!self.emergency_stopped.read(), 'S4_EMERGENCY_STOP');
            assert(self.scope_active.read(), 'S4_SCOPE_INACTIVE');
            assert(self.policy_active.read(), 'S4_POLICY_REVOKED');
            assert(self.proof_descriptor_active.read(), 'S4_DESCRIPTOR_REVOKED');
            assert(self.device_active.read(), 'S4_DEVICE_REVOKED');

            assert(
                envelope.scoped_owner_commitment == self.scoped_owner_commitment.read()
                    && envelope.scope_id == self.scope_id.read()
                    && envelope.scope_instance == self.scope_instance.read(),
                'S4_SCOPE_BINDING',
            );
            assert(envelope.principal_id_hash == self.principal_id_hash.read(), 'S4_PRINCIPAL');
            assert(envelope.network_id_hash == self.network_id_hash.read(), 'S4_NETWORK');
            assert(envelope.account_binding_hash == self.account_binding_hash.read(), 'S4_ACCOUNT');
            assert(envelope.adapter_id == self.adapter_id.read(), 'S4_ADAPTER');
            assert(envelope.action_type_hash == self.action_type_hash.read(), 'S4_ACTION');
            assert(envelope.parameters_hash == self.parameters_hash.read(), 'S4_PARAMETERS');
            assert(envelope.intent_digest == self.intent_digest.read(), 'S4_INTENT');
            assert(envelope.policy_hash == self.policy_hash.read(), 'S4_POLICY');
            assert(envelope.nonce_domain == self.nonce_domain.read(), 'S4_NONCE_DOMAIN');
            assert(
                envelope.proof_descriptor_hash == self.proof_descriptor_hash.read(),
                'S4_DESCRIPTOR',
            );
            assert(
                envelope.human_presentation_hash == self.human_presentation_hash.read(),
                'S4_PRESENTATION',
            );
            assert(
                envelope.device_signature_suite_id == self.device_signature_suite_id.read(),
                'S4_DEVICE_SUITE',
            );
            let authorization_envelope_digest = derive_authorization_envelope_digest(@envelope);
            assert(
                approval.authorization_envelope_digest == authorization_envelope_digest,
                'S4_APPROVAL_ENVELOPE',
            );
            assert(
                approval.device_id == self.device_id.read()
                    && approval.device_key_id == self.device_key_id.read(),
                'S4_APPROVAL_DEVICE',
            );
            assert(
                approval.human_presentation_hash == self.human_presentation_hash.read(),
                'S4_APPROVAL_PRESENTATION',
            );
            assert(
                approval.signature_suite_id == self.device_signature_suite_id.read(),
                'S4_APPROVAL_SUITE',
            );

            assert(envelope.scope_epoch == self.scope_epoch.read(), 'S4_SCOPE_EPOCH');
            assert(envelope.capability_epoch == self.capability_epoch.read(), 'S4_CAP_EPOCH');
            assert(envelope.device_epoch == self.device_epoch.read(), 'S4_DEVICE_EPOCH');
            assert(envelope.recovery_epoch == self.recovery_epoch.read(), 'S4_RECOVERY_EPOCH');
            assert(envelope.validator_epoch == self.validator_epoch.read(), 'S4_VALIDATOR_EPOCH');
            assert(approval.device_epoch == self.device_epoch.read(), 'S4_APPROVAL_EPOCH');

            let now = starknet::get_block_timestamp();
            assert(now >= envelope.valid_after, 'S4_NOT_YET_VALID');
            assert(now <= envelope.valid_until, 'S4_ENVELOPE_EXPIRED');
            assert(
                self.reference_action_value.read() <= envelope.value_limit
                    && self.reference_action_value.read() <= self.policy_max_value.read(),
                'S4_VALUE_LIMIT',
            );
            assert(
                self.reference_action_fee.read() <= envelope.fee_limit
                    && self.reference_action_fee.read() <= self.policy_max_fee.read(),
                'S4_FEE_LIMIT',
            );
            assert(approval.approved_at >= envelope.valid_after, 'S4_APPROVAL_TOO_EARLY');
            assert(approval.approved_at <= now, 'S4_APPROVAL_FUTURE');
            assert(approval.approval_expires_at >= approval.approved_at, 'S4_APPROVAL_TIME');
            assert(approval.approval_expires_at <= envelope.valid_until, 'S4_APPROVAL_WINDOW');
            assert(now <= approval.approval_expires_at, 'S4_APPROVAL_EXPIRED');

            let next_nonce = self.next_nonce.read();
            assert(envelope.nonce == u256_from_u64(next_nonce), 'S4_ACCOUNT_NONCE');
            assert(
                !self.consumed_envelope_digests.read(authorization_envelope_digest),
                'S4_ENVELOPE_REPLAY',
            );
            assert(
                !self.consumed_root_nullifiers.read(envelope.root_proof_nullifier),
                'S4_NULLIFIER_REPLAY',
            );
            assert(
                !self.consumed_approval_nonces.read(approval.approval_nonce),
                'S4_APPROVAL_REPLAY',
            );

            let device_approval_digest = derive_device_approval_digest(@approval);
            assert(
                approval.signature_r != 0
                    && approval.signature_s != 0
                    && approval.signature_s <= P256_HALF_CURVE_ORDER,
                'S4_DEVICE_SIG_FORMAT',
            );
            let device_public_key = Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(
                self.device_public_key_x.read(), self.device_public_key_y.read(),
            )
                .unwrap_syscall();
            assert(device_public_key.is_some(), 'S4_DEVICE_KEY_INVALID');
            assert(
                is_valid_signature::<Secp256r1Point>(
                    device_approval_digest,
                    approval.signature_r,
                    approval.signature_s,
                    device_public_key.unwrap(),
                ),
                'S4_DEVICE_SIGNATURE',
            );

            let proof_result = IUltraKeccakZKHonkVerifierLibraryDispatcher {
                class_hash: accepted_step3_verifier_class_hash(),
            }
                .verify_ultra_keccak_zk_honk_proof(full_proof_with_hints);
            assert(proof_result.is_ok(), 'S4_PROOF_INVALID');
            let public_inputs = proof_result.unwrap();
            assert(public_inputs.len() == 13, 'S4_PROOF_INPUT_COUNT');
            assert(
                public_pair(public_inputs, 0, 1) == envelope.scoped_owner_commitment,
                'S4_PROOF_SCOPED_OWNER',
            );
            assert(public_pair(public_inputs, 2, 3) == envelope.scope_id, 'S4_PROOF_SCOPE_ID');
            assert(
                public_pair(public_inputs, 4, 5) == envelope.scope_instance,
                'S4_PROOF_SCOPE_INSTANCE',
            );
            assert(
                *public_inputs.at(6) == u256_from_u64(envelope.scope_epoch),
                'S4_PROOF_SCOPE_EPOCH',
            );
            assert(
                public_pair(public_inputs, 7, 8) == authorization_envelope_digest,
                'S4_PROOF_ENVELOPE',
            );
            assert(
                public_pair(public_inputs, 9, 10) == envelope.root_proof_nullifier,
                'S4_PROOF_NULLIFIER',
            );
            assert(
                public_pair(public_inputs, 11, 12) == envelope.proof_descriptor_hash,
                'S4_PROOF_DESCRIPTOR',
            );

            let receipt_sequence = self.receipt_count.read() + 1;
            let receipt_digest = derive_reference_receipt_digest(
                authorization_envelope_digest,
                envelope.root_proof_nullifier,
                device_approval_digest,
                next_nonce,
                receipt_sequence,
            );
            self.consumed_envelope_digests.write(authorization_envelope_digest, true);
            self.consumed_root_nullifiers.write(envelope.root_proof_nullifier, true);
            self.consumed_approval_nonces.write(approval.approval_nonce, true);
            self.next_nonce.write(next_nonce + 1);
            self.receipt_count.write(receipt_sequence);
            self.last_receipt_digest.write(receipt_digest);
            self.emit(
                Event::ExceptionalReferenceActionAuthorized(
                    ExceptionalReferenceActionAuthorized {
                        authorization_envelope_digest,
                        root_proof_nullifier: envelope.root_proof_nullifier,
                        device_approval_digest,
                        account_nonce: next_nonce,
                        receipt_sequence,
                        receipt_digest,
                    },
                ),
            );
            receipt_digest
        }

        fn authorization_state(self: @ContractState) -> (u64, u64, u256) {
            (
                self.next_nonce.read(),
                self.receipt_count.read(),
                self.last_receipt_digest.read(),
            )
        }

        fn replay_state(
            self: @ContractState,
            envelope_digest: u256,
            root_proof_nullifier: u256,
            approval_nonce: u256,
        ) -> (bool, bool, bool) {
            (
                self.consumed_envelope_digests.read(envelope_digest),
                self.consumed_root_nullifiers.read(root_proof_nullifier),
                self.consumed_approval_nonces.read(approval_nonce),
            )
        }

        fn accepted_root_verifier_class_hash(self: @ContractState) -> starknet::ClassHash {
            accepted_step3_verifier_class_hash()
        }
    }
}

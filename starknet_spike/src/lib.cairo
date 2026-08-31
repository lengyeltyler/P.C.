use core::{integer::u128_byte_reverse, keccak::keccak_u256s_be_inputs};

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct UnlockProofPublicInputs {
    pub owner_commitment: u256,
    pub action_hash: u256,
    pub policy_hash: u256,
    pub nullifier: u256,
    pub consumer_data_hash: u256,
    pub expiry: u64,
}

const DOMAIN_UNLOCK_PROOF_INPUTS: u256 = u256 {
    low: 40939354700605103392208583007457411596,
    high: 268639054636231164950625640019345971342,
};
const VERSION_OFFSET: u256 = u256 { low: 288, high: 0 };
const PROOF_TYPE_OFFSET: u256 = u256 { low: 352, high: 0 };
const VERSION_LENGTH_WORD: u256 = u256 { low: 2, high: 0 };
const VERSION_BYTES_WORD: u256 = u256 {
    low: 0,
    high: 157103326048688279556447227433212444672,
};
const PROOF_TYPE_LENGTH_WORD: u256 = u256 { low: 21, high: 0 };
const PROOF_TYPE_BYTES_WORD: u256 = u256 {
    low: 129491613427520172717528869986428256256,
    high: 153465948365993030244412564244095394659,
};

fn u256_from_u64(value: u64) -> u256 {
    u256 { low: value.into(), high: 0 }
}

fn flip_endianness_u256(value: u256) -> u256 {
    u256 { low: u128_byte_reverse(value.high), high: u128_byte_reverse(value.low) }
}

pub fn locked_proof_input_words(public_inputs: @UnlockProofPublicInputs) -> Array<u256> {
    let mut words = array![];
    words.append(DOMAIN_UNLOCK_PROOF_INPUTS);
    words.append(VERSION_OFFSET);
    words.append(PROOF_TYPE_OFFSET);
    words.append((*public_inputs).owner_commitment);
    words.append((*public_inputs).action_hash);
    words.append((*public_inputs).policy_hash);
    words.append((*public_inputs).nullifier);
    words.append((*public_inputs).consumer_data_hash);
    words.append(u256_from_u64((*public_inputs).expiry));
    words.append(VERSION_LENGTH_WORD);
    words.append(VERSION_BYTES_WORD);
    words.append(PROOF_TYPE_LENGTH_WORD);
    words.append(PROOF_TYPE_BYTES_WORD);
    words
}

pub fn derive_locked_proof_input_hash(public_inputs: @UnlockProofPublicInputs) -> u256 {
    let words = locked_proof_input_words(public_inputs);
    flip_endianness_u256(keccak_u256s_be_inputs(words.span()))
}

pub fn proof_input_hash_payload(hash: u256) -> Array<felt252> {
    let mut payload = array![];
    payload.append(hash.high.into());
    payload.append(hash.low.into());
    payload
}

#[starknet::contract]
pub mod PhilProofInputHashFactRegistry {
    use super::{
        UnlockProofPublicInputs, derive_locked_proof_input_hash, proof_input_hash_payload,
    };
    use starknet::{
        storage::{Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess},
        syscalls::send_message_to_l1_syscall,
    };

    #[storage]
    struct Storage {
        verified_proof_input_hash: Map<u256, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProofInputHashVerified: ProofInputHashVerified,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofInputHashVerified {
        proof_input_hash: u256,
    }

    #[abi(embed_v0)]
    impl Registry of super::IRegistry<ContractState> {
        fn mark_verified_and_send(
            ref self: ContractState,
            l1_recipient: felt252,
            public_inputs: UnlockProofPublicInputs,
        ) -> u256 {
            let proof_input_hash = derive_locked_proof_input_hash(@public_inputs);
            self.verified_proof_input_hash.entry(proof_input_hash).write(true);

            let payload = proof_input_hash_payload(proof_input_hash);
            send_message_to_l1_syscall(l1_recipient, payload.span()).unwrap();

            self.emit(Event::ProofInputHashVerified(ProofInputHashVerified { proof_input_hash }));
            proof_input_hash
        }

        fn is_verified(self: @ContractState, proof_input_hash: u256) -> bool {
            self.verified_proof_input_hash.entry(proof_input_hash).read()
        }
    }
}

#[starknet::interface]
pub trait IRegistry<TContractState> {
    fn mark_verified_and_send(
        ref self: TContractState,
        l1_recipient: felt252,
        public_inputs: UnlockProofPublicInputs,
    ) -> u256;
    fn is_verified(self: @TContractState, proof_input_hash: u256) -> bool;
}

#[cfg(test)]
mod tests {
    use super::{
        DOMAIN_UNLOCK_PROOF_INPUTS, PROOF_TYPE_BYTES_WORD, PROOF_TYPE_LENGTH_WORD,
        PROOF_TYPE_OFFSET, VERSION_BYTES_WORD, VERSION_LENGTH_WORD, VERSION_OFFSET,
        UnlockProofPublicInputs, derive_locked_proof_input_hash, locked_proof_input_words,
        proof_input_hash_payload,
    };

    fn fixture_public_inputs() -> UnlockProofPublicInputs {
        UnlockProofPublicInputs {
            owner_commitment: u256 {
                low: 152166580331148585412406444991358236662,
                high: 312016927853905627998572459602224793239,
            },
            action_hash: u256 {
                low: 93834187378286389586744615618689341468,
                high: 284209275744829419161774714143483500622,
            },
            policy_hash: u256 {
                low: 72405555892127915548662011227267478646,
                high: 260735035723715441624499470647765928490,
            },
            nullifier: u256 {
                low: 267936569665172740409019718547042619142,
                high: 203012290459675877255205880109486121260,
            },
            consumer_data_hash: u256 {
                low: 246848300515972007588112733327075381473,
                high: 43217259809243316238108077399937267758,
            },
            expiry: 1900000000,
        }
    }

    fn fixture_proof_input_hash() -> u256 {
        u256 {
            low: 234978826528971615597333428375786886098,
            high: 187867841298823798720100353582510495302,
        }
    }

    #[test]
    fn proof_input_words_match_locked_shape() {
        let words = locked_proof_input_words(@fixture_public_inputs());

        assert(words.len() == 13, 'bad_words_len');
        assert(*words.at(0) == DOMAIN_UNLOCK_PROOF_INPUTS, 'bad_domain');
        assert(*words.at(1) == VERSION_OFFSET, 'bad_v_off');
        assert(*words.at(2) == PROOF_TYPE_OFFSET, 'bad_t_off');
        assert(*words.at(9) == VERSION_LENGTH_WORD, 'bad_v_len');
        assert(*words.at(10) == VERSION_BYTES_WORD, 'bad_v_bytes');
        assert(*words.at(11) == PROOF_TYPE_LENGTH_WORD, 'bad_t_len');
        assert(*words.at(12) == PROOF_TYPE_BYTES_WORD, 'bad_t_bytes');
    }

    #[test]
    fn proof_input_hash_matches_fixture() {
        let derived = derive_locked_proof_input_hash(@fixture_public_inputs());
        assert(derived == fixture_proof_input_hash(), 'bad_hash');
    }

    #[test]
    fn verification_payload_is_exact_two_felts() {
        let payload = proof_input_hash_payload(fixture_proof_input_hash());
        assert(payload.len() == 2, 'bad_payload_len');
        assert(*payload.at(0) == 187867841298823798720100353582510495302, 'bad_hi');
        assert(*payload.at(1) == 234978826528971615597333428375786886098, 'bad_lo');
    }
}

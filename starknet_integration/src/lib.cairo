use phil_cairo_air_adapter_spike::{
    ProofInputHashSliceClaim, StarkProofMirror, VerificationFactPayload,
    verify_proof_input_hash_slice as adapter_verify_proof_input_hash_slice,
};
use starknet::SyscallResultTrait;
use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

fn fact_u256(payload: @VerificationFactPayload) -> u256 {
    u256 { low: (*payload).fact_low, high: (*payload).fact_high }
}

pub fn verify_proof_input_hash_slice_fact(
    proof: StarkProofMirror, claim: ProofInputHashSliceClaim,
) -> VerificationFactPayload {
    adapter_verify_proof_input_hash_slice(proof, claim)
}

fn fact_payload_felts(payload: @VerificationFactPayload) -> Array<felt252> {
    let mut relay_payload = array![];
    relay_payload.append((*payload).fact_high.into());
    relay_payload.append((*payload).fact_low.into());
    relay_payload
}

pub fn run_verify_proof_input_hash_slice_via_contract_syscalls(
    contract_address: starknet::ContractAddress, calldata: Array<felt252>,
) -> (u128, u128, u128, u128) {
    starknet::testing::set_contract_address(contract_address);

    let mut return_data =
        phil_proof_input_hash_verifier::__external::verify_proof_input_hash_slice(calldata.span());
    let payload = Serde::<VerificationFactPayload>::deserialize(ref return_data).unwrap();
    assert!(return_data.is_empty(), "unexpected leftover return data");

    let emitted: phil_proof_input_hash_verifier::Event =
        starknet::testing::pop_log(contract_address).unwrap();
    assert!(
        starknet::testing::pop_log_raw(contract_address).is_none(), "unexpected extra logs",
    );

    match emitted {
        phil_proof_input_hash_verifier::Event::ProofInputHashFactVerified(event) => {
            (payload.fact_high, payload.fact_low, event.fact_high, event.fact_low)
        },
    }
}

pub fn run_verify_proof_input_hash_slice_and_send_to_l1_via_contract_syscalls(
    contract_address: starknet::ContractAddress, l1_recipient: felt252, calldata: Array<felt252>,
) -> (felt252, felt252, felt252, felt252, felt252, felt252, felt252) {
    starknet::testing::set_contract_address(contract_address);

    let mut full_calldata = array![];
    full_calldata.append(l1_recipient);
    full_calldata.append_span(calldata.span());

    let mut return_data = phil_proof_input_hash_verifier::__external
        ::verify_proof_input_hash_slice_and_send_to_l1(full_calldata.span());
    let payload = Serde::<VerificationFactPayload>::deserialize(ref return_data).unwrap();
    assert!(return_data.len() == 0, "unexpected leftover return data");

    let emitted: phil_proof_input_hash_verifier::Event =
        starknet::testing::pop_log(contract_address).unwrap();
    let (relay_to_address, relay_payload) =
        starknet::testing::pop_l2_to_l1_message(contract_address).unwrap();

    assert!(relay_payload.len() == 2, "unexpected relay payload length");
    assert!(
        starknet::testing::pop_log_raw(contract_address).is_none(), "unexpected extra logs",
    );
    assert!(
        starknet::testing::pop_l2_to_l1_message(contract_address).is_none(),
        "unexpected extra l2-to-l1 messages",
    );

    match emitted {
        phil_proof_input_hash_verifier::Event::ProofInputHashFactVerified(event) => (
            payload.fact_high.into(),
            payload.fact_low.into(),
            event.fact_high.into(),
            event.fact_low.into(),
            relay_to_address,
            *relay_payload.at(0),
            *relay_payload.at(1),
        ),
    }
}

#[starknet::contract]
pub mod phil_proof_input_hash_verifier {
    use super::{
        Map, ProofInputHashSliceClaim, StarkProofMirror, StorageMapReadAccess,
        StorageMapWriteAccess, SyscallResultTrait, VerificationFactPayload, fact_payload_felts,
        fact_u256,
        verify_proof_input_hash_slice_fact,
    };

    #[storage]
    pub struct Storage {
        verified_facts: Map<u256, bool>,
    }

    #[derive(Copy, Drop, Debug, PartialEq, starknet::Event)]
    pub struct ProofInputHashFactVerified {
        pub fact_high: u128,
        pub fact_low: u128,
    }

    #[event]
    #[derive(Copy, Drop, Debug, PartialEq, starknet::Event)]
    pub enum Event {
        ProofInputHashFactVerified: ProofInputHashFactVerified,
    }

    #[abi(per_item)]
    #[generate_trait]
    pub impl IPhilProofInputHashVerifierImpl of IPhilProofInputHashVerifier {
        #[external(v0)]
        fn verify_proof_input_hash_slice(
            ref self: ContractState, proof: StarkProofMirror, claim: ProofInputHashSliceClaim,
        ) -> VerificationFactPayload {
            let payload = verify_proof_input_hash_slice_fact(proof, claim);
            self.register_verified_fact(payload);
            payload
        }

        #[external(v0)]
        fn verify_proof_input_hash_slice_and_send_to_l1(
            ref self: ContractState,
            l1_recipient: felt252,
            proof: StarkProofMirror,
            claim: ProofInputHashSliceClaim,
        ) -> VerificationFactPayload {
            let payload = verify_proof_input_hash_slice_fact(proof, claim);
            self.register_verified_fact_and_send_to_l1(l1_recipient, payload);
            payload
        }

        fn is_verified(self: @ContractState, fact_high: u128, fact_low: u128) -> bool {
            self.verified_facts.read(u256 { low: fact_low, high: fact_high })
        }
    }

    #[generate_trait]
    pub impl PhilVerificationStateImpl of PhilVerificationStateTrait {
        fn register_verified_fact(ref self: ContractState, payload: VerificationFactPayload) {
            self.verified_facts.write(fact_u256(@payload), true);
            self.emit(
                Event::ProofInputHashFactVerified(
                    ProofInputHashFactVerified {
                        fact_high: payload.fact_high, fact_low: payload.fact_low,
                    },
                ),
            );
        }

        fn register_verified_fact_and_send_to_l1(
            ref self: ContractState, l1_recipient: felt252, payload: VerificationFactPayload,
        ) {
            self.register_verified_fact(payload);
            let relay_payload = fact_payload_felts(@payload);
            starknet::syscalls::send_message_to_l1_syscall(
                l1_recipient, relay_payload.span(),
            )
                .unwrap_syscall();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        VerificationFactPayload, phil_proof_input_hash_verifier,
    };
    use super::phil_proof_input_hash_verifier::{
        Event, IPhilProofInputHashVerifier, PhilVerificationStateTrait, ProofInputHashFactVerified,
    };

    #[test]
    fn test_register_verified_fact_emits_exact_two_felt_payload() {
        let mut contract = phil_proof_input_hash_verifier::unsafe_new_contract_state();
        let contract_address: starknet::ContractAddress = 0x5048494c_felt252.try_into().unwrap();
        let payload = VerificationFactPayload {
            fact_high: 0x8d5607b595200f66c7d24010dc79d646,
            fact_low: 0xb0c7469cdaca5eecbbabb83d326413d2,
        };

        starknet::testing::set_contract_address(contract_address);
        contract.register_verified_fact(payload);

        assert!(contract.is_verified(payload.fact_high, payload.fact_low), "fact not stored");
        let emitted: Option<Event> = starknet::testing::pop_log(contract_address);
        assert!(
            emitted
                == Some(
                    Event::ProofInputHashFactVerified(
                        ProofInputHashFactVerified {
                            fact_high: payload.fact_high, fact_low: payload.fact_low,
                        },
                    ),
                ),
            "unexpected emitted fact payload",
        );
        assert!(
            starknet::testing::pop_log_raw(contract_address).is_none(),
            "unexpected extra logs",
        );
    }
}

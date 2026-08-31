// Local-only reference verification. No fork, network endpoint, or chain mutation.

use phil_v1_step3_verifier::honk_verifier::{
    IUltraKeccakZKHonkVerifierDispatcherTrait, IUltraKeccakZKHonkVerifierLibraryDispatcher,
};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{DeclareResultTrait, declare};

fn verifier() -> IUltraKeccakZKHonkVerifierLibraryDispatcher {
    let class_hash = *declare("UltraKeccakZKHonkVerifier")
        .unwrap()
        .contract_class()
        .class_hash;
    IUltraKeccakZKHonkVerifierLibraryDispatcher { class_hash }
}

fn proof_calldata() -> Array<felt252> {
    let file = FileTrait::new("tests/proof_calldata.txt");
    read_txt(@file)
}

#[test]
fn valid_phil_root_proof_returns_exact_public_inputs() {
    let result = verifier().verify_ultra_keccak_zk_honk_proof(proof_calldata().span());
    assert(result.is_ok(), 'valid Phil proof rejected');
    let public_inputs = result.unwrap();
    assert(public_inputs.len() == 13, 'public input count');

    let scoped_owner_commitment_high = *public_inputs.at(0);
    assert(
        scoped_owner_commitment_high.low
            == 0x5663430e521900932a9e2aa9685b16f7
            && scoped_owner_commitment_high.high == 0,
        'scoped commitment mismatch',
    );
    let scope_epoch = *public_inputs.at(6);
    assert(scope_epoch.low == 7 && scope_epoch.high == 0, 'scope epoch mismatch');
    let descriptor_hash_low = *public_inputs.at(12);
    assert(
        descriptor_hash_low.low == 0x80961b12a937b0a37fcac79a8851f135
            && descriptor_hash_low.high == 0,
        'descriptor mismatch',
    );
}

#[test]
#[should_panic]
fn tampered_public_input_is_rejected() {
    let original = proof_calldata();
    let mut calldata = array![];
    // The first item is the public-input span length; the next item is the low
    // limb of the first u256 public input. Change only that bound value.
    for i in 0..original.len() {
        let value = *original.at(i);
        calldata.append(if i == 1 { value + 1 } else { value });
    }
    // Garaga's generated verifier aborts during malformed proof decomposition;
    // the expected panic proves that the altered public input fails closed.
    let _result = verifier().verify_ultra_keccak_zk_honk_proof(calldata.span());
}

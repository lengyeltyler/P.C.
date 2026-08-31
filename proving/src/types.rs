use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockPublicInputs {
    pub owner_commitment: [u8; 32],
    pub action_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub consumer_data_hash: [u8; 32],
    pub expiry: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateProofInput {
    pub public_inputs: UnlockPublicInputs,
    pub phil_secret: [u8; 32],
    pub nullifier_seed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockProofArtifactEnvelope {
    #[serde(rename = "artifactVersion")]
    pub artifact_version: String,
    #[serde(rename = "verifierKeyId")]
    pub verifier_key_id: [u8; 32],
    #[serde(rename = "proofBytes")]
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockVerifierPackage {
    pub version: String,
    #[serde(rename = "proofType")]
    pub proof_type: String,
    #[serde(rename = "publicInputs")]
    pub public_inputs: UnlockPublicInputs,
    #[serde(rename = "proofInputHash")]
    pub proof_input_hash: [u8; 32],
    #[serde(rename = "proofBlob")]
    pub proof_blob: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockPublicInputsJson {
    #[serde(rename = "ownerCommitment")]
    pub owner_commitment: String,
    #[serde(rename = "actionHash")]
    pub action_hash: String,
    #[serde(rename = "policyHash")]
    pub policy_hash: String,
    pub nullifier: String,
    #[serde(rename = "consumerDataHash")]
    pub consumer_data_hash: String,
    pub expiry: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockFixtureVectorJson {
    pub version: String,
    #[serde(rename = "proofType")]
    pub proof_type: String,
    #[serde(rename = "publicInputs")]
    pub public_inputs: UnlockPublicInputsJson,
    #[serde(rename = "philSecret")]
    pub phil_secret: String,
    #[serde(rename = "identityRootPreimage")]
    pub identity_root_preimage: String,
    #[serde(rename = "identityRootHash")]
    pub identity_root_hash: String,
    #[serde(rename = "ownerCommitmentPreimage")]
    pub owner_commitment_preimage: String,
    #[serde(rename = "ownerCommitmentHash")]
    pub owner_commitment_hash: String,
    #[serde(rename = "nullifierSeed")]
    pub nullifier_seed: String,
    #[serde(rename = "nullifierPreimage")]
    pub nullifier_preimage: String,
    #[serde(rename = "nullifierHash")]
    pub nullifier_hash: String,
    #[serde(rename = "proofInputHashPreimage")]
    pub proof_input_hash_preimage: String,
    #[serde(rename = "proofInputHashValue")]
    pub proof_input_hash_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateProofRequestJson {
    #[serde(rename = "publicInputs")]
    pub public_inputs: UnlockPublicInputsJson,
    #[serde(rename = "philSecret")]
    pub phil_secret: String,
    #[serde(rename = "nullifierSeed")]
    pub nullifier_seed: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyProofRequestJson {
    #[serde(rename = "proofBlob")]
    pub proof_blob: String,
    #[serde(rename = "publicInputs")]
    pub public_inputs: UnlockPublicInputsJson,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockFixtureVector {
    pub version: String,
    pub proof_type: String,
    pub public_inputs: UnlockPublicInputs,
    pub phil_secret: [u8; 32],
    pub identity_root_preimage: [u8; 64],
    pub identity_root_hash: [u8; 32],
    pub owner_commitment_preimage: [u8; 64],
    pub owner_commitment_hash: [u8; 32],
    pub nullifier_seed: [u8; 32],
    pub nullifier_preimage: [u8; 160],
    pub nullifier_hash: [u8; 32],
    pub proof_input_hash_preimage: [u8; 416],
    pub proof_input_hash_value: [u8; 32],
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    let trimmed = value.trim();
    let hex_value = trimmed
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("hex value must be 0x-prefixed"))?;
    let bytes = hex::decode(hex_value).with_context(|| format!("invalid hex: {trimmed}"))?;
    if bytes.len() != N {
        return Err(anyhow!("expected {N} bytes, got {}", bytes.len()));
    }

    bytes
        .try_into()
        .map_err(|_| anyhow!("failed to decode fixed-size hex"))
}

fn decode_u64(value: &str) -> Result<u64> {
    value
        .trim()
        .parse::<u64>()
        .with_context(|| format!("invalid u64 value: {value}"))
}

pub fn decode_hex_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    decode_hex(value)
}

pub fn decode_hex_vec(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    let hex_value = trimmed
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("hex value must be 0x-prefixed"))?;
    hex::decode(hex_value).with_context(|| format!("invalid hex: {trimmed}"))
}

pub fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

impl TryFrom<UnlockPublicInputsJson> for UnlockPublicInputs {
    type Error = anyhow::Error;

    fn try_from(value: UnlockPublicInputsJson) -> Result<Self> {
        Ok(Self {
            owner_commitment: decode_hex(&value.owner_commitment)?,
            action_hash: decode_hex(&value.action_hash)?,
            policy_hash: decode_hex(&value.policy_hash)?,
            nullifier: decode_hex(&value.nullifier)?,
            consumer_data_hash: decode_hex(&value.consumer_data_hash)?,
            expiry: decode_u64(&value.expiry)?,
        })
    }
}

impl TryFrom<UnlockFixtureVectorJson> for UnlockFixtureVector {
    type Error = anyhow::Error;

    fn try_from(value: UnlockFixtureVectorJson) -> Result<Self> {
        Ok(Self {
            version: value.version,
            proof_type: value.proof_type,
            public_inputs: value.public_inputs.try_into()?,
            phil_secret: decode_hex(&value.phil_secret)?,
            identity_root_preimage: decode_hex(&value.identity_root_preimage)?,
            identity_root_hash: decode_hex(&value.identity_root_hash)?,
            owner_commitment_preimage: decode_hex(&value.owner_commitment_preimage)?,
            owner_commitment_hash: decode_hex(&value.owner_commitment_hash)?,
            nullifier_seed: decode_hex(&value.nullifier_seed)?,
            nullifier_preimage: decode_hex(&value.nullifier_preimage)?,
            nullifier_hash: decode_hex(&value.nullifier_hash)?,
            proof_input_hash_preimage: decode_hex(&value.proof_input_hash_preimage)?,
            proof_input_hash_value: decode_hex(&value.proof_input_hash_value)?,
        })
    }
}

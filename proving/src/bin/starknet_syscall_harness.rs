use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use cairo_lang_runner::{Arg, RunResultValue, SierraCasmRunner, StarknetState};
use cairo_lang_sierra::program::VersionedProgram;
use cairo_lang_utils::ordered_hash_map::OrderedHashMap;
use serde::Serialize;
use starknet_types_core::felt::Felt;

#[derive(Serialize)]
struct HarnessOutput {
    function: String,
    contract_address: String,
    returned_fact_high: String,
    returned_fact_low: String,
    emitted_fact_high: String,
    emitted_fact_low: String,
    expected_fact_high: String,
    expected_fact_low: String,
    syscalls: std::collections::HashMap<String, usize>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("proving lives under the repo root")
        .to_path_buf()
}

fn read_hex_felts(path: &PathBuf) -> Result<Vec<Felt>> {
    let raw: Vec<String> = serde_json::from_str(
        &fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;
    raw.into_iter()
        .map(|value| Felt::from_hex(&value).with_context(|| format!("parsing felt {value}")))
        .collect()
}

fn main() -> Result<()> {
    let root = repo_root();
    let sierra_path = root.join("starknet_integration/target/dev/phil_starknet_integration.sierra.json");
    let args_path =
        root.join("proving/out/cairo_air_adapter_spike/proof_input_hash_slice_verify_args.json");
    let summary_path = root.join("proving/out/cairo_air_adapter_spike/summary.json");

    let versioned: VersionedProgram = serde_json::from_str(
        &fs::read_to_string(&sierra_path)
            .with_context(|| format!("reading {}", sierra_path.display()))?,
    )
    .with_context(|| format!("parsing {}", sierra_path.display()))?;
    let program = versioned.into_v1()?.program;
    let runner =
        SierraCasmRunner::new(program, Some(Default::default()), OrderedHashMap::default(), None)
            .context("building SierraCasmRunner")?;

    let function_name =
        "phil_starknet_integration::run_verify_proof_input_hash_slice_via_contract_syscalls";
    let func = runner.find_function(function_name).context("finding syscall harness function")?;

    let calldata = read_hex_felts(&args_path)?;
    let summary: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&summary_path)
            .with_context(|| format!("reading {}", summary_path.display()))?,
    )
    .with_context(|| format!("parsing {}", summary_path.display()))?;
    let expected = summary["expectedFactPayload"]
        .as_array()
        .context("expectedFactPayload missing or not an array")?;
    ensure!(expected.len() == 2, "expectedFactPayload must contain exactly two felts");
    let expected_high =
        Felt::from_hex(expected[0].as_str().context("expectedFactPayload[0] is not a string")?)?;
    let expected_low =
        Felt::from_hex(expected[1].as_str().context("expectedFactPayload[1] is not a string")?)?;

    let contract_address = Felt::from_hex("0x5048494c")?;
    let result = runner
        .run_function_with_starknet_context(
            func,
            vec![
                Arg::Value(contract_address),
                Arg::Array(calldata.into_iter().map(Arg::Value).collect()),
            ],
            Some(20_000_000_000usize),
            StarknetState::default(),
        )
        .context("running Starknet syscall harness")?;

    let values = match result.value {
        RunResultValue::Success(values) => values,
        RunResultValue::Panic(values) => {
            bail!(
                "syscall harness panicked with felts: {}",
                values
                    .into_iter()
                    .map(|felt| format!("{felt:#x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    };
    ensure!(
        values.len() == 4,
        "expected 4 return felts from syscall harness, got {}",
        values.len()
    );

    let output = HarnessOutput {
        function: function_name.to_string(),
        contract_address: format!("{contract_address:#x}"),
        returned_fact_high: format!("{:#x}", values[0]),
        returned_fact_low: format!("{:#x}", values[1]),
        emitted_fact_high: format!("{:#x}", values[2]),
        emitted_fact_low: format!("{:#x}", values[3]),
        expected_fact_high: format!("{expected_high:#x}"),
        expected_fact_low: format!("{expected_low:#x}"),
        syscalls: result.used_resources.syscalls,
    };

    ensure!(
        values[0] == expected_high
            && values[1] == expected_low
            && values[2] == expected_high
            && values[3] == expected_low,
        "returned/emitted fact payload does not match locked expected payload"
    );

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

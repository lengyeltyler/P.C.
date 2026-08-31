#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cache/philcore/toolchains/scarb-v2.15.0/bin:$HOME/.cache/philcore/toolchains/cairo-v2.15.0/bin:$HOME/.cache/philcore/toolchains/starknet-foundry-v0.53.0/bin:$HOME/.cache/philcore/toolchains/universal-sierra-compiler-v2.10.0/bin:$PATH"

echo "PhilCore pinned Starknet toolchain PATH activated for this shell."
echo "scarb: $(command -v scarb || echo missing)"
echo "cairo-execute: $(command -v cairo-execute || echo missing)"
echo "snforge: $(command -v snforge || echo missing)"
echo "universal-sierra-compiler: $(command -v universal-sierra-compiler || echo missing)"

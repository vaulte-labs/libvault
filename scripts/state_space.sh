#!/bin/sh
# Walks every sequence of roster changes and attacks to DEPTH through the real replay code.
set -eu
cd "$(dirname "$0")/.."
LV_STATE_SPACE_DEPTH=${1:-4} cargo test --features test-hooks --lib state_space::deep -- --ignored --nocapture

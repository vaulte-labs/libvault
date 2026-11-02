#!/bin/sh
# Everything a change must pass. Lessons live here as checks instead of notes.
set -eu
cd "$(dirname "$0")/.."

cargo fmt --check
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo clippy --no-default-features -- -D warnings
cargo clippy --features fuzz -- -D warnings
# The relay tests run through lv-relay, which Vaulte keeps private, checked out beside this one.
if [ -z "${LV_RELAY_BIN:-}" ]; then
    cargo build --release --manifest-path ../relay/Cargo.toml
    export LV_RELAY_BIN="$PWD/../relay/target/release/lv-relay"
fi
cargo test --features test-hooks

# `unsafe` stays in the two files built to contain it.
allowed=$(grep -rl 'allow(unsafe_code)' src | sort | tr '\n' ' ')
[ "$allowed" = "src/device/enclave.rs src/sys.rs " ] || { echo "unsafe_code allowed in: $allowed"; exit 1; }

# A file past 500 lines has more than one job.
for file in $(find src -name '*.rs' ! -name tests.rs ! -name '*_tests.rs'); do
    lines=$(wc -l < "$file")
    [ "$lines" -le 500 ] || { echo "$file has $lines lines"; exit 1; }
done

# Every interface shows these messages, and most of them have no command line.
if grep -rnE '"[^"]*`vlt |Use vlt |Run vlt |newer version of vlt' src --include='*.rs' --exclude='tests.rs' --exclude='*_tests.rs'; then
    echo "a library message names the command line"
    exit 1
fi

# Only `Client` reaches a secret, so no interface can skip an approval.
if grep -nE 'pub (mod|use) .*\b(vault|log|record|state|wire|crypto)\b' src/lib.rs | grep -vE 'pub use vault::\{DeviceInfo, default_home, exists, needs_passphrase\}'; then
    echo "src/lib.rs exposes an internal module"
    exit 1
fi

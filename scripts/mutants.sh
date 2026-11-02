#!/bin/sh
# Breaks the security code on purpose and checks a test notices. Survivors are listed, and any not
# accepted in scripts/mutants-accepted.txt fail this script, as does a run that tested nothing.
set -eu
cd "$(dirname "$0")/.."
out=$(mktemp -d)

cargo mutants --features test-hooks -j 3 --timeout 180 --no-shuffle -o "$out" \
    --file src/state/mod.rs --file src/state/rules.rs --file src/digest.rs --file src/sync/merge.rs --file src/roster.rs --file src/space.rs --file src/rescue.rs --file src/devices.rs --file src/broker/policy.rs \
    --file src/scrub.rs --file src/crypto.rs --file src/recovery.rs \
    --file src/net/pair.rs --file src/sync/exchange.rs \
    --file src/state/vouching.rs --file src/listing.rs --file src/icon.rs --file src/generate.rs \
    --file src/passkey.rs --file src/links.rs --file src/locking.rs --file src/profile.rs --file src/client_builds.rs \
    --file src/broker/passkeys.rs --file src/broker/codes.rs --file src/broker/shared_socket.rs || true

results="$out/mutants.out"
caught=$(wc -l < "$results/caught.txt")
[ "$caught" -gt 0 ] || { echo "no mutant was caught, so nothing was tested"; exit 1; }

survivors=$(cut -d: -f1,4- "$results/missed.txt" | grep -vxFf scripts/mutants-accepted.txt || true)
echo "caught $caught, missed $(wc -l < "$results/missed.txt"), timed out $(wc -l < "$results/timeout.txt")"
if [ -n "$survivors" ]; then
    echo "not accepted:"
    echo "$survivors"
    exit 1
fi

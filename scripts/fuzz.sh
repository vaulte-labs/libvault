#!/bin/sh
# Runs every fuzz target for SECONDS each, JOBS at a time, and says what it covered. A crash fails
# the run and leaves its input in fuzz/artifacts.
set -eu
cd "$(dirname "$0")/.."
seconds=${1:-600}
jobs=${2:-5}
cargo test --features test-hooks --lib write_fuzz_seeds -- --ignored > /dev/null
cd fuzz
cargo +nightly fuzz build --sanitizer=address
target_dir=target/aarch64-apple-darwin/release
[ -d "$target_dir" ] || target_dir=$(dirname "$(find target -name log -type f -perm -u+x | head -1)")
mkdir -p logs corpus
# Bounded so a slow target cannot spend the run on one enormous input.
export seconds target_dir
cargo +nightly fuzz list | xargs -P "$jobs" -n 1 sh -c '
    mkdir -p "corpus/$0"
    "$target_dir/$0" "corpus/$0" -max_total_time="$seconds" -timeout=20 -rss_limit_mb=3000 -max_len=262144 \
        -print_final_stats=1 -artifact_prefix="artifacts/$0-" > "logs/$0.log" 2>&1 || echo "CRASH $0"'
for target in $(cargo +nightly fuzz list); do
    runs=$(grep -a stat::number_of_executed_units logs/$target.log | awk '{print $2}')
    printf '%-18s %12s runs  %6s corpus files\n' "$target" "${runs:-CRASHED}" "$(ls corpus/$target | wc -l | tr -d ' ')"
done
ls artifacts 2>/dev/null | grep . && exit 1
exit 0
